"""ATWA-NG Airwave Teardown Wireless Auditing-Next Gen
	System's Down.

  - scan, injection-test, wps-recon: native scapy scanning, injection
    self-test, and WPS reconnaissance (scan.py, injection_test.py,
    secure.wps_profile()) — no vendored binary involved.
  - crack-cap: the one remaining wrapper path, a permitted exception
    (cap/pcap-format cracking backend, alongside John).
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

from .cli_commands.attacks import (
    _cmd_deauth,
    _cmd_eviltwin,
    _cmd_handshake,
    _cmd_omni,
    _cmd_pmkid,
    _cmd_smart,
    _cmd_wep,
    _cmd_wps_oneshot,
    _cmd_wps_pixie,
)
from .cli_commands.crack import _cmd_crack, _cmd_crack_cap, _cmd_verify_handshake
from .cli_commands.misc import _cmd_gui
from .cli_commands.scan import (
    _cmd_eapol_hunt,
    _cmd_injection_test,
    _cmd_scan,
    _cmd_wps_recon,
)


def build_parser() -> argparse.ArgumentParser:
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="atwa", description="ATWA-NG — Airwave Teardown Wireless Auditing-NextGen"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="channel-hopping AP/client scan")
    p.add_argument("iface")
    p.add_argument("--duration", type=float, default=10.0)
    p.add_argument("--band", choices=("2.4GHz", "5GHz", "Both"), default="Both")
    p.add_argument("--channels", help="explicit channel spec, e.g. '1,6,11' or '1,3-7,11' -- overrides --band")
    p.add_argument("--active-probe", type=float, default=None, metavar="SECONDS",
                    help="broadcast a wildcard probe request roughly every N seconds (reveals hidden SSIDs faster)")
    p.add_argument("--clients", action="store_true", help="also print associated clients")
    p.set_defaults(func=_cmd_scan)

    p = sub.add_parser("injection-test", help="native injection self-test (ported from aireplay-ng --test)")
    p.add_argument("iface")
    p.add_argument("--bssid", help="test against a specific AP instead of discovering one")
    p.add_argument("--count", type=int, default=30, help="directed ping attempts against the target AP")
    p.set_defaults(func=_cmd_injection_test)

    p = sub.add_parser("wps-recon", help="WPS-enabled AP reconnaissance")
    p.add_argument("iface")
    p.add_argument("--channel", type=int)
    p.add_argument("--channels", help="explicit channel spec, e.g. '1,6,11' or '1,3-7,11' -- overrides --channel")
    p.add_argument("--duration", type=int, default=15)
    p.set_defaults(func=_cmd_wps_recon)

    p = sub.add_parser("eapol-hunt", help="independent passive EAPOL handshake capture")
    p.add_argument("iface")
    p.add_argument("--bssid")
    p.add_argument("--duration", type=float, default=300.0)
    p.set_defaults(func=_cmd_eapol_hunt)

    p = sub.add_parser("verify-handshake", help="independently verify a captured EAPOL handshake")
    p.add_argument("capfile")
    p.add_argument("--mac")
    p.add_argument("--frames", type=int, nargs="*", default=[])
    p.set_defaults(func=_cmd_verify_handshake)

    p = sub.add_parser("crack-cap", help="crack a WPA/WEP capture directly")
    p.add_argument("capfile")
    p.add_argument("wordlist")
    p.add_argument("--bssid")
    p.add_argument("--timeout", type=float, default=3600.0,
                   help="give up after this long (default 1h; wordlist attacks can run long)")
    p.set_defaults(func=_cmd_crack_cap)

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
    p.add_argument("--iface-ap", default=None, help="second interface to host the eviltwin stage's rogue AP on")
    p.set_defaults(func=_cmd_omni)

    p = sub.add_parser("smart", help="quick attack: pmkid -> deauth+handshake")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--channel", type=int)
    p.add_argument("--profile-duration", type=float, default=8.0)
    p.add_argument("--wordlist")
    p.add_argument("--capture-dir", default=None)
    p.add_argument("--iface-ap", default=None, help="second interface to host the eviltwin stage's rogue AP on")
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

    p = sub.add_parser("gui", help="launch the desktop GUI")
    p.add_argument("--demo", action="store_true")
    p.set_defaults(func=_cmd_gui)

    p = sub.add_parser("crack", help="crack a 22000/cap file with John")
    p.add_argument("hashfile")
    p.add_argument("wordlist")
    p.set_defaults(func=_cmd_crack)

    p = sub.add_parser("eviltwin", help="rogue AP + captive portal")
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
