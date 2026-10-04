"""ATWA-NG Airwave Teardown Wireless Auditing-Next Gen
	System's Down.

  - scan, injection-test, wps-recon: native scapy scanning, injection
    self-test, and WPS reconnaissance (scan.py, injection_test.py,
    secure.wps_profile()) — no vendored binary involved.
  - crack-cap: a permitted wrapper path (cap/pcap-format cracking
    backend, alongside John). eapol-hunt/verify-handshake are additional
    wrapper paths that no longer exist -- eapol-hunt and verify-handshake
    are native now (atwa.eapol.scanner / atwa.eapol.dumper)
    (cli_commands/__init__.py) -- see that module for the full, current
    list of permitted exceptions to the native-only policy.
  - deauth, pmkid, handshake, omni, smart, wep, wep-hirte, wps-pixie,
    crack: native-Python attack implementations (attacks/, wep/, wps/,
    crack/), imported here with plain relative imports (`.`/`..`) —
    nothing is hardcoded to the package name, so this whole folder can
    be renamed or moved without breaking.
  - wps-oneshot is the explicit managed-mode exception: it drives
     wpa_supplicant directly rather than using the native monitor-mode path.
  - downgrade-twin, pmf-bypass, owe-downgrade, gui: portal-free rogue-AP
    workflows and desktop GUI wiring around the same engine.
"""

from __future__ import annotations

import argparse
import importlib
import shutil
import sys
import textwrap

from .radio import RadioError

# Subcommand handlers are wired as "module:attr" STRINGS and imported only
# when that subcommand actually runs. Importing all 23 handlers eagerly
# pulled scapy (~230ms of crypto/socket/layer init) into even
# `atwa --help` and `atwa update`, which need none of it -- measured
# startup: 523ms median before this, ~100ms for non-radio commands after.
# RadioError stays eager: main()'s except clause must name it before any
# dispatch happens.


def resolve_handler(target: str):
    """Import and return the handler for a ``module:attr`` dispatch string."""
    module_name, _, attr = target.partition(":")
    return getattr(importlib.import_module(module_name), attr)

# --- help presentation -------------------------------------------------
# Stock argparse crams all 23 subcommand names into one `{a,b,c,...}`
# metavar and prints it twice, then hangs every description off a block
# that is hard to scan. The formatter below fixes the layout only:
# command name left, description right, both wrapped to the terminal.
#
# Colour is deliberately NOT done here. Python 3.14's argparse colourises
# help natively and already honours NO_COLOR plus TTY detection; adding
# our own ANSI on top produced doubled escape sequences.


def _term_width() -> int:
    """Terminal width, clamped so descriptions never wrap into slivers."""
    try:
        cols = shutil.get_terminal_size().columns
    except OSError:
        cols = 80
    return max(60, min(cols, 100))


class _AtwaHelpFormatter(argparse.HelpFormatter):
    """Two-column help layout with a column sized to the widest entry."""

    def __init__(self, prog: str, width: int | None = None) -> None:
        # `color` is deliberately not a parameter. ArgumentParser applies it
        # afterwards via formatter._set_color(), and the keyword only exists
        # on Python 3.14+ while this project supports 3.10+.
        super().__init__(prog, width=_term_width() if width is None else width)
        self._desc_col = 22

    def set_desc_col(self, column: int) -> None:
        self._desc_col = max(12, min(column, 28))

    def _row(self, inv: str, help_text: str | None) -> str:
        """Render one `name  description` row, wrapping under the column."""
        if not help_text or not help_text.strip():
            return f"  {inv}\n"
        pad = " " * max(self._desc_col - 2 - len(inv), 2)
        help_width = max(self._width - self._desc_col, 24)
        lines = textwrap.wrap(" ".join(help_text.split()), help_width) or [""]
        head = f"  {inv}{pad}{lines[0]}\n"
        tail = "".join(f"{' ' * self._desc_col}{line}\n" for line in lines[1:])
        return head + tail

    def _format_action(self, action: argparse.Action) -> str:
        subactions = list(self._iter_indented_subactions(action))

        if isinstance(action, argparse._SubParsersAction):
            # Suppress the bare `COMMAND` placeholder -- the subcommand list
            # below is the real content, so the metavar row is just noise.
            out = ""
            if action.help:
                out = self._row("COMMAND", action.help)
            return out + "".join(self._format_action(s) for s in subactions)

        # argparse only expands a non-empty help string; positionals declared
        # without `help=` carry None, and _expand_help would fail on it.
        help_text = action.help and self._expand_help(action)
        return self._row(self._format_action_invocation(action), help_text)


class _AtwaParser(argparse.ArgumentParser):
    """Parser that lays help out through _AtwaHelpFormatter.

    Subclassing rather than passing `formatter_class` to a single parser
    matters: `add_subparsers` inherits this class, so `atwa <cmd> --help`
    is laid out the same way as the top-level help.

    The description column is measured once per parser, up front. It cannot
    be measured in `add_arguments`, because argparse defers every
    `_format_action` call until after all groups have been added -- a
    per-group value there would be overwritten before anything is rendered.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        kwargs.setdefault("formatter_class", _AtwaHelpFormatter)
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    def format_help(self) -> str:
        # Subcommand parsers inherit this class but not the main parser's
        # group titles, so normalise argparse's defaults here. The top-level
        # COMMANDS title is already custom and is left alone.
        for group in self._action_groups:
            if group.title == "positional arguments":
                group.title = "ARGUMENTS"
            elif group.title == "options":
                group.title = "OPTIONS"
        return super().format_help()

    def _get_formatter(self) -> _AtwaHelpFormatter:
        # Built here rather than via super() so the concrete type is known
        # without a cast. This mirrors ArgumentParser._get_formatter, which
        # applies colour after construction -- both the call and the `color`
        # attribute only exist on Python 3.14+.
        formatter = _AtwaHelpFormatter(prog=self.prog)
        set_color = getattr(formatter, "_set_color", None)
        if set_color is not None:
            set_color(getattr(self, "color", None))

        widest = 0
        for action in self._actions:
            if action.help is argparse.SUPPRESS:
                continue
            get_subactions = getattr(action, "_get_subactions", None)
            if get_subactions is not None:
                # Subcommand entries live here; the parent's own metavar
                # ("COMMAND") is a placeholder and must not drive the width.
                for sub in get_subactions():
                    widest = max(widest, len(formatter._format_action_invocation(sub)))
            else:
                widest = max(widest, len(formatter._format_action_invocation(action)))
        formatter.set_desc_col(widest + 4)
        return formatter


def build_parser() -> argparse.ArgumentParser:
    from . import __version__

    parser = _AtwaParser(
        prog="atwa",
        description="ATWA-NG — Airwave Teardown Wireless Auditing-NextGen",
        epilog="Run 'atwa <command> --help' for options of a single command.",
    )
    parser._optionals.title = "OPTIONS"
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="COMMAND",
        title="COMMANDS",
    )

    p = sub.add_parser("scan", help="channel-hopping AP/client scan")
    p.add_argument("iface")
    p.add_argument("--duration", type=float, default=10.0)
    p.add_argument("--band", choices=("2.4GHz", "5GHz", "Both"), default="Both")
    p.add_argument("--channels", help="explicit channel spec, e.g. '1,6,11' or '1,3-7,11' -- overrides --band")
    p.add_argument("--active-probe", type=float, default=None, metavar="SECONDS",
                    help="broadcast a wildcard probe request roughly every N seconds (reveals hidden SSIDs faster)")
    p.add_argument("--clients", action="store_true", help="also print associated clients")
    p.set_defaults(func="atwa.cli_commands.scan:_cmd_scan")

    p = sub.add_parser("injection-test", help="native injection self-test (ported from aireplay-ng --test)")
    p.add_argument("iface")
    p.add_argument("--bssid", help="test against a specific AP instead of discovering one")
    p.add_argument("--count", type=int, default=30, help="directed ping attempts against the target AP")
    p.set_defaults(func="atwa.cli_commands.scan:_cmd_injection_test")

    p = sub.add_parser("wps-recon", help="WPS-enabled AP reconnaissance")
    p.add_argument("iface")
    p.add_argument("--channel", type=int)
    p.add_argument("--channels", help="explicit channel spec, e.g. '1,6,11' or '1,3-7,11' -- overrides --channel")
    p.add_argument("--duration", type=int, default=15)
    p.set_defaults(func="atwa.cli_commands.scan:_cmd_wps_recon")

    p = sub.add_parser("eapol-hunt", help="independent passive EAPOL handshake capture")
    p.add_argument("iface")
    p.add_argument("--bssid")
    p.add_argument("--duration", type=float, default=300.0)
    p.set_defaults(func="atwa.cli_commands.scan:_cmd_eapol_hunt")

    p = sub.add_parser("verify-handshake", help="independently verify a captured EAPOL handshake")
    p.add_argument("capfile")
    p.add_argument("--mac")
    p.add_argument("--frames", type=int, nargs="*", default=[])
    p.set_defaults(func="atwa.cli_commands.crack:_cmd_verify_handshake")

    p = sub.add_parser("crack-cap", help="crack a WPA/WEP capture directly")
    p.add_argument("capfile")
    p.add_argument("wordlist")
    p.add_argument("--bssid")
    p.add_argument("--timeout", type=float, default=3600.0,
                   help="give up after this long (default 1h; wordlist attacks can run long)")
    p.set_defaults(func="atwa.cli_commands.crack:_cmd_crack_cap")

    p = sub.add_parser("deauth", help="deauth flood (native scapy)")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--client")
    p.add_argument("--count", type=int, default=64)
    p.add_argument("--channel", type=int)
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_deauth")

    p = sub.add_parser("pmkid", help="clientless PMKID capture")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("client")
    p.add_argument("--channel", type=int)
    p.add_argument("--essid", help="network name -- required for a crackable 22000 line (PMK derives from it)")
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_pmkid")

    p = sub.add_parser("handshake", help="4-way handshake capture")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--channel", type=int)
    p.add_argument("--timeout", type=float, default=60.0)
    p.add_argument("--outfile")
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_handshake")

    p = sub.add_parser("omni", help="adaptive chain: profile -> pmkid -> handshake -> crack")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--channel", type=int)
    p.add_argument("--profile-duration", type=float, default=8.0)
    p.add_argument("--wordlist")
    p.add_argument("--capture-dir", default=None)
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_omni")

    p = sub.add_parser("smart", help="quick attack: pmkid -> deauth+handshake")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--channel", type=int)
    p.add_argument("--profile-duration", type=float, default=8.0)
    p.add_argument("--wordlist")
    p.add_argument("--capture-dir", default=None)
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_smart")

    p = sub.add_parser("wep", help="native WEP: fake-auth + ARP replay + PTW")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("ssid")
    p.add_argument("--key-len", type=int, default=13, choices=(5, 13))
    p.add_argument("--channel", type=int)
    p.add_argument("--target-sessions", type=int, default=40_000)
    p.add_argument("--timeout", type=float, default=300.0)
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_wep")

    p = sub.add_parser("wep-hirte", help="native WEP Hirte client attack (IBSS)")
    p.add_argument("iface")
    p.add_argument("client")
    p.add_argument("--key-len", type=int, default=13, choices=(5, 13))
    p.add_argument("--channel", type=int)
    p.add_argument("--target-sessions", type=int, default=25_000)
    p.add_argument("--timeout", type=float, default=120.0)
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_wep_hirte")

    p = sub.add_parser("wps-pixie", help="WPS pixie-dust (native scapy monitor mode)")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("ssid")
    p.add_argument("--channel", type=int)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--eapol-versions", default="2,1")
    p.add_argument("--passive", action="store_true")
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_wps_pixie")

    p = sub.add_parser("wps-oneshot", help="WPS via wpa_supplicant managed mode")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--pin")
    p.add_argument("--pbc", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_wps_oneshot")

    p = sub.add_parser("gui", help="launch the desktop GUI")
    p.add_argument("--demo", action="store_true")
    p.set_defaults(func="atwa.cli_commands.misc:_cmd_gui")

    p = sub.add_parser("update", help="check GitHub for a newer ATWA-NG release and install it")
    p.add_argument("--timeout", type=float, default=3.0, help="network timeout in seconds (default: 3)")
    p.set_defaults(func="atwa.cli_commands.misc:_cmd_update_check")

    p = sub.add_parser("crack", help="crack a 22000/cap file with John")
    p.add_argument("hashfile")
    p.add_argument("wordlist")
    p.add_argument("--rules", default="", help="John --rules section name (e.g. best64, Jumbo, All); omit for plain wordlist mode")
    p.set_defaults(func="atwa.cli_commands.crack:_cmd_crack")

    p = sub.add_parser("downgrade-twin", help="WPA3-transition rogue WPA2-only twin (secure.py downgrade_twin recommendation)")
    p.add_argument("iface_ap")
    p.add_argument("iface_mon")
    p.add_argument("bssid")
    p.add_argument("ssid")
    p.add_argument("channel", type=int)
    p.add_argument("outfile")
    p.add_argument("--timeout", type=float, default=120.0)
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_downgrade_twin")

    p = sub.add_parser("pmf-bypass", help="PMF-required rogue twin + malformed EAPOL reconnect chain")
    p.add_argument("iface_ap")
    p.add_argument("iface_mon")
    # v2.5.4: the `bssid` positional is gone. It was never forwarded to
    # run_pmf_bypass_chain() in a way that function could accept, and the
    # chain has no use for it -- it raises its own rogue twin and reads that
    # twin's BSSID back from the interface. No working invocation ever got
    # far enough to depend on the old argument order.
    p.add_argument("ssid")
    p.add_argument("channel", type=int)
    p.add_argument("outfile")
    p.add_argument(
        "--timeout", type=float, default=120.0,
        help="total budget, split evenly between waiting for an association "
             "and waiting for the reconnect handshake (default: 120)",
    )
    p.add_argument("--key-info", default=None, help="override malformed EAPOL key-info value")
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_pmf_bypass")

    p = sub.add_parser("owe-downgrade", help="OWE-transition rogue open twin (secure.py owe_downgrade recommendation)")
    p.add_argument("iface_ap")
    p.add_argument("iface_mon")
    p.add_argument("owe_bssid", help="the REAL OWE AP's BSSID -- deauth target")
    p.add_argument("open_ssid", help="the paired open network's SSID, from the OWE Transition Mode IE (see scan's owe_transition_ssid field)")
    p.add_argument("channel", type=int)
    p.add_argument("--timeout", type=float, default=120.0)
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_owe_downgrade")

    p = sub.add_parser("dragonblood", help="SAE timing side-channel wordlist pruning (CVE-2019-9494) -- only meaningful against unpatched pre-hostapd-2.10 APs")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("wordlist", help="path to a newline-separated password wordlist")
    p.add_argument("--channel", type=int, default=None)
    p.add_argument("--num-macs", type=int, default=4)
    p.add_argument("--samples-per-mac", type=int, default=5)
    p.add_argument("--timeout", type=float, default=2.0, help="per-SAE-Commit reply timeout in seconds")
    p.add_argument("--outfile", default=None, help="write the pruned wordlist here")
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_dragonblood")

    p = sub.add_parser("chaos", help="coordinated multi-vector flood against one target, escalating tiers")
    p.add_argument("iface")
    p.add_argument("bssid")
    p.add_argument("--channel", type=int, default=None)
    p.add_argument("--client", default=None, help="target one client instead of broadcast")
    p.add_argument("--vectors", default=None,
                   help="comma-separated subset of: beacon_flood,eapol_flood,"
                        "auth_flood,deauth,csa_spoof,tkip_mic_flood "
                        "(default: all, in that order)")
    p.add_argument("--tiers", default="100,1000,5000",
                   help="comma-separated frame counts to escalate through "
                        "(default: 100,1000,5000)")
    p.add_argument("--delay", type=float, default=2.0,
                   help="seconds to settle between vectors (default: 2). "
                        "Without this gap the vectors contaminate each "
                        "other's reported effects.")
    p.set_defaults(func="atwa.cli_commands.attacks:_cmd_chaos")

    # argparse emits the optionals group before the subcommand group, which
    # buries the command list a user came for under two flag rows. Parsing
    # reads `_actions`, not `_action_groups`, so reordering only affects help.
    if parser._action_groups and parser._action_groups[-1] is not parser._optionals:
        parser._action_groups.remove(parser._optionals)
        parser._action_groups.append(parser._optionals)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return resolve_handler(args.func)(args)
    except (RadioError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
