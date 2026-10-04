"""Scan and reconnaissance subcommands."""

from __future__ import annotations

import sys
import time

from ..injection_test import injection_test
from ..radio import get_allowed_channels, get_mode
from ..scan import channels_for_band, parse_channel_range, scan


def _cmd_scan(args) -> int:
    """Native scapy channel-hopping scan (scan.py) — no external engine."""
    channels = parse_channel_range(args.channels) if args.channels else channels_for_band(args.band)
    # 2026-09-25: the regulatory domain can make channels unusable and the
    # hopper swallows that error (radio.ChannelHopper.hop catches RadioError
    # so one bad channel can't kill the loop). The consequence was that a
    # scan silently skipped them: under country BO / DFS-JP this host cannot
    # tune to 36/40/44/48 or 100-140, so a 5GHz AP on ch 36 was invisible
    # and the run looked like "no 5GHz networks here" rather than "15
    # channels were never scanned". Report the gap instead of hiding it.
    skipped: list[int] = []
    if channels:
        try:
            allowed = set(get_allowed_channels(args.iface, list(channels)))
            skipped = [ch for ch in channels if ch not in allowed]
        except Exception:  # noqa: BLE001 - advisory only, never fail the scan
            skipped = []
    if skipped:
        print(f"note: regulatory domain blocks {len(skipped)} of {len(channels)} "
              f"requested channels -- NOT scanned: {','.join(str(c) for c in skipped)}",
              file=sys.stderr)
    result = scan(args.iface, duration=args.duration, channels=channels, active_probe_interval=args.active_probe)
    for ap in sorted(result.aps.values(), key=lambda a: a.bssid):
        print(f"{ap.bssid}  ch={ap.channel}  {ap.security}  "
              f"pwr={ap.signal}  beacons={ap.beacon_count}  ssid={ap.ssid!r}")
        if ap.pmkid:
            print(f"  PMKID (passively sniffed): {ap.pmkid}")
        if args.clients:
            for client in sorted(ap.clients):
                print(f"  client {client}  pwr={ap.client_signal.get(client)}")
    # 2026-09-25: a managed-mode interface silently yields zero APs, and this
    # used to return 0 with no output at all -- verified live. Scanning in
    # managed mode was never supported (the GUI has an explicit Start Monitor
    # button), so the fix is not to make it work, it's to say why it found
    # nothing instead of looking identical to a genuinely empty area.
    if not result.aps:
        mode = get_mode(args.iface)
        if mode != "monitor":
            print(f"error: {args.iface} is in '{mode}' mode, not 'monitor' -- "
                  f"a managed-mode interface cannot see 802.11 frames.\n"
                  f"       fix: sudo iw dev {args.iface} set monitor", file=sys.stderr)
        else:
            print(f"no APs seen on {args.iface} in {args.duration}s "
                  f"(channel spec: {channels or 'all'})", file=sys.stderr)
        return 1
    return 0


def _cmd_injection_test(args) -> int:
    """Native injection self-test — confirms the adapter can actually
    inject frames that elicit real over-the-air replies, ported from
    aireplay-ng's --test attack methodology (see injection_test.py)."""
    result = injection_test(
        args.iface, bssid=args.bssid, count=args.count,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    if result.bssid is None:
        print(f"error: {result.detail}", file=sys.stderr)
        return 1
    print(f"{result.pings_answered}/{result.pings_sent}: {result.percent:.0f}% ({result.detail})")
    # 2026-09-26: report TX power alongside the percentage. Deauth
    # reliability is TX-power sensitive -- at 20 dBm a 384-frame burst
    # left a real client associated, at 30 dBm the same burst dropped it
    # instantly -- and nothing said so, so "deauth does nothing" looked
    # like a code bug rather than a power setting.
    print(f"  {result.txpower_note}")
    return 0 if result.pings_answered else 1


def _cmd_wps_recon(args) -> int:
    """WPS-enabled AP reconnaissance — native passive scan filtered to
    WPS-advertising APs, replacing the vendored `wash` binary. The data
    (lock state, manufacturer, model, device name) already comes from
    scan.py/secure.wps_profile()'s native beacon parsing (2026-08-27
    "wash parity" pass); this command just surfaces it standalone
    instead of requiring a full GUI/`atwa scan` session to see it."""
    channels = parse_channel_range(args.channels) if args.channels else ([args.channel] if args.channel else None)
    result = scan(args.iface, duration=args.duration, channels=channels)
    wps_aps = sorted((ap for ap in result.aps.values() if ap.wps is not None), key=lambda a: a.bssid)
    if not wps_aps:
        # 2026-09-25: returned 0 on "nothing found", same silent-success
        # shape as _cmd_scan/_cmd_handshake. Reconnaissance that found
        # nothing is not a successful recon.
        print("no WPS-enabled APs seen", file=sys.stderr)
        return 1
    for ap in wps_aps:
        print(f"{ap.bssid}  ch={ap.channel}  wps={ap.wps}  "
              f"manuf={ap.wps_manufacturer!r}  model={ap.wps_model_name!r}  "
              f"device={ap.wps_device_name!r}  ssid={ap.ssid!r}")
    return 0


def _cmd_eapol_hunt(args) -> int:
    """Passive EAPOL capture, native (was a vendored wrapper script)."""
    import threading

    from scapy.layers.eap import EAPOL
    from scapy.sendrecv import AsyncSniffer

    from ..eapol.scanner import EapolScanner
    from ..radio import ALL_CHANNELS, ChannelHopper, check_kill_interfering_processes

    iface, duration = args.iface, args.duration
    scanner = EapolScanner()

    def handle(pkt) -> None:
        eapol = pkt.getlayer(EAPOL)
        if eapol is None:
            return
        addr1, addr2 = getattr(pkt, "addr1", None), getattr(pkt, "addr2", None)
        if not (addr1 and addr2):
            return
        scanner.observe_packet(bytes(eapol), addr1, addr2)

    check_kill_interfering_processes()
    hopper = ChannelHopper(iface=iface, channels=list(ALL_CHANNELS))
    stop = threading.Event()

    def hop_loop() -> None:
        # ChannelHopper is a one-shot hop() plus a dwell sleep, not a
        # long-running thread of its own; the GUI drives it the same way.
        while not stop.is_set():
            hopper.hop()

    hop_thread = threading.Thread(target=hop_loop, daemon=True)
    hop_thread.start()
    sniffer = AsyncSniffer(iface=iface, prn=handle)
    sniffer.start()
    try:
        print(f"listening for EAPOL on {iface} for {duration:.0f}s", file=sys.stderr)
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        sniffer.stop()
        hop_thread.join(timeout=2.0)

    summary = scanner.summary()
    if not summary:
        print("no EAPOL-Key frames seen")
        return 0
    print(f"\n{'BSSID':<18} {'Client':<18} {'Quality':<12} Notes")
    print("-" * 78)
    for (bssid, client), quality in sorted(summary.items(), key=lambda kv: kv[1].value):
        notes = scanner.explain(bssid, client).problems
        print(f"{bssid:<18} {client:<18} {quality.value:<12} "
              f"{'; '.join(notes) if notes else 'crackable'}")
    return 0
