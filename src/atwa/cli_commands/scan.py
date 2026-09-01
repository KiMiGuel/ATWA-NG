"""Scan and reconnaissance subcommands."""

from __future__ import annotations

import signal
import subprocess
import sys
import time

from ..injection_test import injection_test
from ..scan import channels_for_band, parse_channel_range, scan
from . import EAPOLHUNTER_BIN, _python_for_scripts


def _cmd_scan(args) -> int:
    """Native scapy channel-hopping scan (scan.py) — no external engine."""
    channels = parse_channel_range(args.channels) if args.channels else channels_for_band(args.band)
    result = scan(args.iface, duration=args.duration, channels=channels, active_probe_interval=args.active_probe)
    for ap in sorted(result.aps.values(), key=lambda a: a.bssid):
        print(f"{ap.bssid}  ch={ap.channel}  {ap.security}  "
              f"pwr={ap.signal}  beacons={ap.beacon_count}  ssid={ap.ssid!r}")
        if ap.pmkid:
            print(f"  PMKID (passively sniffed): {ap.pmkid}")
        if args.clients:
            for client in sorted(ap.clients):
                print(f"  client {client}  pwr={ap.client_signal.get(client)}")
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
        print("no WPS-enabled APs seen")
        return 0
    for ap in wps_aps:
        print(f"{ap.bssid}  ch={ap.channel}  wps={ap.wps}  "
              f"manuf={ap.wps_manufacturer!r}  model={ap.wps_model_name!r}  "
              f"device={ap.wps_device_name!r}  ssid={ap.ssid!r}")
    return 0


def _cmd_eapol_hunt(args) -> int:
    cmd = [_python_for_scripts(), str(EAPOLHUNTER_BIN), args.iface]
    if args.bssid:
        cmd.append(args.bssid)
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
