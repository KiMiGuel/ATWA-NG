"""Scan and reconnaissance subcommands."""

from __future__ import annotations

import signal
import subprocess
import sys
import time

from ..injection_test import injection_test
from ..scan import channels_for_band, scan
from . import WPSRECON_BIN


def _cmd_scan(args) -> int:
    """Native scapy channel-hopping scan (scan.py) — no external engine."""
    result = scan(args.iface, duration=args.duration, channels=channels_for_band(args.band))
    for ap in sorted(result.aps.values(), key=lambda a: a.bssid):
        print(f"{ap.bssid}  ch={ap.channel}  {ap.security}  "
              f"pwr={ap.signal}  beacons={ap.beacon_count}  ssid={ap.ssid!r}")
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
