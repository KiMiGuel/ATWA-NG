"""Passive EAPOL handshake capture and capture-quality grading.

This is the part of vendor/eapol_hunter.py worth keeping: tracking a
4-way exchange per (AP, client) pair, and saying whether what was
collected is actually crackable. The scanner's banner-drawing, ANSI box
rendering, channel hopper and raw-pcap writer from that file are not
reproduced -- channel hopping is radio/ and scan/, writing is
capture/lock.py, and ATWA-NG has its own log pane.

Classification is eapol.utils.message_number, i.e. the spec rules rather
than flag-bit guessing. Group (GTK) frames and Request/Error frames are
excluded by that function, so a GTK rekey cannot masquerade as a pairwise
M3 and promote a capture to "authorized".
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum

from .utils import extract_mic, extract_nonce, message_number, parse_eapol_key


class CaptureQuality(Enum):
    """How usable a collected exchange is for cracking.

    Ordering matters: callers compare with `<`, so keep NONE lowest.
    """

    NONE = "none"
    #: M1+M2: enough for a PMKID/PSK derivation attempt.
    CHALLENGE = "challenge"
    #: M2+M3: the AP has proved possession of the PMK. Crackable.
    AUTHORIZED = "authorized"


@dataclass
class PairState:
    """Per (AP, client) exchange state."""

    messages: set[int] = field(default_factory=set)
    anonce: bytes | None = None
    snonce: bytes | None = None
    mic: bytes | None = None
    #: Non-zero replay counters seen, used to tell an M2 from a WPA
    #: legacy M4 (they differ only there -- see utils.message_number).
    replay_counters: set[int] = field(default_factory=set)

    def quality(self) -> CaptureQuality:
        seen = self.messages
        if 2 in seen and 3 in seen:
            return CaptureQuality.AUTHORIZED
        if 1 in seen and 2 in seen:
            return CaptureQuality.CHALLENGE
        return CaptureQuality.NONE


@dataclass
class QualityReport:
    """Why a pair grades the way it does -- the actionable part."""

    quality: CaptureQuality
    problems: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.quality is not CaptureQuality.NONE


class EapolScanner:
    """Accumulates EAPOL-Key exchanges from sniffed frames.

    Feed it any frame; it returns the handshake number it saw (1-4) or
    None. Nothing here touches the radio or writes files -- capture is
    attacks/handshake.py's job and disk is capture/lock.py's -- so this
    can be used offline against a pcap just as easily as live.
    """

    def __init__(self) -> None:
        self.pairs: dict[tuple[str, str], PairState] = {}
        #: Coarse latch: once any pair reaches AUTHORIZED there is no
        #: reason to keep classifying, which matters on a live feed where
        #: the stop_filter runs per packet.
        self._authorized_found: bool = False

    # -- ingestion ------------------------------------------------------

    def observe(self, bssid: str, client: str, frame_bytes: bytes) -> int | None:
        """Record one frame; return its handshake number, or None if it is
        not a usable pairwise EAPOL-Key message."""
        msg_no = message_number(frame_bytes)
        if msg_no is None:
            return None

        key = parse_eapol_key(frame_bytes)
        if key is not None:
            state = self.pairs.setdefault((bssid, client), PairState())
            state.messages.add(msg_no)
            state.replay_counters.add(key.replay_counter)
            # ANonce arrives on M1 (and M3); SNonce on M2 (and M4).
            nonce = extract_nonce(frame_bytes)
            if nonce is not None:
                if msg_no in (1, 3) and state.anonce is None:
                    state.anonce = nonce
                elif msg_no in (2, 4) and state.snonce is None:
                    state.snonce = nonce
            mic = extract_mic(frame_bytes)
            if mic is not None and state.mic is None:
                state.mic = mic
            if state.quality() is CaptureQuality.AUTHORIZED:
                self._authorized_found = True
        return msg_no

    def observe_packet(self, frame_bytes: bytes, addr1: str, addr2: str) -> int | None:
        """Ingest a frame, deriving (AP, client) from the 802.11 header.

        Odd-numbered messages are AP->station, so addr2 is the AP; even
        ones are station->AP, so addr1 is.
        """
        msg_no = message_number(frame_bytes)
        if msg_no is None:
            return None
        bssid, client = (addr2, addr1) if msg_no % 2 == 1 else (addr1, addr2)
        return self.observe(bssid, client, frame_bytes)

    # -- reporting ------------------------------------------------------

    def quality(self, bssid: str, client: str) -> CaptureQuality:
        state = self.pairs.get((bssid, client))
        return state.quality() if state else CaptureQuality.NONE

    def explain(self, bssid: str, client: str) -> QualityReport:
        """Grade a pair and list what's missing or wrong.

        The problems mirror what vendor/eapol_hunter.py's
        verify_handshake_quality() checked, kept because each one is a
        real reason a capture fails to crack.
        """
        state = self.pairs.get((bssid, client))
        if state is None:
            return QualityReport(
                CaptureQuality.NONE, ["no EAPOL-Key frames seen for this pair"]
            )

        problems: list[str] = []
        quality = state.quality()

        if quality is CaptureQuality.NONE:
            missing = [n for n in (1, 2, 3) if n not in state.messages]
            problems.append(
                "missing handshake message(s): " + ", ".join(f"M{n}" for n in missing)
            )
        if state.anonce is None:
            problems.append("ANonce missing (expected on M1)")
        if state.snonce is None:
            problems.append("SNonce missing (expected on M2)")
        if state.mic is None:
            problems.append("MIC missing (expected on M2)")
        if (
            state.anonce is not None
            and state.snonce is not None
            and state.anonce == state.snonce
        ):
            problems.append("ANonce and SNonce are identical; capture is suspect")
        return QualityReport(quality, problems)

    def authorized(self) -> bool:
        """True once some pair reached AUTHORIZED."""
        return self._authorized_found

    def summary(self) -> dict[tuple[str, str], CaptureQuality]:
        return {pair: state.quality() for pair, state in self.pairs.items()}

    def reset(self) -> None:
        self.pairs.clear()
        self._authorized_found = False


class PassiveEapolListener:
    """Runs an EapolScanner against a live sniffer on a worker thread.

    Thin on purpose: it owns the thread and the stop flag, and delegates
    every decision to EapolScanner. The sniffer itself is injected so a
    caller (or test) decides whether that is scapy's AsyncSniffer, a
    pcap reader, or anything else.
    """

    def __init__(self, scanner: EapolScanner, sniffer_factory) -> None:
        self._scanner = scanner
        self._sniffer_factory = sniffer_factory
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _handle(self, frame_bytes: bytes, addr1: str, addr2: str) -> None:
        if self._stop.is_set():
            return
        self._scanner.observe_packet(frame_bytes, addr1, addr2)

    def start(self) -> threading.Thread:
        """Begin listening. Returns the worker thread."""
        if self._thread is not None:
            return self._thread
        self._thread = threading.Thread(target=self._sniffer_factory, daemon=True)
        self._thread.start()
        return self._thread

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None