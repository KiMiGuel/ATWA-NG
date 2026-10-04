"""Per-frame EAPOL nonce/MIC reporting for a capture file.

The capability behind vendor/eapol_dump/eapol_dump.sh, which shelled out
to tshark and grepped its verbose output. Same job, no external tool, and
the offsets come from the shared parser in utils.py rather than being
duplicated as tshark field expressions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .utils import extract_mic, extract_nonce, message_number, parse_eapol_key


@dataclass(frozen=True)
class FrameReport:
    """One EAPOL-Key frame, as a dumper row."""

    index: int
    bssid: str
    client: str
    message: int | None
    descriptor_type: int
    key_info: int
    nonce: bytes | None
    mic: bytes | None

    @property
    def label(self) -> str:
        msg = f"M{self.message}" if self.message is not None else "--"
        return f"#{self.index} {self.bssid} -> {self.client} {msg}"

    def nonce_hex(self) -> str:
        return self.nonce.hex() if self.nonce else ""

    def mic_hex(self) -> str:
        return self.mic.hex() if self.mic else ""

    def key_info_flags(self) -> str:
        """Human-readable key_info bits -- the part a human actually reads
        when deciding whether a frame is usable."""
        bits = []
        for mask, name in (
            (0x0008, "pairwise"),
            (0x0040, "install"),
            (0x0080, "ack"),
            (0x0100, "mic"),
            (0x0200, "secure"),
            (0x0400, "error"),
            (0x0800, "request"),
        ):
            if self.key_info & mask:
                bits.append(name)
        return ",".join(bits) if bits else "none"


class EapolDumper:
    """Summarise every EAPOL-Key frame in a capture.

    Read-only: opens the file, never writes or moves it.
    """

    def __init__(self, capfile: str | Path) -> None:
        self.capfile = Path(capfile)

    def frames(self, mac: str | None = None) -> list[FrameReport]:
        """Report each EAPOL-Key frame, optionally filtered to one MAC.

        `mac` matches either endpoint of the exchange, not just the AP --
        the vendored eapol_dump.sh filtered on `wlan.addr==<mac>`, which
        matches both directions, and a caller filtering by a station MAC
        would otherwise get nothing.

        Pairing is (addr3, addr1) as seen on the wire; for an M2/M4 that
        is (client, AP), which is why `client` and `bssid` are reported as
        observed rather than normalised.
        """
        from scapy.layers.eap import EAPOL

        # capture.reader, not PcapReader: monitor-mode captures are written
        # with linktype 127, which Scapy's own table may not resolve, in
        # which case every packet reads back as opaque Raw.
        from ..capture.reader import read_capture

        reports: list[FrameReport] = []
        for index, pkt in enumerate(read_capture(str(self.capfile)), start=1):
            eapol = pkt.getlayer(EAPOL)
            if eapol is None:
                continue
            raw = bytes(eapol)
            parsed = parse_eapol_key(raw)
            if parsed is None:
                continue
            addr3 = getattr(pkt, "addr3", None)
            addr1 = getattr(pkt, "addr1", None)
            addr2 = getattr(pkt, "addr2", None)
            # M1/M3 are AP->station (addr2 == AP); M2/M4 the reverse.
            msg = message_number(raw)
            if msg is not None and msg % 2 == 0:
                bssid_here, client_here = (addr1 or "?"), (addr2 or "?")
            else:
                bssid_here, client_here = (addr3 or addr2 or "?"), (addr1 or "?")
            if mac and mac.lower() not in (bssid_here.lower(), client_here.lower()):
                continue
            reports.append(
                FrameReport(
                    index=index,
                    bssid=bssid_here,
                    client=client_here,
                    message=msg,
                    descriptor_type=parsed.descriptor_type,
                    key_info=parsed.key_info,
                    nonce=extract_nonce(raw),
                    mic=extract_mic(raw),
                )
            )
        return reports

    def render(self, mac: str | None = None) -> str:
        """A fixed-width table of every EAPOL-Key frame -- the same thing
        eapol_dump.sh printed, minus tshark."""
        reports = self.frames(mac)
        if not reports:
            return "no EAPOL-Key frames found"

        head = f"{'Frame':>6}  {'BSSID':<18} {'Client':<18} {'Msg':<4} {'Nonce':<20} {'MIC':<12}"
        lines = [head, "-" * len(head)]
        for r in reports:
            lines.append(
                f"{r.index:>6}  {r.bssid:<18} {r.client:<18} "
                f"{('M' + str(r.message)) if r.message is not None else '--':<4} "
                f"{r.nonce_hex()[:18]:<20} {r.mic_hex()[:10]:<12}"
            )
        return "\n".join(lines)

    def summary(self, mac: str | None = None) -> dict[str, int]:
        """Counts by handshake message -- the quick "did I get M2 and M3?"
        answer."""
        counts: dict[str, int] = {}
        for r in self.frames(mac):
            key = f"M{r.message}" if r.message is not None else "other"
            counts[key] = counts.get(key, 0) + 1
        return counts