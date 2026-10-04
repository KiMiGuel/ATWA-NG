"""Native continuous packet capture restricted to one BSSID.

Backs the GUI's channel-lock feature (App._lock_channel /
_start_lock_capture): once ensure_channel() has parked the adapter on a
single target's channel, this sniffs and writes every frame addressed
to/from/by that BSSID to a pcap file continuously, so the live
capture-size (KB) readout grows from real on-disk data and the file is
available afterward for handshake/PMKID extraction.

Replaces the vendored airodump-ng process that used to do this via
`-c <channel> --bssid <bssid> --output-format pcap,csv`. The CSV half of
that output was never read by anything downstream (checked: only the
pcap's file size and its frame content matter here), so it's dropped
rather than reproduced.
"""

from __future__ import annotations

from scapy.data import DLT_IEEE802_11_RADIO
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapWriter


class LockCapture:
    """Sniff on `iface` and write every frame touching `bssid` to `outfile`.

    Channel is not managed here — the caller (App._lock_channel) already
    calls ensure_channel() before starting this, and channel lock stays in
    effect until _unlock_channel() calls stop().
    """

    def __init__(self, iface: str, bssid: str, outfile: str):
        self.iface = iface
        self.bssid = bssid.lower()
        self._writer = PcapWriter(outfile, linktype=DLT_IEEE802_11_RADIO, append=True, sync=True)
        self._sniffer: AsyncSniffer | None = None

    def _matches(self, pkt) -> bool:
        dot11 = pkt.getlayer(Dot11)
        if dot11 is None:
            return False
        return any(addr and addr.lower() == self.bssid for addr in (dot11.addr1, dot11.addr2, dot11.addr3))

    def _on_packet(self, pkt) -> None:
        if self._matches(pkt):
            self._writer.write(pkt)

    def start(self) -> None:
        self._sniffer = AsyncSniffer(iface=self.iface, prn=self._on_packet, store=False)
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:  # noqa: BLE001, S110 - teardown must be best-effort
                pass
            self._sniffer = None
        try:
            self._writer.close()
        except Exception:  # noqa: BLE001, S110 - teardown must be best-effort
            pass

    def is_running(self) -> bool:
        if self._sniffer is None or self._sniffer.thread is None:
            return False
        return self._sniffer.thread.is_alive()
