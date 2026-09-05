"""Passive scan: sniff beacons/probe-responses while channel hopping."""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field

from scapy.config import conf
from scapy.sendrecv import sendp

from .attacks.pmkid import extract_pmkid, to_22000
from .dissect import Frame, channel_of, dissect, eapol_key_info, is_beacon_or_probe_resp, is_eapol, ssid_of
from .frames import craft_probe_req
from .radio import ALL_CHANNELS, CHANNELS_5GHZ, CHANNELS_24GHZ, ChannelHopper, random_locally_administered_mac
from .secure import owe_transition_info, security_profile, wps_profile

BROADCAST = "ff:ff:ff:ff:ff:ff"

# Band-name -> channel-subset mapping. Native replacement for the vendored
# airodump-ng engine's --band bg/a/abg flag, kept as the same three
# GUI-facing labels ("2.4GHz" / "5GHz" / "Both") so callers don't change.
BAND_CHANNELS = {
    "2.4GHz": CHANNELS_24GHZ,
    "5GHz": CHANNELS_5GHZ,
    "Both": ALL_CHANNELS,
}


def channels_for_band(band: str) -> list[int]:
    """Return the channel list for a band label, defaulting to ALL_CHANNELS
    for 'Both' or any unrecognized value (matches the old --band abg default)."""
    return list(BAND_CHANNELS.get(band, ALL_CHANNELS))


def parse_channel_range(spec: str) -> list[int]:
    """Parse a comma-separated channel spec with optional ranges, e.g.
    "1,6,11" or "1,3-7,11" -- same syntax as airodump-ng's -c/--channel.
    Raises ValueError on malformed input. Order is preserved as given,
    duplicates are dropped."""
    seen: dict[int, None] = {}
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_s, _, end_s = token.partition("-")
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(f"invalid channel range {token!r}: start > end")
            for ch in range(start, end + 1):
                seen[ch] = None
        else:
            seen[int(token)] = None
    if not seen:
        raise ValueError(f"no channels parsed from {spec!r}")
    return list(seen)


@dataclass
class AccessPoint:
    """A discovered access point."""

    bssid: str
    ssid: str | None = None
    channel: int | None = None
    security: str | None = None  # open | WEP | WPA | WPA2 | WPA3 | transition
    pmf: str | None = None  # none | capable | required | unknown
    wps: str | None = None  # enabled | locked | None (no WPS IE seen)
    wps_manufacturer: str | None = None
    wps_model_name: str | None = None
    wps_model_number: str | None = None
    wps_device_name: str | None = None
    owe_transition_bssid: str | None = None  # paired open BSS, from the OWE Transition Mode IE
    owe_transition_ssid: str | None = None
    signal: int | None = None  # best (strongest) dBm seen from RadioTap
    last_signal: int | None = None  # most recent dBm reading (NOT a running max -- for live time-series display)
    beacon_count: int = 0  # number of beacon frames seen (not probe responses)
    first_seen: float | None = None  # time.time() of first frame seen for this bssid
    last_seen: float | None = None  # time.time() of most recent frame seen for this bssid
    manufacturer: str | None = None  # OUI vendor name resolved from the BSSID
    rx_quality: int = 0  # 0-100, fraction of the AP's own beacon sequence numbers we didn't miss
    pmkid: str | None = None  # 22000-format line, opportunistically sniffed from ambient EAPOL M1 traffic
    clients: set[str] = field(default_factory=set)
    client_signal: dict[str, int] = field(default_factory=dict)  # best dBm seen per client MAC
    _last_seq: int | None = field(default=None, repr=False, compare=False)
    _fcapt: int = field(default=0, repr=False, compare=False)
    _fmiss: int = field(default=0, repr=False, compare=False)


@dataclass
class ScanResult:
    """Accumulated deduplicated scan results."""

    aps: dict[str, AccessPoint] = field(default_factory=dict)


def _update_rx_quality(ap: AccessPoint, frame: Frame) -> None:
    """Track the AP's beacon/probe-response sequence numbers to derive
    rx_quality: what fraction of its frames we actually captured, adapted
    from airodump-ng's update_rx_quality() (dump_add_packet()'s seq-gap
    accounting). A gap in the 802.11 SC sequence counter means a frame
    was sent but missed (e.g. we were hopped to another channel) --
    cumulative fcapt/fmiss across the AP's lifetime, not airodump-ng's
    periodic reset-and-recompute window, since this scanner has no
    separate periodic-tick callback to drive that reset from."""
    seq = frame.sequence_control >> 4
    if ap._last_seq is not None:
        missed = (seq - ap._last_seq - 1) % 4096
        if 0 < missed < 1000:  # same sanity bound as airodump-ng -- reject wraparound noise
            ap._fmiss += missed
    ap._fcapt += 1
    ap._last_seq = seq
    total = ap._fcapt + ap._fmiss
    ap.rx_quality = min(100, int(100 * ap._fcapt / total)) if total else 0


def process_packet(raw: bytes, result: ScanResult, own_mac: str | None = None) -> None:
    """Update result with AP and client info from one sniffed frame
    (RadioTap header onward, as captured off the wire).

    own_mac (optional): the scanning/attacking adapter's own MAC, excluded
    from client detection -- without it, our own auth/deauth/assoc frames
    sent at the target during an attack get misread as a real client of
    that AP (confirmed live, 2026-08-28: our randomized monitor MAC showed
    up in a target's Clients list after running PMKID/deauth against it)."""
    frame = dissect(raw)
    if frame is None:
        return
    if is_beacon_or_probe_resp(frame):
        bssid = frame.addr3
        if not bssid:
            return
        now = time.time()
        is_new = bssid not in result.aps
        ap = result.aps.setdefault(bssid, AccessPoint(bssid=bssid))
        if is_new:
            ap.first_seen = now
            manuf = conf.manufdb._get_manuf(bssid)
            if manuf and manuf.lower() != bssid.lower():
                ap.manufacturer = manuf
        ap.last_seen = now
        if frame.subtype == 8:  # beacon, not probe response
            ap.beacon_count += 1
        _update_rx_quality(ap, frame)
        ssid = ssid_of(frame)
        if ssid:
            ap.ssid = ssid
        ch = channel_of(frame)
        if ch:
            ap.channel = ch
        profile = security_profile(frame)
        # Never let a transient "open" reading downgrade an AP already
        # known to be secured — real captures include malformed/partial
        # frames (weak signal, RF noise) where security_profile() can't
        # find the RSN/WPA IE it's really carrying. Same merge-if-better
        # idea as ssid/channel above, just inverted (open is the "no
        # info" case here, not None).
        if profile["security"] != "open" or ap.security is None:
            ap.security = profile["security"]
            ap.pmf = profile["pmf"]
        if ap.security == "OWE":
            owe = owe_transition_info(frame)
            if owe is not None:
                ap.owe_transition_bssid = owe["bssid"]
                ap.owe_transition_ssid = owe["ssid"]
        wps = wps_profile(frame)
        if wps is not None:
            ap.wps = wps["state"]  # AP self-reports current lock state each beacon; always take the latest
            for key in ("manufacturer", "model_name", "model_number", "device_name"):
                if wps.get(key):
                    setattr(ap, f"wps_{key}", wps[key])
        if frame.signal_dbm is not None:
            ap.last_signal = frame.signal_dbm  # always the latest reading, unlike signal's running max
            if ap.signal is None or frame.signal_dbm > ap.signal:
                ap.signal = frame.signal_dbm
        return
    # Attribute client addresses to their AP via addr3 (BSSID) when known.
    bssid = frame.addr3
    if bssid and bssid in result.aps:
        ap = result.aps[bssid]
        dbm = frame.signal_dbm
        for addr in (frame.addr1, frame.addr2):
            if addr and addr != BROADCAST and addr != bssid and (own_mac is None or addr.lower() != own_mac.lower()):
                ap.clients.add(addr)
                if dbm is not None and (addr not in ap.client_signal or dbm > ap.client_signal[addr]):
                    ap.client_signal[addr] = dbm
        # Opportunistic passive PMKID capture: airodump-ng extracts a PMKID
        # from ANY observed EAPOL Message 1, not just frames triggered by
        # our own active association (that's attacks/pmkid.py's job). A
        # client naturally reconnecting to this AP during a routine scan
        # is a "free" capture we were previously just discarding.
        if ap.pmkid is None and is_eapol(frame):
            info = eapol_key_info(frame)
            if info is not None and info[1] and not info[0]:  # M1: ack set, mic not set
                found = extract_pmkid(frame.raw)
                if found:
                    client = frame.addr1 if frame.addr2 == bssid else frame.addr2
                    ap.pmkid = to_22000(found, bssid, client, ap.ssid)


class RawFrameSniffer:
    """Continuous raw-bytes capture loop -- the dpkt-swap replacement for
    scapy's AsyncSniffer in the scan hot path. Opens a raw AF_PACKET
    socket via scapy's own L2listen() (socket setup/promisc/bind
    machinery is unrelated to the per-packet dissection cost this swap
    targets, so it stays) but calls recv_raw() instead of recv() --
    recv_raw() returns raw bytes without scapy dissecting them into a
    Packet object, letting prn() hand them to dissect() instead.

    Deliberately mirrors just the AsyncSniffer surface callers already
    depend on (start()/stop()/.thread.is_alive()/.exception) so the
    self-healing check wired into the GUI's scan loop (app.py
    _start_scan, radio.check_and_heal()) keeps working unchanged.
    """

    def __init__(self, iface: str, prn):
        self.iface = iface
        self.prn = prn
        self.exception: Exception | None = None
        self.thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        sock = None
        try:
            sock = conf.L2listen(iface=self.iface)
            sock.ins.settimeout(0.5)  # periodic wake-up so stop() is noticed promptly even with no traffic
            while not self._stop_event.is_set():
                try:
                    _cls, raw, _ts = sock.recv_raw()
                except socket.timeout:
                    continue
                if raw:
                    self.prn(raw)
        except Exception as exc:  # noqa: BLE001 - surfaced via .exception, same contract as AsyncSniffer
            self.exception = exc
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:  # noqa: BLE001, S110 - close can race with teardown
                    pass

    def stop(self) -> None:
        self._stop_event.set()


def scan(
    iface: str,
    duration: float = 10.0,
    channels: list[int] | None = None,
    active_probe_interval: float | None = None,
) -> ScanResult:
    """Passively scan iface for duration seconds, hopping channels.

    active_probe_interval (optional): if set, broadcast a wildcard probe
    request (empty SSID, random source MAC) roughly every N seconds --
    ported from airodump-ng's --active-scan-sim (-x). Provokes faster AP
    responses and can reveal hidden SSIDs sooner than waiting passively
    for a client to probe first. Off by default since it's active
    (transmits), unlike the rest of this function.

    Keeps ONE capture socket open for the whole scan instead of opening
    a fresh sniff() per channel hop. The old per-hop sniff() approach
    opened/closed a raw socket on every single hop (~every dwell
    period), which on mt76x0u drops the adapter out of promiscuous mode
    and back in on each call (confirmed live via dmesg — "entered/left
    promiscuous mode" firing in lockstep with the dwell timer). Each of
    those USB control-transfer round trips eats into the listening
    window, so a real chunk of every dwell period was spent on socket
    teardown/setup rather than actually receiving frames — beacons
    arriving during that gap were simply missed. rtw88_8814au doesn't
    show the same symptom, which is why this only showed up as "wlan1
    barely sees anything" and not on wlan0 despite identical channel
    hopping logic."""
    result = ScanResult()
    hopper = ChannelHopper(iface=iface, channels=channels or list(ALL_CHANNELS))
    sniffer = RawFrameSniffer(
        iface=iface,
        prn=lambda raw: process_packet(raw, result),
    )
    sniffer.start()
    try:
        deadline = time.monotonic() + duration
        probe_interval: float = active_probe_interval or 0.0
        next_probe = time.monotonic() + probe_interval if probe_interval else None
        while time.monotonic() < deadline:
            hopper.hop()
            if next_probe is not None and time.monotonic() >= next_probe:
                probe = craft_probe_req(BROADCAST, random_locally_administered_mac())
                sendp(probe, iface=iface, verbose=False)
                next_probe = time.monotonic() + probe_interval
    finally:
        sniffer.stop()
    return result
