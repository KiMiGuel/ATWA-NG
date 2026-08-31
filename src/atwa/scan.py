"""Passive scan: sniff beacons/probe-responses while channel hopping."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from scapy.config import conf
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, RadioTap
from scapy.sendrecv import AsyncSniffer

from .frames import bssid_of, channel_of, ssid_of
from .radio import ALL_CHANNELS, CHANNELS_5GHZ, CHANNELS_24GHZ, ChannelHopper
from .secure import security_profile, wps_profile

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
    signal: int | None = None  # best (strongest) dBm seen from RadioTap
    last_signal: int | None = None  # most recent dBm reading (NOT a running max -- for live time-series display)
    beacon_count: int = 0  # number of Dot11Beacon frames seen (not probe responses)
    first_seen: float | None = None  # time.time() of first frame seen for this bssid
    last_seen: float | None = None  # time.time() of most recent frame seen for this bssid
    manufacturer: str | None = None  # OUI vendor name resolved from the BSSID
    rx_quality: int = 0  # 0-100, fraction of the AP's own beacon sequence numbers we didn't miss
    clients: set[str] = field(default_factory=set)
    client_signal: dict[str, int] = field(default_factory=dict)  # best dBm seen per client MAC
    _last_seq: int | None = field(default=None, repr=False, compare=False)
    _fcapt: int = field(default=0, repr=False, compare=False)
    _fmiss: int = field(default=0, repr=False, compare=False)


@dataclass
class ScanResult:
    """Accumulated deduplicated scan results."""

    aps: dict[str, AccessPoint] = field(default_factory=dict)


def _is_target_frame(pkt) -> bool:
    return pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)


def _update_rx_quality(ap: AccessPoint, pkt) -> None:
    """Track the AP's beacon/probe-response sequence numbers to derive
    rx_quality: what fraction of its frames we actually captured, adapted
    from airodump-ng's update_rx_quality() (dump_add_packet()'s seq-gap
    accounting). A gap in the 802.11 SC sequence counter means a frame
    was sent but missed (e.g. we were hopped to another channel) --
    cumulative fcapt/fmiss across the AP's lifetime, not airodump-ng's
    periodic reset-and-recompute window, since this scanner has no
    separate periodic-tick callback to drive that reset from."""
    dot11 = pkt.getlayer(Dot11)
    if dot11 is None:
        return
    seq = dot11.SC >> 4
    if ap._last_seq is not None:
        missed = (seq - ap._last_seq - 1) % 4096
        if 0 < missed < 1000:  # same sanity bound as airodump-ng -- reject wraparound noise
            ap._fmiss += missed
    ap._fcapt += 1
    ap._last_seq = seq
    total = ap._fcapt + ap._fmiss
    ap.rx_quality = min(100, int(100 * ap._fcapt / total)) if total else 0


def process_packet(pkt, result: ScanResult, own_mac: str | None = None) -> None:
    """Update result with AP and client info from one sniffed frame.

    own_mac (optional): the scanning/attacking adapter's own MAC, excluded
    from client detection -- without it, our own auth/deauth/assoc frames
    sent at the target during an attack get misread as a real client of
    that AP (confirmed live, 2026-08-28: our randomized monitor MAC showed
    up in a target's Clients list after running PMKID/deauth against it)."""
    if _is_target_frame(pkt):
        bssid = bssid_of(pkt)
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
        if pkt.haslayer(Dot11Beacon):
            ap.beacon_count += 1
        _update_rx_quality(ap, pkt)
        ssid = ssid_of(pkt)
        if ssid:
            ap.ssid = ssid
        ch = channel_of(pkt)
        if ch:
            ap.channel = ch
        profile = security_profile(pkt)
        # Never let a transient "open" reading downgrade an AP already
        # known to be secured — real captures include malformed/partial
        # frames (weak signal, RF noise) where security_profile() can't
        # find the RSN/WPA IE it's really carrying. Same merge-if-better
        # idea as ssid/channel above, just inverted (open is the "no
        # info" case here, not None).
        if profile["security"] != "open" or ap.security is None:
            ap.security = profile["security"]
            ap.pmf = profile["pmf"]
        wps = wps_profile(pkt)
        if wps is not None:
            ap.wps = wps["state"]  # AP self-reports current lock state each beacon; always take the latest
            for key in ("manufacturer", "model_name", "model_number", "device_name"):
                if wps.get(key):
                    setattr(ap, f"wps_{key}", wps[key])
        rtap = pkt.getlayer(RadioTap)
        dbm = getattr(rtap, "dBm_AntSignal", None) if rtap else None
        if dbm is not None:
            ap.last_signal = dbm  # always the latest reading, unlike signal's running max
            if ap.signal is None or dbm > ap.signal:
                ap.signal = dbm
        return
    dot11 = pkt.getlayer(Dot11)
    if dot11 is None:
        return
    # Attribute client addresses to their AP via addr3 (BSSID) when known.
    bssid = dot11.addr3
    if bssid and bssid in result.aps:
        ap = result.aps[bssid]
        rtap = pkt.getlayer(RadioTap)
        dbm = getattr(rtap, "dBm_AntSignal", None) if rtap else None
        for addr in (dot11.addr1, dot11.addr2):
            if addr and addr != BROADCAST and addr != bssid and (own_mac is None or addr.lower() != own_mac.lower()):
                ap.clients.add(addr)
                if dbm is not None and (addr not in ap.client_signal or dbm > ap.client_signal[addr]):
                    ap.client_signal[addr] = dbm


def scan(iface: str, duration: float = 10.0, channels: list[int] | None = None) -> ScanResult:
    """Passively scan iface for duration seconds, hopping channels.

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
    sniffer = AsyncSniffer(
        iface=iface,
        prn=lambda pkt: process_packet(pkt, result),
        store=False,
    )
    sniffer.start()
    try:
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            hopper.hop()
    finally:
        sniffer.stop()
    return result
