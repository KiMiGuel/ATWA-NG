"""Passive scan: sniff beacons/probe-responses while channel hopping."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, RadioTap
from scapy.sendrecv import AsyncSniffer

from .frames import bssid_of, channel_of, ssid_of
from .radio import ALL_CHANNELS, ChannelHopper
from .secure import security_profile, wps_profile

BROADCAST = "ff:ff:ff:ff:ff:ff"


@dataclass
class AccessPoint:
    """A discovered access point."""

    bssid: str
    ssid: str | None = None
    channel: int | None = None
    security: str | None = None  # open | WEP | WPA | WPA2 | WPA3 | transition
    pmf: str | None = None  # none | capable | required | unknown
    wps: str | None = None  # enabled | locked | None (no WPS IE seen)
    signal: int | None = None  # best (strongest) dBm seen from RadioTap
    clients: set[str] = field(default_factory=set)
    client_signal: dict[str, int] = field(default_factory=dict)  # best dBm seen per client MAC


@dataclass
class ScanResult:
    """Accumulated deduplicated scan results."""

    aps: dict[str, AccessPoint] = field(default_factory=dict)


def _is_target_frame(pkt) -> bool:
    return pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)


def process_packet(pkt, result: ScanResult) -> None:
    """Update result with AP and client info from one sniffed frame."""
    if _is_target_frame(pkt):
        bssid = bssid_of(pkt)
        if not bssid:
            return
        ap = result.aps.setdefault(bssid, AccessPoint(bssid=bssid))
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
            ap.wps = wps  # AP self-reports current lock state each beacon; always take the latest
        rtap = pkt.getlayer(RadioTap)
        dbm = getattr(rtap, "dBm_AntSignal", None) if rtap else None
        if dbm is not None and (ap.signal is None or dbm > ap.signal):
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
            if addr and addr != BROADCAST and addr != bssid:
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
