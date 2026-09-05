"""dissect.py: raw-bytes 802.11 frame parsing (dpkt swap, roadmap final
item). Every test builds its fixture via scapy's existing craft_*()
helpers (or a hand-built Raw payload matching the same conventions as
test_scan.py's own fixtures) and cross-checks dissect()'s output
against scapy's own ground-truth values -- not hand-guessed byte
layouts. This is also where the confirmed dpkt Beacon.capability
byte-swap bug is locked in as a regression test."""

from __future__ import annotations

from scapy.layers.dot11 import Dot11, RadioTap
from scapy.layers.eap import EAPOL

from atwa.dissect import (
    SUBTYPE_BEACON,
    TYPE_DATA,
    TYPE_MGMT,
    beacon_capability,
    channel_of,
    dissect,
    eapol_key_info,
    is_beacon_or_probe_resp,
    is_eapol,
    ssid_of,
    walk_ies,
)
from atwa.frames import craft_beacon, craft_probe_resp, craft_rsn_ie

BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "11:22:33:44:55:66"


def test_dissect_beacon_type_subtype():
    pkt = craft_beacon(bssid=BSSID, ssid="TestNet", channel=6)
    frame = dissect(bytes(pkt))
    assert frame is not None
    assert frame.frame_type == TYPE_MGMT
    assert frame.subtype == SUBTYPE_BEACON
    assert is_beacon_or_probe_resp(frame)


def test_dissect_addresses_match_scapy():
    pkt = craft_beacon(bssid=BSSID, ssid="TestNet", channel=6)
    dot11 = pkt.getlayer(Dot11)
    frame = dissect(bytes(pkt))
    assert frame is not None
    assert frame.addr1 == dot11.addr1
    assert frame.addr2 == dot11.addr2
    assert frame.addr3 == dot11.addr3


def test_dissect_sequence_control_matches_scapy():
    pkt = craft_beacon(bssid=BSSID, ssid="TestNet", channel=6)
    pkt.getlayer(Dot11).SC = 0x1230
    frame = dissect(bytes(pkt))
    assert frame is not None
    assert frame.sequence_control == 0x1230


def test_dissect_returns_none_for_short_garbage():
    assert dissect(b"\x00\x00\x08\x00") is None  # radiotap-shaped but no MAC header


def test_dissect_signal_dbm_from_radiotap():
    pkt = craft_beacon(bssid=BSSID, ssid="TestNet", channel=6)
    pkt[RadioTap].present = "Flags+Rate+Channel+dBm_AntSignal"
    pkt[RadioTap].dBm_AntSignal = -57
    frame = dissect(bytes(pkt))
    assert frame is not None
    assert frame.signal_dbm == -57


def test_dissect_signal_dbm_none_when_absent():
    pkt = craft_beacon(bssid=BSSID, ssid="TestNet", channel=6)  # bare RadioTap(), no signal field
    frame = dissect(bytes(pkt))
    assert frame is not None
    assert frame.signal_dbm is None


# --- the confirmed dpkt capability byte-swap bug, locked in as a regression test ---


def test_beacon_capability_privacy_bit_matches_wire_bytes_not_dpkts_native_field():
    """Ground truth: scapy's own emitted wire bytes for cap="privacy"
    are 0x10 0x00 -- correctly little-endian 0x0010, the standard
    802.11 privacy bit. dpkt's own Beacon.capability field misreads
    this as 4096 (0x1000, the big-endian misinterpretation) due to a
    confirmed bug in its unpack() (byte-swaps timestamp/interval but
    not capability) -- this project's own beacon_capability() must NOT
    reproduce that bug."""
    pkt = craft_beacon(bssid=BSSID, ssid="TestNet", channel=6, privacy=True)
    frame = dissect(bytes(pkt))
    assert frame is not None
    cap = beacon_capability(frame)
    assert cap == 0x0010
    assert cap != 4096  # the dpkt bug's exact wrong value -- must never regress to this


def test_beacon_capability_no_privacy():
    pkt = craft_beacon(bssid=BSSID, ssid="TestNet", channel=6, privacy=False)
    frame = dissect(bytes(pkt))
    assert frame is not None
    assert beacon_capability(frame) & 0x0010 == 0


# --- information elements ---


def test_ssid_of_extracts_ssid():
    pkt = craft_beacon(bssid=BSSID, ssid="MyNetwork", channel=6)
    frame = dissect(bytes(pkt))
    assert frame is not None
    assert ssid_of(frame) == "MyNetwork"


def test_ssid_of_none_for_hidden_ssid():
    pkt = craft_beacon(bssid=BSSID, ssid="", channel=6)
    frame = dissect(bytes(pkt))
    assert frame is not None
    assert ssid_of(frame) is None


def test_channel_of_extracts_ds_channel():
    pkt = craft_beacon(bssid=BSSID, ssid="TestNet", channel=11)
    frame = dissect(bytes(pkt))
    assert frame is not None
    assert channel_of(frame) == 11


def test_walk_ies_yields_rsn_element():
    rsn = craft_rsn_ie(akms=[2])
    pkt = craft_beacon(bssid=BSSID, ssid="TestNet", channel=6, privacy=True, extra_ies=[rsn])
    frame = dissect(bytes(pkt))
    assert frame is not None
    ies = dict(walk_ies(frame.body[12:]))
    assert 48 in ies  # RSN element ID
    assert ies[48] == bytes(rsn.info)


def test_dissect_probe_response_also_recognized():
    pkt = craft_probe_resp(bssid=BSSID, ssid="TestNet", client=CLIENT, channel=6)
    frame = dissect(bytes(pkt))
    assert frame is not None
    assert is_beacon_or_probe_resp(frame)
    assert ssid_of(frame) == "TestNet"


# --- EAPOL detection: both real (LLC/SNAP) and simplified test-fixture shapes ---


def _data_frame_with_eapol_llc_snap(bssid: str, client: str, key_frame: bytes) -> bytes:
    """A data frame with a REAL 802.2 LLC/SNAP header before EAPOL --
    matches actual over-the-air captures."""
    dot11 = Dot11(addr1=client, addr2=bssid, addr3=bssid, type=2, subtype=0)
    llc_snap = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
    eapol_hdr = bytes([1, 3]) + len(key_frame).to_bytes(2, "big")
    from scapy.packet import Raw
    return bytes(RadioTap() / dot11 / Raw(load=llc_snap + eapol_hdr + key_frame))


def test_is_eapol_true_with_real_llc_snap_header():
    key_frame = bytes([1]) + (0x0080).to_bytes(2, "big") + b"\x00" * 90  # ack_set, mic not set (M1)
    raw = _data_frame_with_eapol_llc_snap(BSSID, CLIENT, key_frame)
    frame = dissect(raw)
    assert frame is not None
    assert frame.frame_type == TYPE_DATA
    assert is_eapol(frame)
    info = eapol_key_info(frame)
    assert info == (False, True)  # (mic_set, ack_set) -- M1


def test_is_eapol_true_with_simplified_test_fixture_shape():
    """Matches this project's own existing test-fixture convention
    (test_scan.py, test_handshake.py): EAPOL attached directly after
    the MAC header, no LLC/SNAP -- previously relied on scapy's
    layer-tree search working regardless of exact byte adjacency."""
    dot11 = Dot11(addr1=CLIENT, addr2=BSSID, addr3=BSSID, type=2, subtype=0)
    key = bytes([1]) + (0x0100).to_bytes(2, "big") + b"\x00" * 90  # mic_set, ack not set (M2)
    from scapy.packet import Raw
    pkt = dot11 / EAPOL(version=1, type=3) / Raw(load=key)
    frame = dissect(bytes(RadioTap() / pkt))
    assert frame is not None
    assert is_eapol(frame)
    assert eapol_key_info(frame) == (True, False)


def test_is_eapol_false_for_ordinary_data_frame():
    dot11 = Dot11(addr1=CLIENT, addr2=BSSID, addr3=BSSID, type=2, subtype=0)
    from scapy.packet import Raw
    frame = dissect(bytes(RadioTap() / dot11 / Raw(load=b"just some ordinary payload data")))
    assert frame is not None
    assert is_eapol(frame) is False
    assert eapol_key_info(frame) is None
