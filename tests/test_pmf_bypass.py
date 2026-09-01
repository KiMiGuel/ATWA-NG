"""attacks/pmf_bypass.py: the malformed 4-way-handshake Message 1/4 frame
is ported byte-for-byte from a published PoC (see module docstring for
provenance) -- these tests confirm the ported bytes round-trip correctly
and the frame addressing is right, not that the underlying vulnerability
itself works (that needs a real vulnerable client)."""

from __future__ import annotations

from scapy.layers.dot11 import Dot11, Dot11QoS
from scapy.layers.l2 import LLC, SNAP

from atwa.attacks.pmf_bypass import (
    KEY_INFO_WPA2_PMF,
    KEY_INFO_WPA3_PMF,
    _CORRUPTED_M1_HEX,
    craft_corrupted_m1,
)

BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "11:22:33:44:55:66"


def test_corrupted_hex_payload_is_valid_hex_and_length_matches_its_own_declared_size():
    payload = bytes.fromhex(_CORRUPTED_M1_HEX.format(key_info=KEY_INFO_WPA3_PMF))
    # Byte 1 is EAPOL type (0x03 = EAPOL-Key), bytes 2-3 are the EAPOL body
    # length (big-endian). Total frame = 4-byte EAPOL header + declared
    # body length -- checking this against the actual byte count is a
    # real cross-check that the hand-transcribed PoC hex wasn't mangled.
    declared_body_len = int.from_bytes(payload[2:4], "big")
    assert len(payload) == 4 + declared_body_len == 121


def test_corrupted_payload_contains_the_underflowed_pmkid_tag():
    payload = bytes.fromhex(_CORRUPTED_M1_HEX.format(key_info=KEY_INFO_WPA3_PMF))
    assert b"\xdd\xff\x00\x0f\xac\x04" in payload


def test_key_info_byte_is_actually_substituted():
    wpa3 = bytes.fromhex(_CORRUPTED_M1_HEX.format(key_info=KEY_INFO_WPA3_PMF))
    wpa2 = bytes.fromhex(_CORRUPTED_M1_HEX.format(key_info=KEY_INFO_WPA2_PMF))
    assert wpa3 != wpa2
    assert wpa3[5:7] == b"\x00\x88"
    assert wpa2[5:7] == b"\x00\x8a"


def test_craft_corrupted_m1_frame_shape_and_addressing():
    pkt = craft_corrupted_m1(BSSID, CLIENT)
    dot11 = pkt.getlayer(Dot11)
    assert dot11 is not None
    assert dot11.type == 2  # data
    assert dot11.subtype == 8  # QoS data
    assert dot11.addr2 == BSSID  # sent as if from the AP
    assert dot11.addr1 == CLIENT
    assert pkt.haslayer(Dot11QoS)
    assert pkt.haslayer(LLC)
    assert pkt.haslayer(SNAP)


def test_craft_corrupted_m1_serializes_without_error():
    pkt = craft_corrupted_m1(BSSID, CLIENT)
    raw = bytes(pkt)
    assert len(raw) > 0
