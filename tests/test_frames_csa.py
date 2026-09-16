"""frames.py: craft_csa_action() -- Channel Switch Announcement Action
frame (Phase 4.1, v2.4). Category 0 (Spectrum Management) / Action 4,
NOT category 6 as an earlier internal note mistakenly had it -- see the
function's own docstring for why."""
from __future__ import annotations

from scapy.layers.dot11 import Dot11, Dot11Elt

from atwa.frames import craft_csa_action

BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "11:22:33:44:55:66"


def test_craft_csa_action_addresses_frame_from_ap_to_client():
    pkt = craft_csa_action(BSSID, CLIENT, new_channel=6)
    dot11 = pkt.getlayer(Dot11)
    assert dot11.type == 0
    assert dot11.subtype == 13  # Action
    assert dot11.addr1 == CLIENT
    assert dot11.addr2 == BSSID
    assert dot11.addr3 == BSSID


def test_craft_csa_action_category_and_action_are_spectrum_management():
    pkt = craft_csa_action(BSSID, CLIENT, new_channel=6)
    raw = bytes(pkt)
    # Raw(category, action) sits right after the fixed Dot11 header fields.
    action_body = bytes(pkt.getlayer(Dot11).payload)
    assert action_body[0] == 0  # category: Spectrum Management
    assert action_body[1] == 4  # action: Channel Switch Announcement
    assert len(raw) > 0


def test_craft_csa_action_ie_carries_new_channel_and_count():
    pkt = craft_csa_action(BSSID, CLIENT, new_channel=11, count=3)
    ie = pkt.getlayer(Dot11Elt)
    assert ie is not None
    assert ie.ID == 37  # Channel Switch Announcement element
    switch_mode, new_channel, switch_count = ie.info[0], ie.info[1], ie.info[2]
    assert switch_mode == 1
    assert new_channel == 11
    assert switch_count == 3


def test_craft_csa_action_defaults_count_to_one():
    pkt = craft_csa_action(BSSID, CLIENT, new_channel=1)
    ie = pkt.getlayer(Dot11Elt)
    assert ie.info[2] == 1
