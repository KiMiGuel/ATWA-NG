"""frames.py: SAE Commit frame crafting/parsing (Dragonblood stage 2,
2026-09-04) -- no dedicated test file existed for frames.py before this;
scoped here to only the new SAE functions, not a retroactive sweep of
the existing craft_*() helpers."""

from __future__ import annotations

from scapy.layers.dot11 import Dot11Auth

from atwa.frames import (
    SAE_GROUP_P256,
    craft_auth,
    craft_sae_commit,
    is_sae_commit,
    sae_commit_group,
)

BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "11:22:33:44:55:66"


def test_craft_sae_commit_sets_sae_algo_and_seqnum():
    pkt = craft_sae_commit(BSSID, CLIENT)
    auth = pkt.getlayer(Dot11Auth)
    assert auth is not None
    assert auth.algo == 3
    assert auth.seqnum == 1


def test_craft_sae_commit_addresses_frame_correctly():
    pkt = craft_sae_commit(BSSID, CLIENT)
    dot11 = pkt.getlayer(Dot11Auth).underlayer
    assert dot11.addr1 == BSSID
    assert dot11.addr2 == CLIENT
    assert dot11.addr3 == BSSID


def test_craft_sae_commit_body_carries_group_and_length():
    pkt = craft_sae_commit(BSSID, CLIENT, group=SAE_GROUP_P256)
    assert sae_commit_group(pkt) == SAE_GROUP_P256


def test_craft_sae_commit_rejects_wrong_seed_length():
    import pytest
    with pytest.raises(ValueError):
        craft_sae_commit(BSSID, CLIENT, seed=b"too short")


def test_craft_sae_commit_seed_is_reproducible():
    seed = b"\x01" * 96
    a = craft_sae_commit(BSSID, CLIENT, seed=seed)
    b = craft_sae_commit(BSSID, CLIENT, seed=seed)
    assert bytes(a) == bytes(b)


def test_craft_sae_commit_random_by_default_not_identical():
    a = craft_sae_commit(BSSID, CLIENT)
    b = craft_sae_commit(BSSID, CLIENT)
    assert bytes(a) != bytes(b)


def test_is_sae_commit_true_for_sae_commit_frame():
    pkt = craft_sae_commit(BSSID, CLIENT)
    assert is_sae_commit(pkt) is True


def test_is_sae_commit_false_for_open_auth():
    pkt = craft_auth(BSSID, CLIENT)
    assert is_sae_commit(pkt) is False


def test_is_sae_commit_false_for_sae_confirm_seqnum():
    # seqnum=2 would be an SAE Confirm, not a Commit -- same algo, different stage.
    pkt = craft_sae_commit(BSSID, CLIENT)
    pkt.getlayer(Dot11Auth).seqnum = 2
    assert is_sae_commit(pkt) is False


def test_sae_commit_group_returns_none_for_non_sae_frame():
    pkt = craft_auth(BSSID, CLIENT)
    assert sae_commit_group(pkt) is None
