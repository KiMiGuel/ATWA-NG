"""Native injection self-test (injection_test.py) — ported from
aireplay-ng's --test attack. Frame shapes are checked directly; the
discovery/ping orchestration is tested with sendp_fn/sniff_fn injected
(no hardware, no vendored binary)."""
from __future__ import annotations

from scapy.layers.dot11 import Dot11, Dot11Auth, Dot11ProbeResp

from atwa.frames import BROADCAST, craft_null_data, craft_probe_req, craft_rts
from atwa.injection_test import InjectionTestResult, _is_reply_to, injection_test


# --- frame shapes ------------------------------------------------------------


def test_craft_probe_req_wildcard_ssid_is_broadcast():
    pkt = craft_probe_req(bssid=BROADCAST, client="11:22:33:44:55:66")
    dot11 = pkt.getlayer(Dot11)
    assert dot11.type == 0 and dot11.subtype == 4
    assert dot11.addr1 == BROADCAST
    assert dot11.addr2 == "11:22:33:44:55:66"


def test_craft_probe_req_directed_carries_ssid():
    pkt = craft_probe_req(bssid="aa:bb:cc:dd:ee:ff", client="11:22:33:44:55:66", ssid="MyNet")
    dot11 = pkt.getlayer(Dot11)
    assert dot11.addr1 == "aa:bb:cc:dd:ee:ff"
    assert dot11.addr3 == "aa:bb:cc:dd:ee:ff"


def test_craft_rts_is_control_frame_addressed_to_bssid():
    pkt = craft_rts(bssid="aa:bb:cc:dd:ee:ff", client="11:22:33:44:55:66")
    dot11 = pkt.getlayer(Dot11)
    assert dot11.type == 1 and dot11.subtype == 11
    assert dot11.addr1 == "aa:bb:cc:dd:ee:ff"


def test_craft_null_data_addressing():
    pkt = craft_null_data(bssid="aa:bb:cc:dd:ee:ff", client="11:22:33:44:55:66")
    dot11 = pkt.getlayer(Dot11)
    assert dot11.type == 2 and dot11.subtype == 4
    assert dot11.addr1 == "aa:bb:cc:dd:ee:ff"
    assert dot11.addr2 == "11:22:33:44:55:66"
    assert dot11.addr3 == "aa:bb:cc:dd:ee:ff"


# --- _is_reply_to -------------------------------------------------------


def test_is_reply_to_matches_probe_response_from_bssid():
    from atwa.frames import craft_probe_resp

    pkt = craft_probe_resp(bssid="aa:bb:cc:dd:ee:ff", ssid="test", client="11:22:33:44:55:66")
    assert _is_reply_to(pkt, "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff") is True


def test_is_reply_to_rejects_probe_response_from_wrong_bssid():
    from atwa.frames import craft_probe_resp

    pkt = craft_probe_resp(bssid="11:11:11:11:11:11", ssid="test", client="11:22:33:44:55:66")
    assert _is_reply_to(pkt, "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff") is False


def test_is_reply_to_rejects_frame_not_addressed_to_client():
    from atwa.frames import craft_probe_resp

    pkt = craft_probe_resp(bssid="aa:bb:cc:dd:ee:ff", ssid="test", client="ff:ff:ff:ff:ff:ff")
    assert _is_reply_to(pkt, "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff") is False


def test_is_reply_to_matches_cts_control_frame():
    pkt = Dot11(type=1, subtype=12, addr1="11:22:33:44:55:66")
    assert _is_reply_to(pkt, "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff") is True


def test_is_reply_to_matches_ack_control_frame():
    pkt = Dot11(type=1, subtype=13, addr1="11:22:33:44:55:66")
    assert _is_reply_to(pkt, "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff") is True


def test_is_reply_to_matches_auth_response_from_bssid():
    pkt = Dot11(type=0, subtype=11, addr1="11:22:33:44:55:66", addr2="aa:bb:cc:dd:ee:ff") / Dot11Auth()
    assert _is_reply_to(pkt, "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff") is True


def test_is_reply_to_case_insensitive_mac_match():
    pkt = Dot11(type=1, subtype=13, addr1="11:22:33:44:55:66")
    assert _is_reply_to(pkt, "11:22:33:44:55:66".upper(), "aa:bb:cc:dd:ee:ff") is True


# --- injection_test(): discovery + directed ping orchestration -------------


def _fake_sendp(pkt, iface, verbose=False):
    pass


def test_injection_test_returns_no_ap_found_when_discovery_empty(monkeypatch):
    def sniff_never_finds(iface, timeout, prn, store, stop_filter=None):
        return  # never calls prn -- no reply ever seen

    result = injection_test(
        "wlan0mon", bssid=None, count=5,
        sendp_fn=_fake_sendp, sniff_fn=sniff_never_finds,
    )

    assert result.bssid is None
    assert "no AP found" in result.detail
    assert result.pings_sent == 0


def test_injection_test_uses_given_bssid_without_discovery(monkeypatch):
    """If bssid is given, discovery must be skipped entirely -- sniff_fn
    should only be called once per directed-ping attempt, not for a
    broadcast discovery phase too."""
    call_count = {"n": 0}

    def sniff_counts(iface, timeout, prn, store, stop_filter=None):
        call_count["n"] += 1

    result = injection_test(
        "wlan0mon", bssid="aa:bb:cc:dd:ee:ff", count=3,
        sendp_fn=_fake_sendp, sniff_fn=sniff_counts,
    )

    assert result.bssid == "aa:bb:cc:dd:ee:ff"
    assert call_count["n"] == 3  # one sniff per directed-ping attempt, no discovery sniffs


def test_injection_test_counts_answered_pings_with_patched_mac(monkeypatch):
    """Simulate 2 of 4 directed pings getting a real reply. _random_mac is
    pinned so the mocked sniff_fn can synthesize a reply addressed to the
    exact MAC injection_test() used for that attempt."""
    import atwa.injection_test as injection_test_module

    monkeypatch.setattr(injection_test_module, "_random_mac", lambda: "11:22:33:44:55:66")
    attempt = {"n": 0}

    def sniff_alternating(iface, timeout, prn, store, stop_filter=None):
        attempt["n"] += 1
        if attempt["n"] % 2 == 0:
            prn(Dot11(type=1, subtype=13, addr1="11:22:33:44:55:66"))  # ACK back to our fixed MAC

    result = injection_test(
        "wlan0mon", bssid="aa:bb:cc:dd:ee:ff", count=4,
        sendp_fn=_fake_sendp, sniff_fn=sniff_alternating,
    )

    assert result.pings_sent == 4
    assert result.pings_answered == 2
    assert result.percent == 50.0
    assert result.detail == "injection is working"


def test_injection_test_percent_zero_when_nothing_sent():
    assert InjectionTestResult().percent == 0.0
