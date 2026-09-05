"""scan.process_packet: AccessPoint.signal is a running best-ever max (for
the target list's sort/display column); last_signal is the latest reading
(for a live rolling time-series graph) -- see gui/widgets.SignalGraph.
Conflating the two made the GUI's signal graph plateau after the first
strong reading instead of tracking live RSSI."""
from __future__ import annotations

import pytest
from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap

from atwa.frames import craft_beacon, craft_probe_resp, craft_rsn_ie
from atwa.radio import ALL_CHANNELS, CHANNELS_24GHZ, CHANNELS_5GHZ
from atwa.scan import ScanResult, channels_for_band, parse_channel_range, process_packet
from atwa.secure import OWE_TRANSITION_OUI_TYPE


def _data_frame(bssid: str, addr1: str, addr2: str):
    """A data frame attributable to `bssid` via addr3 -- the shape
    process_packet's client-detection branch keys off of."""
    return Dot11(addr1=addr1, addr2=addr2, addr3=bssid, type=2, subtype=0)


def _beacon_with_signal(dbm: int):
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)
    rtap = pkt.getlayer(RadioTap)
    rtap.present = "dBm_AntSignal"
    rtap.dBm_AntSignal = dbm
    return pkt


def test_signal_is_running_max_last_signal_is_latest():
    result = ScanResult()

    process_packet(_beacon_with_signal(-40), result)
    process_packet(_beacon_with_signal(-70), result)
    process_packet(_beacon_with_signal(-55), result)

    ap = result.aps["aa:bb:cc:dd:ee:ff"]
    assert ap.signal == -40  # best-ever seen, never regresses
    assert ap.last_signal == -55  # most recent reading, tracks the drop


def test_last_signal_none_when_no_dbm_reported():
    result = ScanResult()
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)

    process_packet(pkt, result)

    ap = result.aps["aa:bb:cc:dd:ee:ff"]
    assert ap.signal is None
    assert ap.last_signal is None


# --- beacon_count / first_seen / last_seen (native replacement for the old
# airodump-ng CSV's "# beacons" and First/Last time seen columns) -----------


def test_beacon_count_increments_only_for_beacon_frames():
    result = ScanResult()
    beacon = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)
    probe_resp = craft_probe_resp(bssid="aa:bb:cc:dd:ee:ff", ssid="test", client="11:22:33:44:55:66", channel=6)

    process_packet(beacon, result)
    process_packet(beacon, result)
    process_packet(probe_resp, result)

    ap = result.aps["aa:bb:cc:dd:ee:ff"]
    assert ap.beacon_count == 2  # probe response must not count as a beacon


def test_beacon_count_starts_at_zero_for_new_ap():
    result = ScanResult()
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)

    process_packet(pkt, result)

    assert result.aps["aa:bb:cc:dd:ee:ff"].beacon_count == 1


def test_first_seen_set_once_last_seen_updates():
    """Real wall-clock timestamps, not a monkeypatched time.time(): scapy's
    own Packet internals call time.time() too (packet construction, field
    generators), so patching the shared stdlib module is unsafe here."""
    import time as real_time

    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6)
    result = ScanResult()

    process_packet(pkt, result)
    ap = result.aps["aa:bb:cc:dd:ee:ff"]
    first_seen_initial = ap.first_seen
    assert first_seen_initial is not None

    real_time.sleep(0.01)
    process_packet(pkt, result)

    assert ap.first_seen == first_seen_initial  # unchanged on repeat sightings
    assert ap.last_seen > first_seen_initial  # advances on repeat sightings


# --- channels_for_band: native replacement for airodump-ng's --band flag ---


def test_channels_for_band_24ghz():
    assert channels_for_band("2.4GHz") == CHANNELS_24GHZ


def test_channels_for_band_5ghz():
    assert channels_for_band("5GHz") == CHANNELS_5GHZ


def test_channels_for_band_both():
    assert channels_for_band("Both") == ALL_CHANNELS


def test_channels_for_band_unknown_defaults_to_all():
    assert channels_for_band("60GHz-typo") == ALL_CHANNELS


# --- client detection: own_mac exclusion (2026-08-28 live bug) -------------
# Without this, a frame our own attacking interface sends AT a target
# (auth/deauth/assoc, addr2=our MAC, addr3=target bssid) gets misread as a
# real client of that AP -- confirmed live: an attack's own randomized
# monitor MAC ended up listed in the target's Clients panel.


def test_own_mac_excluded_from_client_detection():
    result = ScanResult()
    process_packet(craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6), result)

    process_packet(
        _data_frame("aa:bb:cc:dd:ee:ff", addr1="aa:bb:cc:dd:ee:ff", addr2="11:22:33:44:55:66"),
        result, own_mac="11:22:33:44:55:66",
    )

    assert result.aps["aa:bb:cc:dd:ee:ff"].clients == set()


def test_real_client_still_detected_alongside_own_mac_exclusion():
    result = ScanResult()
    process_packet(craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6), result)

    process_packet(
        _data_frame("aa:bb:cc:dd:ee:ff", addr1="aa:bb:cc:dd:ee:ff", addr2="77:88:99:aa:bb:cc"),
        result, own_mac="11:22:33:44:55:66",
    )

    assert result.aps["aa:bb:cc:dd:ee:ff"].clients == {"77:88:99:aa:bb:cc"}


def test_own_mac_none_keeps_old_behavior():
    """No own_mac passed (e.g. the plain scan() call site) -> no filtering,
    matching every existing caller's unchanged behavior."""
    result = ScanResult()
    process_packet(craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6), result)

    process_packet(
        _data_frame("aa:bb:cc:dd:ee:ff", addr1="aa:bb:cc:dd:ee:ff", addr2="11:22:33:44:55:66"),
        result,
    )

    assert result.aps["aa:bb:cc:dd:ee:ff"].clients == {"11:22:33:44:55:66"}


def _eapol_m1_with_pmkid(bssid: str, client: str, pmkid: bytes):
    """A data frame carrying an EAPOL Message 1 with a PMKID KDE, matching
    what attacks/pmkid.py's extract_pmkid() scans for: `dd <len> 00 0f ac
    04 <pmkid16>`. eapol_key_info() reads mic/ack straight from raw bytes,
    not scapy's named EAPOL_KEY fields, so a hand-built Raw payload is
    the simplest faithful test frame."""
    from scapy.layers.eap import EAPOL
    from scapy.packet import Raw

    key_info = (0x0080).to_bytes(2, "big")  # ack set, mic not set = M1
    kde = b"\xdd\x14\x00\x0f\xac\x04" + pmkid
    key_frame = bytes([2]) + key_info + b"\x00" * 92 + kde
    dot11 = _data_frame(bssid, addr1=client, addr2=bssid)
    return dot11 / EAPOL(version=1, type=3) / Raw(load=key_frame)


def test_process_packet_passively_captures_pmkid_from_ambient_m1():
    result = ScanResult()
    process_packet(craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6), result)

    pmkid_bytes = bytes(range(16))
    process_packet(_eapol_m1_with_pmkid("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", pmkid_bytes), result)

    ap = result.aps["aa:bb:cc:dd:ee:ff"]
    assert ap.pmkid is not None
    assert pmkid_bytes.hex() in ap.pmkid
    assert "aabbccddeeff" in ap.pmkid
    assert "112233445566" in ap.pmkid


def test_process_packet_ignores_non_m1_eapol_for_pmkid():
    """M2/M3/M4 have mic_set -- extract_pmkid should never even run for them
    (M1 is the only handshake message carrying the PMKID KDE in practice)."""
    from scapy.layers.eap import EAPOL
    from scapy.packet import Raw

    result = ScanResult()
    process_packet(craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="test", channel=6), result)

    key_info = (0x0180).to_bytes(2, "big")  # ack set AND mic set = M3, not M1
    kde = b"\xdd\x14\x00\x0f\xac\x04" + bytes(range(16))
    key_frame = bytes([2]) + key_info + b"\x00" * 92 + kde
    frame = _data_frame("aa:bb:cc:dd:ee:ff", addr1="11:22:33:44:55:66", addr2="aa:bb:cc:dd:ee:ff")
    process_packet(frame / EAPOL(version=1, type=3) / Raw(load=key_frame), result)

    assert result.aps["aa:bb:cc:dd:ee:ff"].pmkid is None


def test_process_packet_extracts_owe_transition_pair():
    rsn = craft_rsn_ie(akms=[18])
    ssid_bytes = b"HomeOpen"
    owe_ie = Dot11Elt(ID=221, info=OWE_TRANSITION_OUI_TYPE + bytes.fromhex("112233445566") + bytes([len(ssid_bytes)]) + ssid_bytes)
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="OWENet", channel=6, privacy=True, extra_ies=[rsn, owe_ie])
    result = ScanResult()

    process_packet(pkt, result)

    ap = result.aps["aa:bb:cc:dd:ee:ff"]
    assert ap.security == "OWE"
    assert ap.owe_transition_bssid == "11:22:33:44:55:66"
    assert ap.owe_transition_ssid == "HomeOpen"


def test_process_packet_leaves_owe_transition_none_when_not_advertised():
    rsn = craft_rsn_ie(akms=[18])
    pkt = craft_beacon(bssid="aa:bb:cc:dd:ee:ff", ssid="OWENet", channel=6, privacy=True, extra_ies=[rsn])
    result = ScanResult()

    process_packet(pkt, result)

    ap = result.aps["aa:bb:cc:dd:ee:ff"]
    assert ap.security == "OWE"
    assert ap.owe_transition_bssid is None
    assert ap.owe_transition_ssid is None


def test_parse_channel_range_single_values():
    assert parse_channel_range("1,6,11") == [1, 6, 11]


def test_parse_channel_range_with_ranges():
    assert parse_channel_range("1,3-7,11") == [1, 3, 4, 5, 6, 7, 11]


def test_parse_channel_range_drops_duplicates_preserves_order():
    assert parse_channel_range("6,1,6,11,1") == [6, 1, 11]


def test_parse_channel_range_rejects_backwards_range():
    with pytest.raises(ValueError):
        parse_channel_range("7-3")


def test_parse_channel_range_rejects_empty():
    with pytest.raises(ValueError):
        parse_channel_range("")


def test_parse_channel_range_rejects_garbage():
    with pytest.raises(ValueError):
        parse_channel_range("not-a-channel")
