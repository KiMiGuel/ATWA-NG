"""attacks/online.py: frame-building correctness (hermetic, no hardware)
and online_guess()'s wordlist/budget/stop orchestration via a fake
try_fn -- same dependency-injection pattern as wps_pin_bruteforce's
attempt_fn / omni.py's stage functions.
"""
from __future__ import annotations

import threading

from scapy.layers.eap import EAPOL, EAPOL_KEY

from atwa.attacks.online import (
    OnlineGuessResult,
    _build_m2,
    _craft_client_deauth,
    online_guess,
)
from atwa.wpa.crypto import compute_mic


def test_build_m2_mic_is_verifiable():
    kck = b"\x11" * 16
    snonce = b"\x22" * 32
    rsn_ie = b"\x30\x02\x01\x00"
    frame = _build_m2(
        bssid="aa:bb:cc:dd:ee:ff", client="11:22:33:44:55:66",
        replay_counter=7, descriptor_version=2, snonce=snonce, kck=kck, rsn_ie_bytes=rsn_ie,
    )
    pkt = EAPOL(bytes(frame))
    key = pkt.getlayer(EAPOL_KEY)
    assert bytes(key.key_nonce) == snonce
    assert key.key_replay_counter == 7
    assert key.key_ack == 0
    assert key.has_key_mic == 1
    assert key.key_type == 1  # Pairwise
    assert bytes(key.key_data) == rsn_ie

    embedded_mic = bytes(key.key_mic)
    zeroed = EAPOL_KEY(bytes(key))
    zeroed.key_mic = b"\x00" * 16
    recomputed = compute_mic(kck, bytes(EAPOL(version=1, type=3) / zeroed))
    assert embedded_mic == recomputed
    assert embedded_mic != b"\x00" * 16


def test_build_m2_wrong_kck_gives_different_mic():
    common = dict(
        bssid="aa:bb:cc:dd:ee:ff", client="11:22:33:44:55:66",
        replay_counter=1, descriptor_version=2, snonce=b"\x01" * 32, rsn_ie_bytes=b"\x30\x00",
    )
    frame_a = _build_m2(kck=b"\x01" * 16, **common)
    frame_b = _build_m2(kck=b"\x02" * 16, **common)
    mic_a = bytes(EAPOL(bytes(frame_a)).getlayer(EAPOL_KEY).key_mic)
    mic_b = bytes(EAPOL(bytes(frame_b)).getlayer(EAPOL_KEY).key_mic)
    assert mic_a != mic_b


def test_craft_client_deauth_direction():
    """Client-to-AP deauth must be reversed from frames.craft_deauth's
    AP-to-client direction: source (addr2) is the client, dest (addr1)
    and BSSID (addr3) are the AP."""
    from scapy.layers.dot11 import Dot11

    pkt = _craft_client_deauth("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
    dot11 = pkt.getlayer(Dot11)
    assert dot11.addr1 == "aa:bb:cc:dd:ee:ff"
    assert dot11.addr2 == "11:22:33:44:55:66"
    assert dot11.addr3 == "aa:bb:cc:dd:ee:ff"


def _fake_try_fn(outcomes):
    """outcomes: list of (success, detail) consumed in order, one per call."""
    calls = []

    def fn(iface, bssid, client, ssid, password, msg_timeout):
        calls.append(password)
        return outcomes[len(calls) - 1]

    fn.calls = calls
    return fn


def test_online_guess_succeeds_on_matching_password(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("wrongpass1\ncorrecthorse\nwrongpass2\n")
    try_fn = _fake_try_fn([(False, "wrong"), (True, "AP confirmed Message 3"), (False, "wrong")])

    result = online_guess("mon0", "aa:bb:cc:dd:ee:ff", "TestNet", "11:22:33:44:55:66", str(wordlist), try_fn=try_fn)

    assert result.success is True
    assert result.password == "correcthorse"
    assert result.attempts == 2
    assert try_fn.calls == ["wrongpass1", "correcthorse"]  # stopped after success


def test_online_guess_exhausts_wordlist_without_a_match(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("wrongpass1\nwrongpass2\n")
    try_fn = _fake_try_fn([(False, "wrong"), (False, "wrong")])

    result = online_guess("mon0", "aa:bb:cc:dd:ee:ff", "TestNet", "11:22:33:44:55:66", str(wordlist), try_fn=try_fn)

    assert result.success is False
    assert result.attempts == 2
    assert "exhausted" in result.detail


def test_online_guess_skips_out_of_range_passwords(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("short\n\nlongenoughpass\n" + "x" * 64 + "\n")
    try_fn = _fake_try_fn([(False, "wrong")])

    result = online_guess("mon0", "aa:bb:cc:dd:ee:ff", "TestNet", "11:22:33:44:55:66", str(wordlist), try_fn=try_fn)

    assert result.attempts == 1
    assert result.skipped_invalid == 2  # "short" and the 64-char line; blank line isn't counted at all
    assert try_fn.calls == ["longenoughpass"]


def test_online_guess_respects_max_attempts(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("password1\npassword2\npassword3\n")
    try_fn = _fake_try_fn([(False, "wrong"), (False, "wrong")])

    result = online_guess(
        "mon0", "aa:bb:cc:dd:ee:ff", "TestNet", "11:22:33:44:55:66", str(wordlist),
        max_attempts=2, try_fn=try_fn,
    )

    assert result.attempts == 2
    assert "max_attempts" in result.detail
    assert try_fn.calls == ["password1", "password2"]


def test_online_guess_respects_stop_event(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("password1\npassword2\npassword3\n")
    stop_event = threading.Event()

    def fn(iface, bssid, client, ssid, password, msg_timeout):
        if password == "password1":
            stop_event.set()
        return False, "wrong"

    result = online_guess(
        "mon0", "aa:bb:cc:dd:ee:ff", "TestNet", "11:22:33:44:55:66", str(wordlist),
        stop_event=stop_event, try_fn=fn,
    )

    assert result.attempts == 1
    assert result.detail == "stopped"


def test_online_guess_aborts_after_consecutive_assoc_failures(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("password1\npassword2\npassword3\npassword4\npassword5\n")
    try_fn = _fake_try_fn([(False, "assoc: no auth response")] * 5)

    result = online_guess(
        "mon0", "aa:bb:cc:dd:ee:ff", "TestNet", "11:22:33:44:55:66", str(wordlist),
        max_consecutive_assoc_failures=3, try_fn=try_fn,
    )

    assert result.attempts == 3
    assert "consecutive" in result.detail
    assert try_fn.calls == ["password1", "password2", "password3"]


def test_online_guess_resets_consecutive_failure_count_on_non_assoc_failure(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("password1\npassword2\npassword3\npassword4\npassword5\n")
    outcomes = [
        (False, "assoc: no auth response"),
        (False, "assoc: no auth response"),
        (False, "no Message 3 within timeout -- likely wrong password"),  # resets the streak
        (False, "assoc: no auth response"),
        (False, "assoc: no auth response"),
    ]
    try_fn = _fake_try_fn(outcomes)

    result = online_guess(
        "mon0", "aa:bb:cc:dd:ee:ff", "TestNet", "11:22:33:44:55:66", str(wordlist),
        max_consecutive_assoc_failures=3, try_fn=try_fn,
    )

    # Never hits 3 assoc failures in a row, so it should exhaust the wordlist.
    assert result.attempts == 5
    assert "exhausted" in result.detail
