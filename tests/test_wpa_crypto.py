"""wpa/crypto.py correctness: PMK cross-checked against wpa_passphrase
(wpa_supplicant's own reference tool) rather than hand-typed test
vectors; PTK/MIC checked for spec-shape properties (determinism,
role-symmetry, sensitivity to each input) since no independent local
tool computes those in isolation -- live verification against a real
AP is the real proof for those, done separately, not here.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from atwa.wpa.crypto import compute_mic, derive_pmk, derive_ptk, mac_to_bytes, split_ptk

WPA_PASSPHRASE = shutil.which("wpa_passphrase")


def _reference_pmk(ssid: str, passphrase: str) -> bytes:
    out = subprocess.run(
        [WPA_PASSPHRASE, ssid, passphrase], capture_output=True, text=True, timeout=5, check=True
    ).stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("psk="):
            return bytes.fromhex(line.split("=", 1)[1])
    raise AssertionError(f"no psk= line in wpa_passphrase output:\n{out}")


@pytest.mark.skipif(WPA_PASSPHRASE is None, reason="wpa_passphrase not installed")
@pytest.mark.parametrize(
    "ssid,passphrase",
    [
        ("IEEE", "password"),
        ("ThisIsASSID", "ThisIsAPassword"),
        ("Indepentester", "correcthorsebatterystaple"),
        ("a", "12345678"),  # shortest legal passphrase, shortest legal-ish ssid
        ("with space", "with space too!!"),
    ],
)
def test_derive_pmk_matches_wpa_passphrase(ssid, passphrase):
    assert derive_pmk(passphrase, ssid) == _reference_pmk(ssid, passphrase)


def test_derive_pmk_rejects_out_of_range_length():
    with pytest.raises(ValueError):
        derive_pmk("short", "ssid")
    with pytest.raises(ValueError):
        derive_pmk("x" * 64, "ssid")


def test_derive_pmk_boundary_lengths_accepted():
    assert len(derive_pmk("x" * 8, "ssid")) == 32
    assert len(derive_pmk("x" * 63, "ssid")) == 32


def test_derive_pmk_is_deterministic_and_ssid_sensitive():
    pmk1 = derive_pmk("password123", "NetworkA")
    pmk2 = derive_pmk("password123", "NetworkA")
    pmk3 = derive_pmk("password123", "NetworkB")
    assert pmk1 == pmk2
    assert pmk1 != pmk3


def _fixed_inputs():
    pmk = derive_pmk("password123", "TestNet")
    aa = mac_to_bytes("aa:bb:cc:dd:ee:ff")
    spa = mac_to_bytes("11:22:33:44:55:66")
    anonce = bytes(range(32))
    snonce = bytes(range(32, 64))
    return pmk, aa, spa, anonce, snonce


def test_derive_ptk_is_384_bits_and_deterministic():
    pmk, aa, spa, anonce, snonce = _fixed_inputs()
    ptk1 = derive_ptk(pmk, aa, spa, anonce, snonce)
    ptk2 = derive_ptk(pmk, aa, spa, anonce, snonce)
    assert len(ptk1) == 48
    assert ptk1 == ptk2


def test_derive_ptk_is_role_symmetric():
    """The AP (using its own MAC as aa/its ANonce, the station's MAC/SNonce
    as the peer's) and the station (mirrored) must derive the identical
    PTK -- that's the entire point of the min/max canonical ordering."""
    pmk, aa, spa, anonce, snonce = _fixed_inputs()
    ptk_as_ap = derive_ptk(pmk, aa, spa, anonce, snonce)
    ptk_as_station = derive_ptk(pmk, spa, aa, snonce, anonce)
    assert ptk_as_ap == ptk_as_station


@pytest.mark.parametrize("vary", ["pmk", "aa", "spa", "anonce", "snonce"])
def test_derive_ptk_is_sensitive_to_every_input(vary):
    pmk, aa, spa, anonce, snonce = _fixed_inputs()
    base = derive_ptk(pmk, aa, spa, anonce, snonce)
    kwargs = {"pmk": pmk, "aa": aa, "spa": spa, "anonce": anonce, "snonce": snonce}
    if vary == "pmk":
        kwargs["pmk"] = derive_pmk("differentpw", "TestNet")
    elif vary == "aa":
        kwargs["aa"] = mac_to_bytes("00:00:00:00:00:01")
    elif vary == "spa":
        kwargs["spa"] = mac_to_bytes("00:00:00:00:00:02")
    elif vary == "anonce":
        kwargs["anonce"] = bytes(range(1, 33))
    elif vary == "snonce":
        kwargs["snonce"] = bytes(range(33, 65))
    varied = derive_ptk(**kwargs)
    assert varied != base


def test_split_ptk_layout():
    pmk, aa, spa, anonce, snonce = _fixed_inputs()
    ptk = derive_ptk(pmk, aa, spa, anonce, snonce)
    kck, kek, tk = split_ptk(ptk)
    assert (len(kck), len(kek), len(tk)) == (16, 16, 16)
    assert kck + kek + tk == ptk


def test_compute_mic_is_16_bytes_deterministic_and_key_sensitive():
    kck = b"\x01" * 16
    frame = b"\x02" * 99
    mic1 = compute_mic(kck, frame)
    mic2 = compute_mic(kck, frame)
    assert len(mic1) == 16
    assert mic1 == mic2
    assert compute_mic(b"\x03" * 16, frame) != mic1


def test_mac_to_bytes():
    assert mac_to_bytes("aa:bb:cc:dd:ee:ff") == bytes.fromhex("aabbccddeeff")
