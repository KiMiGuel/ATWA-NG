"""attacks/pmkid.py: 22000 formatting and PMKID extraction (hermetic)."""
from __future__ import annotations

from atwa.attacks.pmkid import extract_pmkid, to_22000


def test_to_22000_includes_essid_when_given():
    """PMK = PBKDF2(password, ESSID) -- a PMKID 22000 line without the
    ESSID field is uncrackable, so it must be the 4th field (hex)."""
    line = to_22000(b"\xab" * 16, "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "TestNet")
    pmkid_hex, mac_ap, mac_cl, essid_hex = line.split("*")
    assert pmkid_hex == "ab" * 16
    assert mac_ap == "aabbccddeeff"
    assert mac_cl == "112233445566"
    assert essid_hex == "TestNet".encode().hex()


def test_to_22000_omits_essid_field_when_none():
    line = to_22000(b"\xab" * 16, "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
    assert line.split("*") == ["ab" * 16, "aabbccddeeff", "112233445566"]


def test_extract_pmkid_from_rsn_kde():
    pmkid = bytes(range(16))
    kde = b"\xdd\x14\x00\x0f\xac\x04" + pmkid
    eapol_raw = b"\x00" * 40 + kde + b"\x00" * 10
    assert extract_pmkid(eapol_raw) == pmkid


def test_extract_pmkid_none_when_no_kde():
    assert extract_pmkid(b"\x00" * 100) is None
