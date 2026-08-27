"""WPA/WPA2-Personal (PSK) key derivation: PMK -> PTK -> MIC.

PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096 iterations, 256 bits) --
IEEE 802.11i's own PSK-to-PMK mapping, delegated straight to Python's
stdlib hashlib.pbkdf2_hmac rather than a hand-rolled PBKDF2 loop, to keep
this one load-bearing step out of "did I get the iteration math right"
territory. Cross-checked directly against `wpa_passphrase`
(wpa_supplicant's own reference tool) in tests/test_wpa_crypto.py rather
than hand-typed test vectors, so correctness doesn't depend on anyone's
memory of a hex string.

PTK = PRF-384(PMK, "Pairwise key expansion", B) where B canonically
orders the two MAC addresses and two nonces (min/max byte comparison,
not role-based) per 802.11i 8.5.1.2 -- this is what lets the AP and
station derive the identical PTK despite each computing "own" vs "peer"
MAC/nonce in opposite roles. The PRF itself is the 802.11i sha1_prf
construction (iterated HMAC-SHA1 over label || 0x00 || data || counter),
the same formula hostapd/wpa_supplicant, aircrack-ng, cowpatty, and
hashcat's wpapsk mode all use.

Scope: CCMP/AES pairwise cipher only (Key Descriptor Version 2,
HMAC-SHA1-128 MIC) -- the overwhelming majority of real WPA2-Personal
deployments. TKIP (version 1, HMAC-MD5 MIC, Michael) is not implemented.
"""

from __future__ import annotations

import hashlib
import hmac


def derive_pmk(passphrase: str, ssid: str) -> bytes:
    """PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 256 bits).

    Raises ValueError for a passphrase outside the WPA-PSK-valid 8-63
    ASCII character range -- an out-of-range passphrase isn't a "wrong
    password", it's not a legal PSK input at all, so a wordlist walk
    should skip it rather than waste a live attempt deriving a PMK the
    real AP could never have been configured with.
    """
    if not 8 <= len(passphrase) <= 63:
        raise ValueError(f"WPA-PSK passphrase must be 8-63 characters, got {len(passphrase)}")
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"), ssid.encode("utf-8"), 4096, 32)


def _prf_sha1(key: bytes, label: bytes, data: bytes, bits: int) -> bytes:
    """802.11i PRF: iterated HMAC-SHA1(key, label || 0x00 || data || i), i=0,1,2,..."""
    n_blocks = (bits + 159) // 160
    out = b"".join(
        hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        for i in range(n_blocks)
    )
    return out[: bits // 8]


def derive_ptk(pmk: bytes, aa: bytes, spa: bytes, anonce: bytes, snonce: bytes, key_bits: int = 384) -> bytes:
    """PTK = PRF-key_bits(PMK, "Pairwise key expansion", B).

    aa/spa: raw 6-byte MAC addresses (Authenticator=AP, Supplicant=client).
    anonce/snonce: raw 32-byte nonces. key_bits=384 for CCMP (128 KCK +
    128 KEK + 128 TK) -- see module docstring for TKIP's out-of-scope note.
    """
    b = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    return _prf_sha1(pmk, b"Pairwise key expansion", b, key_bits)


def split_ptk(ptk: bytes) -> tuple[bytes, bytes, bytes]:
    """CCMP PTK layout: KCK(16) | KEK(16) | TK(16)."""
    return ptk[0:16], ptk[16:32], ptk[32:48]


def compute_mic(kck: bytes, eapol_frame_mic_zeroed: bytes) -> bytes:
    """MIC = first 16 bytes of HMAC-SHA1(KCK, eapol_frame) -- Key Descriptor
    Version 2 (HMAC-SHA1-128), the version real WPA2-Personal/CCMP APs use.

    Caller must zero the frame's own 16-byte MIC field before serializing
    the bytes passed in here (the MIC is computed over the frame as if
    the MIC field were all-zero, per 802.11i 8.5.2)."""
    return hmac.new(kck, eapol_frame_mic_zeroed, hashlib.sha1).digest()[:16]


def mac_to_bytes(mac: str) -> bytes:
    """'aa:bb:cc:dd:ee:ff' -> 6 raw bytes."""
    return bytes.fromhex(mac.replace(":", ""))
