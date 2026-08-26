"""WEP crypto primitives: RC4 (KSA/PRGA) and the CRC-32 ICV.

Native RC4 rather than a pip dependency (`arc4` etc.) — it's ~15 lines and
this project prefers native implementations over wrapping/depending on
external packages where the algorithm itself is this small.

WEP per-packet key = IV (3 bytes) || root key (5 or 13 bytes). The ICV is
an unkeyed CRC-32 over the plaintext, little-endian, appended before RC4
encryption — see research/wep_attacks_dim06.md §2 (verified against a
real GitHub WEP implementation) for the exact layout this mirrors.
"""

from __future__ import annotations

import zlib


def rc4_ksa(key: bytes) -> list[int]:
    """RC4 key-scheduling algorithm: build the initial 256-byte S-box."""
    s = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def rc4_prga(s: list[int], length: int) -> bytes:
    """RC4 pseudo-random generation algorithm: emit `length` keystream bytes."""
    s = s.copy()
    i = j = 0
    out = bytearray(length)
    for n in range(length):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out[n] = s[(s[i] + s[j]) % 256]
    return bytes(out)


def rc4_keystream(key: bytes, length: int) -> bytes:
    """RC4 keystream of `length` bytes for `key` (KSA then PRGA)."""
    return rc4_prga(rc4_ksa(key), length)


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """RC4 encrypt/decrypt (XOR with keystream; symmetric)."""
    ks = rc4_keystream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def icv(plaintext: bytes) -> bytes:
    """WEP ICV: CRC-32 over plaintext, little-endian, 4 bytes."""
    return zlib.crc32(plaintext).to_bytes(4, "little")


def per_packet_key(iv: bytes, root_key: bytes) -> bytes:
    """WEP per-packet RC4 key = IV (3 bytes) || root key (5 or 13 bytes)."""
    if len(iv) != 3:
        raise ValueError("WEP IV must be 3 bytes")
    if len(root_key) not in (5, 13):
        raise ValueError("WEP root key must be 5 bytes (WEP-40) or 13 bytes (WEP-104)")
    return iv + root_key


def wep_encrypt(iv: bytes, root_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext under WEP: RC4(IV||key, plaintext || ICV)."""
    return rc4_crypt(per_packet_key(iv, root_key), plaintext + icv(plaintext))


def wep_decrypt(iv: bytes, root_key: bytes, ciphertext: bytes) -> tuple[bytes, bool]:
    """Decrypt a WEP frame body; returns (plaintext, icv_valid)."""
    decrypted = rc4_crypt(per_packet_key(iv, root_key), ciphertext)
    plaintext, received_icv = decrypted[:-4], decrypted[-4:]
    return plaintext, received_icv == icv(plaintext)


def recover_keystream(ciphertext: bytes, known_plaintext: bytes) -> bytes:
    """XOR a known-plaintext prefix against ciphertext to recover keystream bytes.

    This is the core of every WEP traffic-injection attack: ARP's first N
    plaintext bytes are predictable (fixed LLC/SNAP header etc.), so this
    recovers the per-IV RC4 keystream without knowing the WEP key at all.
    """
    n = len(known_plaintext)
    return bytes(c ^ p for c, p in zip(ciphertext[:n], known_plaintext))
