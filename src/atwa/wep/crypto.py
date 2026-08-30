"""WEP crypto primitives: RC4 and the CRC-32 ICV.

RC4 via pycryptodome's C-accelerated `Crypto.Cipher.ARC4` (2026-08-30,
`pycryptodome` ships the `Crypto` namespace — `Cryptodome` is the separate
`pycryptodomex` package) rather than the
hand-rolled pure-Python KSA/PRGA this used to have: `cryptography` (already
a project dependency) dropped RC4 entirely as insecure-by-design, so it can't
cover this path, and WEP cracking (PTW voting tries many keystream
candidates) is CPU-bound enough for the C backend to matter.
`rc4_keystream`/`rc4_crypt` keep their original signatures so callers
(`ptw.py`, and this module's own encrypt/decrypt helpers below) needed no
changes.

WEP per-packet key = IV (3 bytes) || root key (5 or 13 bytes). The ICV is
an unkeyed CRC-32 over the plaintext, little-endian, appended before RC4
encryption — see research/wep_attacks_dim06.md §2 (verified against a
real GitHub WEP implementation) for the exact layout this mirrors.
"""

from __future__ import annotations

import zlib

from Crypto.Cipher import ARC4


def rc4_keystream(key: bytes, length: int) -> bytes:
    """RC4 keystream of `length` bytes for `key`."""
    return ARC4.new(key).encrypt(bytes(length))


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """RC4 encrypt/decrypt (XOR with keystream; symmetric)."""
    return ARC4.new(key).encrypt(data)


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
