"""WPS crypto primitives: DH group 5, the WSC key-derivation chain, and the
E/R-Hash proof-of-PIN-possession formulas.

Sourced from wpa_supplicant's wps_common.c / wps_defs.h (the reference
implementation) rather than reconstructed from memory — see STATUS.md
"Research notes" for exact provenance of each formula. Cross-checked
against Viehböck's "Brute forcing Wi-Fi Protected Setup" (2011) for the
E-Hash/R-Hash byte order and PIN-half split.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# RFC 3526 §2, "1536 bit MODP Group" (Group 5) — quoted verbatim from the
# RFC's own spaced hex formatting, whitespace stripped below, to avoid
# transcription errors from hand-concatenating hex digits.
_DH_GROUP5_PRIME_TEXT = """
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF
"""
DH_GROUP5_PRIME = int("".join(_DH_GROUP5_PRIME_TEXT.split()), 16)
assert DH_GROUP5_PRIME.bit_length() == 1536, "DH group 5 prime must be exactly 1536 bits"
DH_GROUP5_GENERATOR = 2
_DH_KEY_BYTES = 192  # 1536 bits


@dataclass
class DHKeypair:
    """A Diffie-Hellman private/public keypair for WPS's group 5."""

    private: int
    public_bytes: bytes  # big-endian, fixed 192 bytes

    @classmethod
    def generate(cls) -> "DHKeypair":
        private = int.from_bytes(os.urandom(192), "big") % (DH_GROUP5_PRIME - 2) + 1
        public = pow(DH_GROUP5_GENERATOR, private, DH_GROUP5_PRIME)
        return cls(private=private, public_bytes=public.to_bytes(_DH_KEY_BYTES, "big"))

    def shared_secret(self, peer_public_bytes: bytes) -> bytes:
        """Compute g^(ab) mod p with a peer's public key, as fixed-width bytes."""
        peer_public = int.from_bytes(peer_public_bytes, "big")
        shared = pow(peer_public, self.private, DH_GROUP5_PRIME)
        return shared.to_bytes(_DH_KEY_BYTES, "big")


def dhkey(shared_secret: bytes) -> bytes:
    """DHKey = SHA-256(raw DH shared secret)."""
    return hashlib.sha256(shared_secret).digest()


def kdk(dh_key: bytes, n1: bytes, enrollee_mac: bytes, n2: bytes) -> bytes:
    """KDK = HMAC-SHA256(DHKey, N1 || EnrolleeMAC || N2)."""
    return hmac.new(dh_key, n1 + enrollee_mac + n2, hashlib.sha256).digest()

WPS_KDF_LABEL = b"Wi-Fi Easy and Secure Key Derivation"


def wps_kdf(key: bytes, output_bits: int = 640) -> bytes:
    """WSC's KDF: iterated HMAC-SHA256(key, i(BE32) || label || output_bits(BE32))."""
    iterations = (output_bits + 255) // 256
    out = b""
    for i in range(1, iterations + 1):
        block = i.to_bytes(4, "big") + WPS_KDF_LABEL + output_bits.to_bytes(4, "big")
        out += hmac.new(key, block, hashlib.sha256).digest()
    return out[: output_bits // 8]


@dataclass
class DerivedKeys:
    """AuthKey/KeyWrapKey/EMSK split from the 640-bit KDF output."""

    auth_key: bytes  # 32 bytes
    key_wrap_key: bytes  # 16 bytes
    emsk: bytes  # 32 bytes

    @classmethod
    def derive(cls, dh_key: bytes, n1: bytes, enrollee_mac: bytes, n2: bytes) -> "DerivedKeys":
        keymat = wps_kdf(kdk(dh_key, n1, enrollee_mac, n2))
        return cls(auth_key=keymat[0:32], key_wrap_key=keymat[32:48], emsk=keymat[48:80])


def pin_checksum(digits7: int) -> int:
    """Compute the 8th (checksum) digit for a 7-digit PIN core."""
    accum = 0
    while digits7:
        accum += 3 * (digits7 % 10)
        digits7 //= 10
        accum += digits7 % 10
        digits7 //= 10
    return (10 - (accum % 10)) % 10


def split_pin(pin8: str) -> tuple[bytes, bytes]:
    """Split an 8-digit PIN string into (first-half ASCII, second-half ASCII)."""
    if len(pin8) != 8 or not pin8.isdigit():
        raise ValueError("PIN must be 8 digits")
    return pin8[:4].encode(), pin8[4:].encode()


def psk_half(auth_key: bytes, half_ascii: bytes) -> bytes:
    """PSK1/PSK2 = first 128 bits of HMAC-SHA256(AuthKey, half_ascii)."""
    return hmac.new(auth_key, half_ascii, hashlib.sha256).digest()[:16]


def proof_hash(auth_key: bytes, snonce: bytes, psk: bytes, pke: bytes, pkr: bytes) -> bytes:
    """E-Hash/R-Hash = HMAC-SHA256(AuthKey, S-nonce || PSK || PKE || PKR)."""
    return hmac.new(auth_key, snonce + psk + pke + pkr, hashlib.sha256).digest()


def authenticator(auth_key: bytes, prev_msg: bytes, curr_msg: bytes) -> bytes:
    """Authenticator = first 64 bits of HMAC-SHA256(AuthKey, prev_msg || curr_msg)."""
    return hmac.new(auth_key, prev_msg + curr_msg, hashlib.sha256).digest()[:8]


def key_wrap_encrypt(key_wrap_key: bytes, plaintext: bytes) -> bytes:
    """AES-128-CBC encrypt with PKCS#7 padding; random IV prepended (WSC layout: IV || ciphertext)."""
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len]) * pad_len
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_wrap_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded) + encryptor.finalize()


def key_wrap_decrypt(key_wrap_key: bytes, iv_and_ciphertext: bytes) -> bytes:
    """Reverse of key_wrap_encrypt: split IV, decrypt, strip PKCS#7 padding."""
    iv, ciphertext = iv_and_ciphertext[:16], iv_and_ciphertext[16:]
    cipher = Cipher(algorithms.AES(key_wrap_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    if not (1 <= pad_len <= 16):
        raise ValueError("bad PKCS#7 padding in encrypted settings")
    return padded[:-pad_len]
