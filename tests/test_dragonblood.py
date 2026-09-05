"""attacks/dragonblood.py: hunting-and-pecking iteration-count math
(stage 1 of the Dragonblood timing side-channel, CVE-2019-9494).

No reference implementation or real capture exists to check exact byte
output against (see the module's own confidence note) -- these tests
verify internal self-consistency instead: determinism, the MAC-order
symmetry the real spec requires, the value staying in range, and the
iteration-count distribution roughly matching the expected geometric
shape (mean ~2, since each iteration succeeds with ~50% probability)."""

from __future__ import annotations

import statistics
from typing import ClassVar

from scapy.layers.dot11 import Dot11, Dot11Auth, RadioTap

import atwa.attacks.dragonblood as dragonblood_module
from atwa.attacks.dragonblood import (
    MAX_ITERATIONS,
    P256_A,
    P256_B,
    P256_P,
    DragonbloodResult,
    _is_quadratic_residue,
    _kdf_hash_length,
    _measure_sae_commit_rtt,
    hunting_and_pecking_iterations,
    timing_prune_wordlist,
)
from atwa.frames import SAE_AUTH_ALGO

MAC_A = "aa:bb:cc:dd:ee:ff"
MAC_B = "11:22:33:44:55:66"


def test_p256_constants_are_256_bit():
    assert P256_P.bit_length() == 256
    assert 0 < P256_A < P256_P
    assert 0 < P256_B < P256_P


def test_is_quadratic_residue_zero_counts_as_residue():
    assert _is_quadratic_residue(0, P256_P) is True


def test_is_quadratic_residue_known_square_is_residue():
    # 4 = 2^2 is trivially a QR mod any odd prime.
    assert _is_quadratic_residue(4, P256_P) is True


def test_kdf_hash_length_output_size_matches_request():
    out = _kdf_hash_length(b"seed", b"label", 256)
    assert len(out) == 32  # 256 bits = 32 bytes


def test_kdf_hash_length_deterministic():
    a = _kdf_hash_length(b"seed", b"label", 256)
    b = _kdf_hash_length(b"seed", b"label", 256)
    assert a == b


def test_kdf_hash_length_changes_with_key():
    a = _kdf_hash_length(b"seed1", b"label", 256)
    b = _kdf_hash_length(b"seed2", b"label", 256)
    assert a != b


def test_hunting_and_pecking_iterations_is_deterministic():
    a = hunting_and_pecking_iterations("correcthorsebatterystaple", MAC_A, MAC_B)
    b = hunting_and_pecking_iterations("correcthorsebatterystaple", MAC_A, MAC_B)
    assert a == b


def test_hunting_and_pecking_iterations_symmetric_in_mac_order():
    """Both sides of a real SAE handshake must derive the identical
    password element regardless of who's MAC-A and who's MAC-B -- the
    real spec's max(MAC)||min(MAC) construction guarantees this."""
    a = hunting_and_pecking_iterations("correcthorsebatterystaple", MAC_A, MAC_B)
    b = hunting_and_pecking_iterations("correcthorsebatterystaple", MAC_B, MAC_A)
    assert a == b


def test_hunting_and_pecking_iterations_within_bounds():
    for pw in ("short", "a-much-longer-passphrase-here", "1234567890"):
        n = hunting_and_pecking_iterations(pw, MAC_A, MAC_B)
        assert 1 <= n <= MAX_ITERATIONS


def test_hunting_and_pecking_iterations_differs_across_passwords():
    """Weak sanity check: different passwords shouldn't all collide on
    the exact same iteration count (would indicate the password isn't
    actually being mixed into the derivation at all)."""
    counts = {
        hunting_and_pecking_iterations(f"password{i}", MAC_A, MAC_B)
        for i in range(20)
    }
    assert len(counts) > 1


def test_hunting_and_pecking_iterations_differs_across_mac_pairs():
    """Same password, different MAC pair -> different derivation input,
    should not always land on the same count."""
    counts = {
        hunting_and_pecking_iterations("sameword", f"aa:bb:cc:dd:ee:{i:02x}", MAC_B)
        for i in range(20)
    }
    assert len(counts) > 1


def test_hunting_and_pecking_iterations_distribution_matches_geometric_shape():
    """Each iteration succeeds with ~50% probability (QR density), so
    the count should follow a roughly geometric(p=0.5) distribution --
    mean 2. A badly broken QR test (e.g. always/never a residue) would
    make every sample hit 1 or MAX_ITERATIONS instead; this catches
    that class of bug without needing a reference implementation."""
    samples = [
        hunting_and_pecking_iterations(f"pw-{i}", MAC_A, MAC_B)
        for i in range(200)
    ]
    mean = statistics.mean(samples)
    assert 1.5 <= mean <= 3.0
    assert max(samples) < MAX_ITERATIONS  # shouldn't be hitting the cap at all in practice


# --- stage 3: _measure_sae_commit_rtt() / timing_prune_wordlist() --------
# All network I/O mocked -- nothing here touches real hardware.


class FakeThread:
    def __init__(self):
        self.alive = True

    def is_alive(self):
        return self.alive


class FakeSniffer:
    """Mirrors test_handshake.py's FakeSniffer, but does NOT fire prn()
    during start() -- _measure_sae_commit_rtt() starts the sniffer
    BEFORE sending, so a reply can only meaningfully arrive as a
    consequence of the mocked sendp() call, not at construction time."""

    last_instance: ClassVar["FakeSniffer | None"] = None

    def __init__(self, iface, prn, stop_filter, store):
        self.prn = prn
        self.stop_filter = stop_filter
        self.thread = FakeThread()
        FakeSniffer.last_instance = self

    def start(self):
        pass

    def stop(self):
        pass


def _sae_reply(bssid: str, client: str) -> object:
    """A minimal SAE Commit-shaped reply FROM bssid TO client (addr2 is
    the sender -- reversed from craft_sae_commit's own client->bssid
    addressing)."""
    return RadioTap() / Dot11(type=0, subtype=11, addr1=client, addr2=bssid, addr3=bssid) / Dot11Auth(algo=SAE_AUTH_ALGO, seqnum=2, status=0)


def test_measure_sae_commit_rtt_returns_elapsed_time(monkeypatch):
    monkeypatch.setattr(dragonblood_module, "AsyncSniffer", FakeSniffer)
    perf_values = iter([100.0, 100.25])
    monkeypatch.setattr(dragonblood_module.time, "perf_counter", lambda: next(perf_values))
    monkeypatch.setattr(dragonblood_module.time, "sleep", lambda s: None)

    def fake_sendp(pkt, iface, verbose):
        FakeSniffer.last_instance.prn(_sae_reply(MAC_A, MAC_B))

    monkeypatch.setattr(dragonblood_module, "sendp", fake_sendp)

    rtt = _measure_sae_commit_rtt("wlan0mon", MAC_A, MAC_B)
    assert rtt == 0.25


def test_measure_sae_commit_rtt_ignores_reply_from_wrong_bssid(monkeypatch):
    monkeypatch.setattr(dragonblood_module, "AsyncSniffer", FakeSniffer)
    monkeypatch.setattr(dragonblood_module.time, "sleep", lambda s: None)

    def fake_sendp(pkt, iface, verbose):
        FakeSniffer.last_instance.prn(_sae_reply("de:ad:be:ef:00:01", MAC_B))  # not MAC_A

    monkeypatch.setattr(dragonblood_module, "sendp", fake_sendp)

    rtt = _measure_sae_commit_rtt("wlan0mon", MAC_A, MAC_B, timeout=0.05)
    assert rtt is None


def test_measure_sae_commit_rtt_returns_none_on_no_reply(monkeypatch):
    monkeypatch.setattr(dragonblood_module, "AsyncSniffer", FakeSniffer)
    monkeypatch.setattr(dragonblood_module, "sendp", lambda pkt, iface, verbose: None)

    rtt = _measure_sae_commit_rtt("wlan0mon", MAC_A, MAC_B, timeout=0.05)
    assert rtt is None


def test_timing_prune_wordlist_keeps_only_rank_consistent_candidates(monkeypatch):
    """Core pruning logic, exercised against the real (mocked-network,
    real-math) hunting_and_pecking_iterations() -- not a guessed
    fixture. Searches for a rank-consistent and a rank-reversed
    candidate deterministically rather than hardcoding passwords and
    hoping they land the right way."""
    bssid = MAC_A
    mac1, mac2 = "11:11:11:11:11:11", "22:22:22:22:22:22"
    macs_iter = iter([mac1, mac2])
    monkeypatch.setattr(dragonblood_module, "random_locally_administered_mac", lambda: next(macs_iter))
    monkeypatch.setattr(dragonblood_module, "ensure_channel", lambda iface, ch: False)

    real_password = "correcthorsebatterystaple"
    real_iter_1 = hunting_and_pecking_iterations(real_password, mac1, bssid)
    real_iter_2 = hunting_and_pecking_iterations(real_password, mac2, bssid)
    assert real_iter_1 != real_iter_2  # need a real ranking to test consistency against

    rtts = {mac1: real_iter_1 * 0.01, mac2: real_iter_2 * 0.01}
    monkeypatch.setattr(dragonblood_module, "_measure_sae_commit_rtt", lambda iface, b, mac, timeout=2.0: rtts[mac])

    consistent = reversed_ = None
    for i in range(500):
        pw = f"candidate{i}"
        it1 = hunting_and_pecking_iterations(pw, mac1, bssid)
        it2 = hunting_and_pecking_iterations(pw, mac2, bssid)
        if it1 == it2:
            continue
        same_order = (it1 < it2) == (real_iter_1 < real_iter_2)
        if same_order and consistent is None:
            consistent = pw
        if not same_order and reversed_ is None:
            reversed_ = pw
        if consistent and reversed_:
            break
    assert consistent and reversed_

    result = timing_prune_wordlist(
        "wlan0mon", bssid, [reversed_, real_password, consistent],
        num_macs=2, samples_per_mac=1,
    )

    assert isinstance(result, DragonbloodResult)
    assert real_password in result.pruned_wordlist
    assert consistent in result.pruned_wordlist
    assert reversed_ not in result.pruned_wordlist
    assert result.mac_timings == rtts


def test_timing_prune_wordlist_returns_unpruned_when_fewer_than_two_macs_respond(monkeypatch):
    mac1, mac2 = "11:11:11:11:11:11", "22:22:22:22:22:22"
    macs_iter = iter([mac1, mac2])
    monkeypatch.setattr(dragonblood_module, "random_locally_administered_mac", lambda: next(macs_iter))
    monkeypatch.setattr(dragonblood_module, "ensure_channel", lambda iface, ch: False)
    # only mac1 ever gets a reply
    monkeypatch.setattr(dragonblood_module, "_measure_sae_commit_rtt", lambda iface, b, mac, timeout=2.0: 0.02 if mac == mac1 else None)

    wordlist = ["password1", "password2"]
    result = timing_prune_wordlist("wlan0mon", MAC_A, wordlist, num_macs=2, samples_per_mac=1)

    assert result.pruned_wordlist == wordlist
    assert "insufficient" in result.detail.lower()


def test_timing_prune_wordlist_stops_early_when_stop_event_set(monkeypatch):
    import threading

    monkeypatch.setattr(dragonblood_module, "random_locally_administered_mac", lambda: "11:11:11:11:11:11")
    monkeypatch.setattr(dragonblood_module, "ensure_channel", lambda iface, ch: False)
    monkeypatch.setattr(dragonblood_module, "_measure_sae_commit_rtt", lambda *a, **k: 0.02)

    stop_event = threading.Event()
    stop_event.set()
    wordlist = ["password1", "password2"]
    result = timing_prune_wordlist("wlan0mon", MAC_A, wordlist, stop_event=stop_event)

    assert result.pruned_wordlist == wordlist
    assert "stopped" in result.detail.lower()
