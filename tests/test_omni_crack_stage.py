"""OmniOrchestrator._stage_crack: must use a cracker's streaming API (Popen
+ proc_holder) when available, not the plain blocking crack() -- otherwise
a running John/aircrack-ng process launched by OMNI/Smart has no handle
anywhere for Stop Attack to terminate. Live-verified 2026-08-27: John ran
320+ seconds after repeated Stop Attack clicks, each of which only ever
re-logged the generic "stop requested" message with nothing behind it for
this specific stage -- had to be killed by hand outside the app."""
from __future__ import annotations

from atwa.omni import OmniOrchestrator, OmniReport


class _StreamingCracker:
    """A cracker exposing both crack() and run_streaming()."""

    def __init__(self):
        self.crack_called = False
        self.run_streaming_calls = []

    def crack(self, hashfile, wordlist):
        self.crack_called = True
        return {}

    def run_streaming(self, hashfile, wordlist, on_line, proc_holder):
        self.run_streaming_calls.append((hashfile, wordlist, proc_holder))
        proc_holder["proc"] = "fake-live-process"
        on_line("cracking...\n")
        return {"hash1": "password123"}


class _BlockingOnlyCracker:
    """A cracker with only the plain crack() -- e.g. a future backend that
    hasn't grown streaming support yet. _stage_crack must still work."""

    def __init__(self):
        self.crack_called = False

    def crack(self, hashfile, wordlist):
        self.crack_called = True
        return {"hash1": "password123"}


def _orch(cracker, tmp_path, proc_holder=None):
    return OmniOrchestrator("mon0", cracker=cracker, capture_dir=tmp_path, proc_holder=proc_holder)


def test_uses_streaming_when_cracker_supports_it(tmp_path):
    cracker = _StreamingCracker()
    proc_holder: dict = {}
    orch = _orch(cracker, tmp_path, proc_holder=proc_holder)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    report.hash_lines.append("WPA*02*deadbeef*aabbccddeeff*112233445566*...")

    orch._stage_crack(report, wordlist="/tmp/wl.txt")

    assert cracker.run_streaming_calls  # streaming path taken
    assert not cracker.crack_called  # blocking path NOT taken
    assert proc_holder["proc"] == "fake-live-process"  # Stop Attack can reach this
    assert report.cracked == {"hash1": "password123"}


def test_falls_back_to_blocking_crack_without_streaming_support(tmp_path):
    cracker = _BlockingOnlyCracker()
    orch = _orch(cracker, tmp_path)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    report.hash_lines.append("WPA*02*deadbeef*aabbccddeeff*112233445566*...")

    orch._stage_crack(report, wordlist="/tmp/wl.txt")

    assert cracker.crack_called
    assert report.cracked == {"hash1": "password123"}


def test_proc_holder_cleared_before_each_new_crack_run(tmp_path):
    cracker = _StreamingCracker()
    proc_holder = {"proc": "stale-from-a-previous-run"}
    orch = _orch(cracker, tmp_path, proc_holder=proc_holder)
    report = OmniReport(target="aa:bb:cc:dd:ee:ff")
    report.hash_lines.append("WPA*02*deadbeef*aabbccddeeff*112233445566*...")

    orch._stage_crack(report, wordlist="/tmp/wl.txt")

    # the fake process from this run, not the stale one from before
    assert proc_holder["proc"] == "fake-live-process"


def test_default_proc_holder_is_not_shared_across_orchestrators(tmp_path):
    # Omitting proc_holder must not silently share mutable state between
    # unrelated OmniOrchestrator instances (the classic mutable-default trap).
    cracker_a, cracker_b = _StreamingCracker(), _StreamingCracker()
    orch_a = OmniOrchestrator("mon0", cracker=cracker_a, capture_dir=tmp_path)
    orch_b = OmniOrchestrator("mon0", cracker=cracker_b, capture_dir=tmp_path)

    assert orch_a._proc_holder is not orch_b._proc_holder
