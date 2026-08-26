"""Tests for scanner.py — ScanEngineWorker. Filesystem-path helpers are
tested against real tmp_path directories (no hardware needed);
subprocess interaction is mocked."""

import subprocess
import time

import pytest

from atwa import scanner as scanner_mod
from atwa.scan_engine import ScanEngineNotBuilt
from atwa.scanner import (
    ScanEngineWorker,
    clear_scan_outputs,
    latest_scan_csv_path,
    numbered_scan_csv_paths,
    numbered_scan_output_paths,
    scan_live,
)


# --- path helpers (pure filesystem, hermetic) --------------------------------


def test_numbered_scan_csv_paths_finds_numbered_files(tmp_path):
    prefix = tmp_path / "scan"
    (tmp_path / "scan-01.csv").write_text("")
    (tmp_path / "scan-02.csv").write_text("")
    (tmp_path / "scan-01.cap").write_text("")  # not csv, must be excluded
    (tmp_path / "other-01.csv").write_text("")  # different prefix, must be excluded
    found = numbered_scan_csv_paths(str(prefix))
    assert {p.name for p in found} == {"scan-01.csv", "scan-02.csv"}


def test_numbered_scan_csv_paths_empty_when_none_exist(tmp_path):
    prefix = tmp_path / "scan"
    assert numbered_scan_csv_paths(str(prefix)) == []


def test_latest_scan_csv_path_picks_most_recent_mtime(tmp_path):
    prefix = tmp_path / "scan"
    older = tmp_path / "scan-01.csv"
    newer = tmp_path / "scan-02.csv"
    older.write_text("old")
    time.sleep(0.01)
    newer.write_text("new")
    assert latest_scan_csv_path(str(prefix)) == newer


def test_latest_scan_csv_path_none_when_no_files(tmp_path):
    prefix = tmp_path / "scan"
    assert latest_scan_csv_path(str(prefix)) is None


def test_numbered_scan_output_paths_matches_any_extension(tmp_path):
    prefix = tmp_path / "scan"
    (tmp_path / "scan-01.csv").write_text("")
    (tmp_path / "scan-01.cap").write_text("")
    (tmp_path / "scan-01.kismet.netxml").write_text("")
    found = numbered_scan_output_paths(str(prefix))
    assert len(found) == 3


def test_clear_scan_outputs_deletes_prior_numbered_files(tmp_path):
    prefix = tmp_path / "scan"
    (tmp_path / "scan-01.csv").write_text("")
    (tmp_path / "scan-01.cap").write_text("")
    (tmp_path / "unrelated.txt").write_text("keep me")
    clear_scan_outputs(str(prefix))
    remaining = {p.name for p in tmp_path.iterdir()}
    assert remaining == {"unrelated.txt"}


def test_clear_scan_outputs_noop_on_empty_dir(tmp_path):
    prefix = tmp_path / "scan"
    clear_scan_outputs(str(prefix))  # must not raise


# --- ScanEngineWorker: command building (subprocess mocked) ------------------


class FakeProc:
    """Minimal stand-in for subprocess.Popen — enough for ScanEngineWorker
    to drive without ever touching a real process or binary."""

    def __init__(self, cmd, **kwargs):
        self.cmd = cmd
        self.kwargs = kwargs
        self.stdout = iter([])  # _read_stdout iterates this; empty is fine
        self._poll = None

    def poll(self):
        return self._poll

    def send_signal(self, sig):
        pass

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self._poll = -9


@pytest.fixture
def scanner_with_fake_binary(monkeypatch, tmp_path):
    fake_bin = tmp_path / "scan-engine"
    fake_bin.write_text("")
    monkeypatch.setattr(scanner_mod, "HOPSCAN_BIN", fake_bin)
    monkeypatch.setattr(subprocess, "Popen", FakeProc)
    s = ScanEngineWorker()
    yield s
    s.shutdown()


def test_start_scan_builds_band_and_iface_args(scanner_with_fake_binary, tmp_path):
    s = scanner_with_fake_binary
    prefix = str(tmp_path / "scan")
    ok, err = s.start_scan("wlan0", "5GHz", prefix)
    assert ok, err
    assert s._proc.cmd[-1] == "wlan0"
    assert "--band" in s._proc.cmd
    assert s._proc.cmd[s._proc.cmd.index("--band") + 1] == "a"


def test_start_scan_both_band_maps_to_abg(scanner_with_fake_binary, tmp_path):
    s = scanner_with_fake_binary
    ok, _ = s.start_scan("wlan0", "Both", str(tmp_path / "scan"))
    assert ok
    assert s._proc.cmd[s._proc.cmd.index("--band") + 1] == "abg"


def test_start_scan_unknown_band_defaults_to_abg(scanner_with_fake_binary, tmp_path):
    s = scanner_with_fake_binary
    ok, _ = s.start_scan("wlan0", "not-a-real-band", str(tmp_path / "scan"))
    assert ok
    assert s._proc.cmd[s._proc.cmd.index("--band") + 1] == "abg"


def test_start_lock_builds_channel_and_bssid_args(scanner_with_fake_binary, tmp_path):
    s = scanner_with_fake_binary
    ok, _ = s.start_lock("wlan0", 6, "AA:BB:CC:DD:EE:FF", str(tmp_path / "scan"))
    assert ok
    cmd = s._proc.cmd
    assert cmd[cmd.index("-c") + 1] == "6"
    assert cmd[cmd.index("--bssid") + 1] == "AA:BB:CC:DD:EE:FF"
    assert cmd[-1] == "wlan0"


def test_start_lock_prefix_gets_lock_suffix(scanner_with_fake_binary, tmp_path):
    s = scanner_with_fake_binary
    s.start_lock("wlan0", 6, "AA:BB:CC:DD:EE:FF", str(tmp_path / "scan"))
    assert s._prefix.endswith("_lock")


def test_popen_called_with_closed_stdin(scanner_with_fake_binary, tmp_path):
    """Regression test for the stdin-inheritance hang bug found during
    code review — same fix required here as in scan_engine.py's
    scan()."""
    s = scanner_with_fake_binary
    s.start_scan("wlan0", "Both", str(tmp_path / "scan"))
    assert s._proc.kwargs.get("stdin") == subprocess.DEVNULL


def test_raises_scan_engine_not_built_when_binary_missing(monkeypatch, tmp_path):
    missing_bin = tmp_path / "does-not-exist"
    monkeypatch.setattr(scanner_mod, "HOPSCAN_BIN", missing_bin)
    s = ScanEngineWorker()
    with pytest.raises(ScanEngineNotBuilt):
        s.start_scan("wlan0", "Both", str(tmp_path / "scan"))
    s.shutdown()


# --- pause/resume/stop state -------------------------------------------------


def test_pause_sends_sigstop_and_sets_flag(scanner_with_fake_binary, tmp_path):
    s = scanner_with_fake_binary
    s.start_scan("wlan0", "Both", str(tmp_path / "scan"))
    assert not s._paused.is_set()
    s.pause()
    assert s._paused.is_set()


def test_resume_clears_paused_flag(scanner_with_fake_binary, tmp_path):
    s = scanner_with_fake_binary
    s.start_scan("wlan0", "Both", str(tmp_path / "scan"))
    s.pause()
    s.resume()
    assert not s._paused.is_set()


def test_pause_is_noop_without_a_running_process():
    s = ScanEngineWorker()
    s.pause()  # must not raise
    assert not s._paused.is_set()
    s.shutdown()


def test_get_latest_returns_a_copy_not_the_live_object(scanner_with_fake_binary):
    s = scanner_with_fake_binary
    first = s.get_latest()
    first.networks.append("mutated-by-caller")
    assert s.get_latest().networks == []


# --- scan_live(): tempdir default, cleanup -----------------------------------


def test_scan_live_uses_a_fresh_tempdir_by_default(monkeypatch, tmp_path):
    """Regression test for the fixed-/tmp-path collision bug found during
    code review — default prefix must not be a shared fixed path."""
    fake_bin = tmp_path / "scan-engine"
    fake_bin.write_text("")
    monkeypatch.setattr(scanner_mod, "HOPSCAN_BIN", fake_bin)
    monkeypatch.setattr(subprocess, "Popen", FakeProc)
    monkeypatch.setattr(scanner_mod.time, "sleep", lambda _s: None)

    seen_prefixes = []
    orig_start_scan = ScanEngineWorker.start_scan

    def spy_start_scan(self, iface, band, prefix):
        seen_prefixes.append(prefix)
        return orig_start_scan(self, iface, band, prefix)

    monkeypatch.setattr(ScanEngineWorker, "start_scan", spy_start_scan)

    scan_live("wlan0", duration=0.01)
    scan_live("wlan0", duration=0.01)
    assert seen_prefixes[0] != seen_prefixes[1]
    assert "atwa_scan_" in seen_prefixes[0]


def test_scan_live_cleans_up_its_tempdir(monkeypatch, tmp_path):
    fake_bin = tmp_path / "scan-engine"
    fake_bin.write_text("")
    monkeypatch.setattr(scanner_mod, "HOPSCAN_BIN", fake_bin)
    monkeypatch.setattr(subprocess, "Popen", FakeProc)
    monkeypatch.setattr(scanner_mod.time, "sleep", lambda _s: None)

    created_dirs = []
    orig_mkdtemp = scanner_mod.tempfile.mkdtemp

    def spy_mkdtemp(*a, **kw):
        d = orig_mkdtemp(*a, **kw)
        created_dirs.append(d)
        return d

    monkeypatch.setattr(scanner_mod.tempfile, "mkdtemp", spy_mkdtemp)

    scan_live("wlan0", duration=0.01)
    assert created_dirs
    assert not scanner_mod.Path(created_dirs[0]).exists()
