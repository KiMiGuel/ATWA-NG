"""Tests for cli.py / cli_commands/ — argument parsing for all subcommands,
and the subprocess-handling logic (_run_bounded, the SIGINT-and-collect
helper in wps-recon) with subprocess mocked out. No hardware, no vendored
binaries required to run this file. `injection-test` is native (see
test_injection_test.py) and no longer touches a vendored binary."""

import subprocess

import pytest

from atwa.cli import build_parser
from atwa.cli_commands import CAPCRACK_BIN, WPSRECON_BIN, _run_bounded
from atwa.cli_commands import attacks as attacks_cmds
from atwa.cli_commands import crack as crack_cmds
from atwa.cli_commands import misc as misc_cmds
from atwa.cli_commands import scan as scan_cmds


# --- argument parsing: every subcommand parses its documented shape --------
# All handler functions are atwa's own.


@pytest.mark.parametrize("argv,expected_func", [
    (["scan", "wlan0"], scan_cmds._cmd_scan),
    (["injection-test", "wlan0"], scan_cmds._cmd_injection_test),
    (["wps-recon", "wlan0"], scan_cmds._cmd_wps_recon),
    (["crack-cap", "cap.cap", "words.txt"], crack_cmds._cmd_crack_cap),
    (["deauth", "wlan0", "AA:BB:CC:DD:EE:FF"], attacks_cmds._cmd_deauth),
    (["pmkid", "wlan0", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"], attacks_cmds._cmd_pmkid),
    (["handshake", "wlan0", "AA:BB:CC:DD:EE:FF"], attacks_cmds._cmd_handshake),
    (["omni", "wlan0", "AA:BB:CC:DD:EE:FF"], attacks_cmds._cmd_omni),
    (["smart", "wlan0", "AA:BB:CC:DD:EE:FF"], attacks_cmds._cmd_smart),
    (["wep", "wlan0", "AA:BB:CC:DD:EE:FF", "MySSID"], attacks_cmds._cmd_wep),
    (["wps-pixie", "wlan0", "AA:BB:CC:DD:EE:FF", "MySSID"], attacks_cmds._cmd_wps_pixie),
    (["wps-oneshot", "wlan0", "AA:BB:CC:DD:EE:FF"], attacks_cmds._cmd_wps_oneshot),
    (["gui"], misc_cmds._cmd_gui),
    (["crack", "hash.22000", "words.txt"], crack_cmds._cmd_crack),
    (["eviltwin", "wlan0", "wlan1", "AA:BB:CC:DD:EE:FF", "MySSID", "6"], attacks_cmds._cmd_eviltwin),
])
def test_subcommand_parses_and_wires_correct_handler(argv, expected_func):
    parser = build_parser()
    args = parser.parse_args(argv)
    assert args.func is expected_func


def test_no_command_is_required_and_errors_cleanly():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_scan_default_band_is_both():
    args = build_parser().parse_args(["scan", "wlan0"])
    assert args.band == "Both"


def test_scan_rejects_invalid_band():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan", "wlan0", "--band", "60GHz"])


def test_injection_test_default_count_is_30():
    args = build_parser().parse_args(["injection-test", "wlan0"])
    assert args.count == 30


def test_injection_test_bssid_optional_defaults_none():
    args = build_parser().parse_args(["injection-test", "wlan0"])
    assert args.bssid is None


def test_crack_aircrack_optional_bssid_defaults_none():
    args = build_parser().parse_args(["crack-cap", "cap.cap", "words.txt"])
    assert args.bssid is None


def test_eviltwin_channel_is_parsed_as_int():
    args = build_parser().parse_args(
        ["eviltwin", "wlan0", "wlan1", "AA:BB:CC:DD:EE:FF", "SSID", "11"]
    )
    assert args.channel == 11
    assert isinstance(args.channel, int)


# --- _run_bounded: the timeout-hang fix from code review --------------------
# Still used by crack-cap (a permitted cap/pcap-format wrapper).


def test_run_bounded_returns_stdout_on_normal_completion(monkeypatch):
    def fake_run(cmd, **kwargs):
        assert kwargs.get("stdin") == subprocess.DEVNULL
        assert kwargs.get("timeout") == 5
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc, out, err = _run_bounded(["echo", "hi"], timeout=5)
    assert rc == 0
    assert out == "ok"


def test_run_bounded_reports_clean_timeout_instead_of_raising(monkeypatch):
    """Regression test for the real hang found live during code review:
    a vendored engine waiting on a beacon that never arrives used to
    hang subprocess.run() forever (no timeout at all originally). Must
    now return a clean error instead of propagating TimeoutExpired."""
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc, out, err = _run_bounded(["aircrack-ng", "-w", "words.txt", "cap.cap"], timeout=10)
    assert rc == 1
    assert "timed out after 10" in err
    assert "beacon" in err


def test_run_bounded_nonzero_exit_is_reported(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="boom")

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc, out, err = _run_bounded(["cmd"], timeout=5)
    assert rc == 1
    assert err == "boom"


# --- _cmd_crack_cap / _cmd_wps_recon: missing-binary guard -------


def test_crack_aircrack_reports_missing_binary_cleanly(monkeypatch, tmp_path, capsys):
    missing = tmp_path / "aircrack-ng"
    monkeypatch.setattr("atwa.cli_commands.crack.CAPCRACK_BIN", missing)
    args = build_parser().parse_args(["crack-cap", "cap.cap", "words.txt"])
    rc = crack_cmds._cmd_crack_cap(args)
    assert rc == 1
    assert "not built" in capsys.readouterr().err


def test_wash_reports_missing_binary_cleanly(monkeypatch, tmp_path, capsys):
    missing = tmp_path / "wash"
    monkeypatch.setattr("atwa.cli_commands.scan.WPSRECON_BIN", missing)
    args = build_parser().parse_args(["wps-recon", "wlan0"])
    rc = scan_cmds._cmd_wps_recon(args)
    assert rc == 1
    assert "not built" in capsys.readouterr().err


# --- wash: SIGINT-and-collect pattern (Popen mocked) ------


class FakeLongRunningProc:
    """Stands in for a process like `wash` that runs until signaled —
    never exits on its own, only on send_signal + communicate."""

    def __init__(self, cmd, **kwargs):
        self.cmd = cmd
        self.kwargs = kwargs
        self.signaled_with = None

    def send_signal(self, sig):
        self.signaled_with = sig

    def communicate(self, timeout=None):
        return "some output\n", None


def test_wash_sends_sigint_and_collects_output(monkeypatch, tmp_path):
    fake_bin = tmp_path / "wash"
    fake_bin.write_text("")
    monkeypatch.setattr("atwa.cli_commands.scan.WPSRECON_BIN", fake_bin)
    monkeypatch.setattr(subprocess, "Popen", FakeLongRunningProc)
    monkeypatch.setattr(scan_cmds.time, "sleep", lambda _s: None)

    args = build_parser().parse_args(["wps-recon", "wlan0", "--duration", "1"])
    rc = scan_cmds._cmd_wps_recon(args)
    assert rc == 0


def test_wash_closes_stdin_on_popen(monkeypatch, tmp_path):
    """Regression test: the stdin-inheritance hang class of bug found
    live for the (now-removed) deauth-inject path must not recur here."""
    fake_bin = tmp_path / "wash"
    fake_bin.write_text("")
    monkeypatch.setattr("atwa.cli_commands.scan.WPSRECON_BIN", fake_bin)
    captured = {}

    def fake_popen(cmd, **kwargs):
        captured.update(kwargs)
        return FakeLongRunningProc(cmd, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(scan_cmds.time, "sleep", lambda _s: None)

    args = build_parser().parse_args(["wps-recon", "wlan0", "--duration", "1"])
    scan_cmds._cmd_wps_recon(args)
    assert captured.get("stdin") == subprocess.DEVNULL
