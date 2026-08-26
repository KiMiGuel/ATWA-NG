"""Live scanning engine — ported directly from n2-ng v1's AirodumpWorker
(main.py), not reimplemented from scratch. Same architecture: a
background thread drives airodump-ng and polls its CSV output every
200ms into a shared, lock-protected buffer that callers read from
independently (v1's "Loop A / Loop B" split, so display/consumption
never blocks on the poll). The only real changes from v1: points at our
own vendored/locally-compiled airodump-ng binary instead of the PATH
lookup, and returns the typed dataclasses from scan_airodump.py instead
of raw dicts.
"""

from __future__ import annotations

import copy
import queue
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections import deque
from pathlib import Path

from .scan_airodump import (
    AIRODUMP_NG_BIN,
    AirodumpNotBuilt,
    Client,
    Network,
    ScanResult,
    parse_airodump_csv,
)

BAND_ARGS = {"2.4GHz": "bg", "5GHz": "a", "Both": "abg"}


def numbered_airodump_csv_paths(prefix: str) -> list[Path]:
    prefix_path = Path(prefix)
    stem = re.escape(prefix_path.name)
    pattern = re.compile(rf"^{stem}-\d+\.csv$")
    return [p for p in prefix_path.parent.glob(f"{prefix_path.name}-*.csv") if pattern.match(p.name)]


def latest_airodump_csv_path(prefix: str) -> Path | None:
    matches = numbered_airodump_csv_paths(prefix)
    if not matches:
        return None
    return max(matches, key=lambda p: (p.stat().st_mtime, p.name))


def numbered_airodump_output_paths(prefix: str) -> list[Path]:
    prefix_path = Path(prefix)
    stem = re.escape(prefix_path.name)
    pattern = re.compile(rf"^{stem}-\d+\..+$")
    return [p for p in prefix_path.parent.glob(f"{prefix_path.name}-*.*") if pattern.match(p.name)]


def clear_airodump_outputs(prefix: str) -> None:
    """airodump-ng bumps the -NN suffix instead of overwriting; clear
    stale outputs so a fresh run starts at -01 and pollers don't pick up
    a dead file from a previous session."""
    for path in numbered_airodump_output_paths(prefix):
        try:
            path.unlink()
        except OSError:
            pass


class AirodumpScanner(threading.Thread):
    """Drives our vendored airodump-ng and parses its CSV output live.
    Ported from v1's AirodumpWorker — same threading/pause/lock-capture
    design, same 200ms poll loop."""

    def __init__(self, event_queue: queue.Queue | None = None,
                 write_interval: int = 1):
        super().__init__(daemon=True)
        self.queue = event_queue or queue.Queue()
        self.write_interval = write_interval
        self._proc: subprocess.Popen | None = None
        self._prefix = ""
        self._running = threading.Event()
        self._shutdown = threading.Event()
        self._thread_started = False
        self._paused = threading.Event()
        self._data_lock = threading.Lock()
        self._latest = ScanResult()
        self._raw_lock = threading.Lock()
        self._raw_lines: deque[str] = deque(maxlen=1000)
        self._stdout_thread: threading.Thread | None = None

    def _build_base_cmd(self, prefix: str) -> list[str]:
        if not AIRODUMP_NG_BIN.exists():
            raise AirodumpNotBuilt(f"{AIRODUMP_NG_BIN} not built — see N2-NGv2/STATUS.md")
        return [
            str(AIRODUMP_NG_BIN),
            "--write-interval", str(self.write_interval),
            "-w", prefix,
            "--output-format", "csv,pcap",
        ]

    def _ensure_poll_thread(self):
        if not self._thread_started:
            self._thread_started = True
            self.start()

    def _stop_process(self):
        if not self._proc:
            return
        proc = self._proc
        self._proc = None
        try:
            if self._paused.is_set():
                proc.send_signal(signal.SIGCONT)
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        except Exception:
            try:
                proc.kill()
                proc.wait()
            except Exception:
                pass
        self._paused.clear()

    def _launch(self, cmd: list[str]) -> tuple[bool, str | None]:
        self._stop_process()
        clear_airodump_outputs(self._prefix)
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
            )
        except OSError as e:
            self._proc = None
            self._running.clear()
            return False, str(e)
        with self._raw_lock:
            self._raw_lines.clear()
        self._stdout_thread = threading.Thread(target=self._read_stdout, args=(self._proc,), daemon=True)
        self._stdout_thread.start()
        self._running.set()
        self._paused.clear()
        self._ensure_poll_thread()
        return True, None

    def _read_stdout(self, proc):
        if not proc.stdout:
            return
        try:
            for line in proc.stdout:
                with self._raw_lock:
                    self._raw_lines.append(line.rstrip("\n"))
        except Exception as e:
            self.queue.put(("error", str(e)))

    def start_scan(self, mon_iface: str, band: str, prefix: str) -> tuple[bool, str | None]:
        """band: '2.4GHz' | '5GHz' | 'Both'."""
        self._prefix = prefix
        cmd = self._build_base_cmd(prefix)
        cmd.extend(["--band", BAND_ARGS.get(band, "abg"), mon_iface])
        return self._launch(cmd)

    def start_lock(self, mon_iface: str, channel: int, bssid: str, prefix: str) -> tuple[bool, str | None]:
        lock_prefix = prefix if prefix.endswith("_lock") else f"{prefix}_lock"
        self._prefix = lock_prefix
        cmd = self._build_base_cmd(lock_prefix)
        cmd.extend(["-c", str(channel), "--bssid", bssid, mon_iface])
        return self._launch(cmd)

    def is_running(self) -> bool:
        return bool(self._proc and self._proc.poll() is None)

    def pause(self):
        if self._proc and not self._paused.is_set():
            self._proc.send_signal(signal.SIGSTOP)
            self._paused.set()

    def resume(self):
        if self._proc and self._paused.is_set():
            self._proc.send_signal(signal.SIGCONT)
            self._paused.clear()

    def stop(self):
        self._running.clear()
        self._stop_process()

    def shutdown(self):
        self.stop()
        self._shutdown.set()

    def run(self):
        """Loop A: poll the CSV file every 200ms and parse it into the
        shared buffer. Channel hopping/capture is airodump-ng's own job;
        this thread only reads its output."""
        last_mtime = 0.0
        last_csv_path = None
        poll_interval = 0.2
        while not self._shutdown.is_set():
            csv_path = latest_airodump_csv_path(self._prefix)
            if self._running.is_set() and not self._paused.is_set() and csv_path and csv_path.exists():
                try:
                    mtime = csv_path.stat().st_mtime
                    if csv_path != last_csv_path or mtime != last_mtime:
                        last_csv_path = csv_path
                        last_mtime = mtime
                        text = csv_path.read_text(encoding="utf-8", errors="replace")
                        with self._data_lock:
                            self._latest = parse_airodump_csv(text)
                except Exception as e:
                    self.queue.put(("error", str(e)))
            time.sleep(poll_interval)

    def get_latest(self) -> ScanResult:
        with self._data_lock:
            return copy.deepcopy(self._latest)

    def get_raw_lines(self) -> list[str]:
        with self._raw_lock:
            lines = list(self._raw_lines)
            self._raw_lines.clear()
        return lines


def scan_live(iface: str, duration: float = 10.0, band: str = "Both",
              prefix: str | None = None) -> ScanResult:
    """Convenience wrapper: run a scan for `duration` seconds using the
    real background-thread engine (not the one-shot scan() in
    scan_airodump.py), return whatever was captured.

    `prefix=None` (the default) uses a fresh temp directory per call —
    the original default was a fixed "/tmp/n2ngv2_scan" path, which
    would collide if two scans ever ran concurrently and never cleaned
    up its output files afterward. Pass an explicit prefix if you want a
    stable, inspectable location instead."""
    tmpdir = None
    if prefix is None:
        tmpdir = tempfile.mkdtemp(prefix="n2ngv2_scan_")
        prefix = str(Path(tmpdir) / "scan")

    scanner = AirodumpScanner()
    ok, err = scanner.start_scan(iface, band, prefix)
    if not ok:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(f"failed to start airodump-ng: {err}")
    try:
        time.sleep(duration)
        return scanner.get_latest()
    finally:
        scanner.shutdown()
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
