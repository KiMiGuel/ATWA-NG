"""aircrack-ng cracker backend — works directly on a .cap/.pcap file with
a known BSSID (`-b`), no 22000 conversion needed first. A second backend
alongside John (still no hashcat, per the project's existing decision) —
the user specifically wants aircrack-ng available since it's simpler to
point at a raw capture than John's convert-to-22000-first flow.
"""

from __future__ import annotations

import re
import shutil
import subprocess

from .base import Cracker

_KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")
# aircrack-ng exits 0 even on "wordlist exhausted, no match" — not a
# useful signal on its own. "0 potential targets" is what it prints when
# the given BSSID has no usable handshake in the capture at all (real,
# directly-observed output format, confirmed live last session) — that's
# a real failure, not "tried and failed," and was previously
# indistinguishable from a genuine exhausted-wordlist result.
_NO_TARGETS_RE = re.compile(r"^0 potential targets", re.MULTILINE)
# aircrack-ng's live status is a redrawn TUI screen, not plain log lines —
# it writes ANSI cursor-position/clear-screen codes (e.g. "\x1b[2J\x1b[3;0H")
# around each update. Strip those before showing output in a GUI text box,
# or it reads as garbled escape-code soup instead of readable progress.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _clean(line: str) -> str:
    return _ANSI_RE.sub("", line).strip()


class AircrackUnavailableError(RuntimeError):
    """Raised when the aircrack-ng binary is not found."""


class AircrackNoHandshakeError(RuntimeError):
    """Raised when aircrack-ng finds 0 usable handshakes for the given
    BSSID — a real failure (wrong BSSID, capture has no full handshake
    for this target), not "wordlist didn't have it"."""


class AirCracker(Cracker):
    """Crack a WPA handshake capture via aircrack-ng -w wordlist -b bssid capfile.

    `-b bssid` is required, not optional: without it, aircrack-ng prompts
    interactively for which network (by index) to attack when a capture
    holds more than one, and a subprocess with no TTY would just hang
    forever on that prompt. Since this project already knows the
    target's BSSID by the time a crack is triggered, this is never a
    real limitation here.
    """

    def __init__(self, bssid: str, binary: str = "aircrack-ng"):
        self.bssid = bssid
        self.binary = binary
        if shutil.which(binary) is None:
            raise AircrackUnavailableError("aircrack-ng not found in PATH; install aircrack-ng")

    def _cmd(self, capfile: str, wordlist: str) -> list[str]:
        return [self.binary, "-w", wordlist, "-b", self.bssid, capfile]

    def crack(self, hashfile: str, wordlist: str) -> dict[str, str]:
        """hashfile is a .cap/.pcap/.pcapng path here, not a 22000 hash file."""
        proc = subprocess.run(self._cmd(hashfile, wordlist), capture_output=True, text=True, check=False)
        cleaned = _clean(proc.stdout)
        if _NO_TARGETS_RE.search(cleaned):
            raise AircrackNoHandshakeError(
                f"aircrack-ng found 0 usable handshakes for {self.bssid} in {hashfile} — "
                f"wrong BSSID, or no full handshake captured for this target."
            )
        match = _KEY_FOUND_RE.search(cleaned)
        return {self.bssid: match.group(1)} if match else {}

    def run_streaming(self, capfile: str, wordlist: str, on_line, proc_holder: dict) -> dict[str, str]:
        """Streaming counterpart to crack(), same shape as JohnCracker's,
        for the crack dialog's live output pane + real Stop button."""
        proc = subprocess.Popen(
            self._cmd(capfile, wordlist), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        proc_holder["proc"] = proc
        if proc.stdout is None:
            return {}
        found: dict[str, str] = {}
        no_targets = False
        for raw_line in proc.stdout:
            line = _clean(raw_line)
            if not line:
                continue
            on_line(line + "\n")
            if _NO_TARGETS_RE.match(line):
                no_targets = True
            match = _KEY_FOUND_RE.search(line)
            if match:
                found[self.bssid] = match.group(1)
        proc.wait()
        if no_targets and not found:
            raise AircrackNoHandshakeError(
                f"aircrack-ng found 0 usable handshakes for {self.bssid} in {capfile} — "
                f"wrong BSSID, or no full handshake captured for this target."
            )
        return found
