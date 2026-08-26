"""Capture file utilities: convert to 22000 (John's wpapsk format), repair,
and merge captures. hcxpcapngtool/pcapfix/mergecap are generic pcap-file
tools, not attack-logic — fine to shell out to, per the project's
native-attack-logic (not native-file-format-parsing) scope.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ..storage import organized_output_path


class ConverterUnavailableError(RuntimeError):
    """Raised when no capture-conversion tool is available."""


class RepairUnavailableError(RuntimeError):
    """Raised when pcapfix is not available."""


class MergeUnavailableError(RuntimeError):
    """Raised when mergecap is not available."""


def cap_to_22000(capfile: str, outfile: str) -> str:
    """Convert a capture to 22000 lines via hcxpcapngtool; return outfile.

    Raises ConverterUnavailableError with install guidance if the tool is
    missing, so callers never silently produce nothing. Also raises if
    hcxpcapngtool exits 0 but wrote nothing — confirmed live (2026-08-26):
    a real capture with actual EAPOL pairs still gets "no hashes written"
    (exit 0, no output file) when it's missing beacon/probe-response frames
    (needed for the ESSID) — a real, unremarkable outcome for a short
    handshake-stage capture, not a tool malfunction. Without this check,
    omni.py's _stage_crack crashed uncaught trying to read a file that was
    never created.
    """
    if shutil.which("hcxpcapngtool") is None:
        raise ConverterUnavailableError(
            "hcxpcapngtool not found; install hcxtools to convert .cap/.pcap "
            "captures to 22000 format"
        )
    proc = subprocess.run(
        ["hcxpcapngtool", "-o", outfile, capfile], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"hcxpcapngtool failed: {proc.stderr.strip()}")
    if not Path(outfile).exists() or Path(outfile).stat().st_size == 0:
        raise RuntimeError(
            f"hcxpcapngtool found no convertible handshake/PMKID material in "
            f"{capfile} (likely missing beacon/probe-response frames for the "
            f"ESSID, or no full EAPOL exchange captured)"
        )
    return outfile


def hc22000_to_john(hashfile: str, outfile: str) -> str:
    """Convert a hashcat-format 22000 file to John's own wpapsk format via
    `hcxhashtool --john=`. Required, not optional: John's wpapsk parser
    does not accept raw hashcat 22000 lines directly — confirmed via a
    real captured line rejected with "No password hashes loaded" despite
    being spec-valid. Also doubles as the "does this file actually hold a
    usable handshake" check: hcxhashtool writes nothing if it doesn't.
    """
    if shutil.which("hcxhashtool") is None:
        raise ConverterUnavailableError(
            "hcxhashtool not found; install hcxtools to convert 22000 hashes for John"
        )
    proc = subprocess.run(
        ["hcxhashtool", "-i", hashfile, f"--john={outfile}"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"hcxhashtool failed: {proc.stderr.strip()}")
    if not Path(outfile).exists() or Path(outfile).stat().st_size == 0:
        raise RuntimeError(
            f"hcxhashtool found no valid EAPOL/PMKID handshake in {hashfile} to convert for John"
        )
    return outfile


def fix_capture(capfile: str) -> str:
    """Repair a malformed .cap/.pcap via pcapfix; return the fixed file's path.

    Output goes under capture_root()/fixed/YYYY-MM-DD/, matching v1's
    fixed_capture_output_path convention.
    """
    if shutil.which("pcapfix") is None:
        raise RepairUnavailableError("pcapfix not found; install pcapfix to repair captures")
    cap = Path(capfile)
    suffix = cap.suffix if cap.suffix.lower() in {".cap", ".pcap", ".pcapng"} else ".cap"
    out = organized_output_path("fixed", f"{cap.stem}.fixed{suffix}")
    proc = subprocess.run(
        ["pcapfix", "-k", "-o", str(out), str(cap)], capture_output=True, text=True, timeout=120
    )
    if proc.returncode != 0 or not out.exists() or out.stat().st_size == 0:
        raise RuntimeError(f"pcapfix failed: {proc.stderr.strip() or 'no output written'}")
    return str(out)


def merge_captures(capfiles: list[str]) -> str:
    """Merge 2+ captures into one via mergecap; return the merged file's path.

    Output goes under capture_root()/merged/YYYY-MM-DD/, matching v1's
    merged_capture_output_path convention.
    """
    if len(capfiles) < 2:
        raise ValueError("need at least two captures to merge")
    if shutil.which("mergecap") is None:
        raise MergeUnavailableError("mergecap not found; install wireshark-common to merge captures")
    first = Path(capfiles[0])
    suffix = first.suffix if first.suffix.lower() in {".cap", ".pcap", ".pcapng"} else ".pcapng"
    out = organized_output_path("merged", f"{first.stem}.merged{suffix}")
    proc = subprocess.run(
        ["mergecap", "-w", str(out), *capfiles], capture_output=True, text=True, timeout=120
    )
    if proc.returncode != 0 or not out.exists():
        raise RuntimeError(f"mergecap failed: {proc.stderr.strip()}")
    return str(out)


def merge_22000_files(paths: list[str]) -> list[str]:
    """Dedupe+merge 22000 hash-line files, same rule as omni.py's
    _stage_crack batching (sorted(set(lines))). Returns the merged lines,
    caller decides where to write them."""
    lines: set[str] = set()
    for p in paths:
        for line in Path(p).read_text().splitlines():
            if line.strip():
                lines.add(line.strip())
    return sorted(lines)
