"""Scanning via a vendored, locally-compiled airodump-ng — not the distro
package, not a thin wrapper around it either: this module owns the CSV
parsing and process lifecycle itself (ported from n2-ng v1's
parse_airodump_csv/run_airodump, adapted), and points at OUR OWN build
in .simulation/vendor/aircrack-ng/airodump-ng, built from vendored
source in this same tree (see .simulation/vendor/aircrack-ng).

Why airodump-ng at all, after v2's from-scratch scapy scanner: confirmed
2026-08-25 (N2-NG_v2/CHECKPOINT.md, session s9-s10) that mt76x0u's
monitor-mode RX is 2.4GHz-only at the kernel/driver level — proven with
scapy AND the distro airodump-ng binary, both got 0 packets on 5GHz.
Recompiling airodump-ng from source does not change that (same kernel
driver underneath); this module doesn't claim to fix 5GHz on mt76x0u.
What it does buy: airodump-ng's mature, decade-tested channel-hop and
capture engine, which handles quirky chipsets more robustly than a
from-scratch reimplementation in general, and gives direct access to
patch/rebuild the actual capture engine's C source in-tree if a real,
verified driver-specific fix is ever found.
"""

from __future__ import annotations

import csv
import io
import os
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# Our own vendored, locally-compiled binary — never the system package.
_VENDOR_ROOT = Path(__file__).resolve().parents[3] / "vendor" / "aircrack-ng"
AIRODUMP_NG_BIN = _VENDOR_ROOT / "airodump-ng"


class AirodumpNotBuilt(RuntimeError):
    """Raised when the vendored airodump-ng binary hasn't been built yet."""


@dataclass
class Network:
    bssid: str
    essid: str
    channel: str
    privacy: str
    cipher: str
    auth: str
    power: str
    beacons: str
    iv: str
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class Client:
    station: str
    bssid: str
    power: str
    packets: str
    probed: str = ""


@dataclass
class ScanResult:
    networks: list[Network] = field(default_factory=list)
    clients: list[Client] = field(default_factory=list)


def _format_bssid(bssid: str) -> str:
    return bssid.upper().strip()


def _normalize_csv_reader(reader: csv.DictReader) -> csv.DictReader:
    if reader.fieldnames:
        reader.fieldnames = [fn.strip() for fn in reader.fieldnames]
    return reader


def _csv_field(row: dict, *keys: str) -> str:
    for key in keys:
        value = row.get(key, "")
        if value:
            return value.strip()
    return ""


def parse_airodump_csv(text: str) -> ScanResult:
    """Ported from n2-ng v1's main.py:parse_airodump_csv — same field
    mapping and hidden-SSID handling, adapted to return typed dataclasses
    instead of raw dicts."""
    result = ScanResult()
    text = text.strip()
    if not text:
        return result
    sections = text.split("\n\n")

    ap_lines = "\n".join(line.strip() for line in sections[0].splitlines())
    reader = _normalize_csv_reader(csv.DictReader(io.StringIO(ap_lines)))
    for row in reader:
        essid = row.get("ESSID", "").strip()
        if not essid or essid.lower().startswith("<length:"):
            essid = "[Hidden]"
        result.networks.append(Network(
            bssid=_format_bssid(row.get("BSSID", "")),
            essid=essid,
            channel=row.get("channel", "").strip(),
            privacy=row.get("Privacy", "").strip(),
            cipher=row.get("Cipher", "").strip(),
            auth=row.get("Authentication", "").strip(),
            power=row.get("Power", "").strip(),
            beacons=_csv_field(row, "# Beacons", "#Beacons", "# beacons", "#beacons"),
            iv=_csv_field(row, "# IV", "#IV", "# iv", "#iv"),
            first_seen=row.get("First time seen", "").strip(),
            last_seen=row.get("Last time seen", "").strip(),
        ))

    if len(sections) > 1:
        client_lines = "\n".join(line.strip() for line in sections[1].splitlines())
        reader = _normalize_csv_reader(csv.DictReader(io.StringIO(client_lines)))
        for row in reader:
            result.clients.append(Client(
                station=_format_bssid(row.get("Station MAC", "")),
                bssid=_format_bssid(row.get("BSSID", "")),
                power=row.get("Power", "").strip(),
                packets=row.get("# packets", "").strip(),
                probed=row.get("Probed ESSIDs", "").strip(),
            ))
    return result


def scan(iface: str, duration: float = 10.0, channel: int | None = None,
          band: str | None = None) -> ScanResult:
    """Run our vendored airodump-ng for `duration` seconds and parse its
    CSV output. `channel` locks to one channel; `band` is 'a' (5GHz),
    'bg' (2.4GHz), or None (both, airodump-ng's own hop list)."""
    if not AIRODUMP_NG_BIN.exists():
        raise AirodumpNotBuilt(
            f"{AIRODUMP_NG_BIN} not found — build it first: "
            f"cd {_VENDOR_ROOT} && autoreconf -i && ./configure && make"
        )

    with tempfile.TemporaryDirectory(prefix="atwa_scan_") as tmp:
        prefix = os.path.join(tmp, "scan")
        cmd = [str(AIRODUMP_NG_BIN), "--output-format", "csv",
               "--write-interval", "1", "-w", prefix]
        if channel is not None:
            cmd += ["-c", str(channel)]
        if band is not None:
            cmd += ["--band", band]
        cmd.append(iface)

        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        try:
            time.sleep(duration)
        finally:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        csv_path = Path(f"{prefix}-01.csv")
        if not csv_path.exists():
            return ScanResult()
        return parse_airodump_csv(csv_path.read_text(errors="replace"))
