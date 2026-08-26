"""Scanning via a locally-compiled scan engine — this module owns the
CSV parsing and process lifecycle itself, and points at OUR OWN build
in vendor/aircrack-ng, compiled from source in this same tree (see
vendor/aircrack-ng).

Why a compiled engine at all, alongside the from-scratch scapy scanner:
its mature, decade-tested channel-hop and capture logic handles quirky
chipsets more robustly than a from-scratch reimplementation in general,
and gives direct access to patch/rebuild the actual capture engine's C
source in-tree if a driver-specific fix is ever needed. (Note: an
earlier mt76x0u 5GHz RX issue was root-caused to a stuck USB device
state, not a real driver/hardware limit — cleared by a physical
unplug/replug; both adapters are confirmed capable of 5GHz monitor-mode
RX.)
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
_VENDOR_ROOT = Path(__file__).resolve().parents[2] / "vendor" / "aircrack-ng"
HOPSCAN_BIN = _VENDOR_ROOT / "airodump-ng"


class ScanEngineNotBuilt(RuntimeError):
    """Raised when the vendored scan-engine binary hasn't been built yet."""


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


def parse_scan_csv(text: str) -> ScanResult:
    """Same field mapping and hidden-SSID handling as the original scan
    engine's CSV output, adapted to return typed dataclasses instead of
    raw dicts."""
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
    """Run the vendored scan engine for `duration` seconds and parse its
    CSV output. `channel` locks to one channel; `band` is 'a' (5GHz),
    'bg' (2.4GHz), or None (both, the engine's own hop list)."""
    if not HOPSCAN_BIN.exists():
        raise ScanEngineNotBuilt(
            f"{HOPSCAN_BIN} not found — build it first: "
            f"cd {_VENDOR_ROOT} && autoreconf -i && ./configure && make"
        )

    with tempfile.TemporaryDirectory(prefix="atwa_scan_") as tmp:
        prefix = os.path.join(tmp, "scan")
        cmd = [str(HOPSCAN_BIN), "--output-format", "csv",
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
        return parse_scan_csv(csv_path.read_text(errors="replace"))
