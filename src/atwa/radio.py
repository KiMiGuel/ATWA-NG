"""Radio control: monitor mode, channel set/hop, interface detection via ip/iw."""

from __future__ import annotations

import random
import re
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


class RadioError(RuntimeError):
    """Raised when an ip/iw operation fails."""


def _run(cmd: list[str]) -> str:
    """Run a command, raising RadioError on non-zero exit; return stdout.

    stdin=DEVNULL + a timeout for the same reason every other subprocess
    call in this tree needs it: an inherited stdin or an unbounded wait
    can hang the caller forever on a misbehaving/blocking child.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=15, check=False)
    except subprocess.TimeoutExpired:
        raise RadioError(f"{cmd[0]} timed out after 15s")
    if proc.returncode != 0:
        raise RadioError(f"{cmd[0]} failed: {proc.stderr.strip()}")
    return proc.stdout


def detect_interfaces() -> list[str]:
    """Return names of wireless interfaces reported by `iw dev`."""
    out = _run(["iw", "dev"])
    return re.findall(r"Interface\s+(\S+)", out)


def get_driver(iface: str) -> str | None:
    """iface's kernel driver name via ethtool -i, or None if undetermined."""
    try:
        out = _run(["ethtool", "-i", iface])
    except RadioError:
        return None
    match = re.search(r"^driver:\s*(\S+)", out, re.MULTILINE)
    return match.group(1) if match else None


# Hardware-specific by design (STATUS.md "Ideas/undecided", 2026-08-14):
# the dual-Alfa flagship mode is the user's own two real devices, not a
# generic "any two adapters" feature. Confirmed live: wlan1=mt76x0u,
# wlan0=rtw88_8814au.
#
# CORRECTION (2026-08-26): an earlier note here claimed mt76x0u
# couldn't receive 5GHz frames in monitor mode at all, based on a
# controlled A/B test that consistently got 0 packets on 5GHz vs.
# thousands on 2.4GHz. That was wrong — the real cause was a stuck USB
# device state left over from a power outage, not a driver/hardware
# limit; a physical unplug/replug cleared it, and a fresh test
# immediately succeeded on 5GHz. Both adapters are confirmed capable of
# 5GHz monitor-mode RX. The role assignment below (mt76x0u=scan,
# rtw88_8814au=attack) is unchanged — that's a design choice, not tied
# to this correction — but don't cite the old "mt76x0u is 2.4GHz-only"
# claim as a reason for it.
ALFA_SCAN_DRIVERS = {"mt76x0u"}
ALFA_ATTACK_DRIVERS = {"rtw88_8814au"}


def detect_alfa_pair(interfaces: list[str]) -> tuple[str, str] | None:
    """(scan_iface, attack_iface) if both known Alfa chipsets are present
    among interfaces, else None — the flagship dual-radio mode's gate."""
    scan_iface = attack_iface = None
    for iface in interfaces:
        driver = get_driver(iface)
        if driver in ALFA_SCAN_DRIVERS:
            scan_iface = iface
        elif driver in ALFA_ATTACK_DRIVERS:
            attack_iface = iface
    return (scan_iface, attack_iface) if scan_iface and attack_iface else None


def get_mac(iface: str) -> str:
    """Return iface's current MAC address (lowercase, colon-separated)."""
    out = _run(["ip", "link", "show", iface])
    match = re.search(r"link/\S+\s+([0-9a-fA-F:]{17})", out)
    if not match:
        raise RadioError(f"could not determine MAC address for {iface}")
    return match.group(1).lower()


def get_permanent_mac(iface: str) -> str:
    """Return iface's burned-in hardware MAC via ethtool -P (not the
    current one — that may already be randomized)."""
    out = _run(["ethtool", "-P", iface])
    match = re.search(r"([0-9a-fA-F:]{17})", out)
    if not match:
        raise RadioError(f"could not determine permanent MAC for {iface}")
    return match.group(1).lower()


def random_locally_administered_mac() -> str:
    """A random unicast, locally-administered MAC: locally-administered
    bit set, not a real vendor OUI, so it reads as intentionally
    randomized rather than spoofing a specific real device."""
    first = (random.randint(0, 255) & 0xFC) | 0x02  # clear multicast bit, set local-admin bit
    rest = [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in [first, *rest])


def set_mac(iface: str, mac: str) -> None:
    """Set iface's MAC. iface must be down first (caller's responsibility
    within set_monitor_mode/set_managed_mode below)."""
    _run(["ip", "link", "set", iface, "address", mac])


# AWUS036ACHM (mt76x0u) txpower fix: EEPROM offset 0x52 → 0x1e raises
# 5GHz output from a stuck 4 dBm to the real 17 dBm per-channel baseline.
# Only applies to mt76x0u adapters; no-op (with a log) if debugfs isn't
# accessible (non-root, debugfs not mounted, or different adapter variant).
_ACHM_EEPROM_OFFSET = 0x52
_ACHM_EEPROM_VALUE = 0x1E


def _phy_for_iface(iface: str) -> str | None:
    link = Path(f"/sys/class/net/{iface}/phy80211")
    try:
        return link.resolve().name if link.is_symlink() else None
    except OSError:
        return None


def apply_achm_txpower_patch(iface: str) -> bool:
    """Apply the mt76x0u EEPROM txpower patch for iface. Returns True if
    patch was written (or was already in place), False if iface is not an
    mt76x0u or debugfs is inaccessible (non-fatal — caller just logs)."""
    if get_driver(iface) not in ALFA_SCAN_DRIVERS:
        return False
    phy = _phy_for_iface(iface)
    if not phy:
        return False
    eeprom = Path(f"/sys/kernel/debug/ieee80211/{phy}/mt76/eeprom")
    # mount debugfs if not already mounted
    debugfs_root = Path("/sys/kernel/debug")
    if not debugfs_root.is_mount():
        subprocess.run(
            ["mount", "-t", "debugfs", "none", str(debugfs_root)],
            capture_output=True,
            check=False,
        )
    if not eeprom.exists():
        return False
    try:
        with open(eeprom, "rb") as fh:
            fh.seek(_ACHM_EEPROM_OFFSET)
            current = fh.read(1)
        if current and current[0] == _ACHM_EEPROM_VALUE:
            return True  # already patched
        with open(eeprom, "r+b") as fh:
            fh.seek(_ACHM_EEPROM_OFFSET)
            fh.write(struct.pack("B", _ACHM_EEPROM_VALUE))
        return True
    except OSError:
        return False


def fix_antenna_mask(iface: str) -> bool:
    """Correct a stuck 'Configured Antennas' bitmap that doesn't match
    what the radio actually has (seen live on mt76x0u/ACHM: Available
    TX 0x1 RX 0x1 but Configured TX 0x101 RX 0x101 — an invalid extra
    antenna bit that isn't backed by real hardware, which can degrade
    RX sensitivity). rtw88_8814au (wlan0) doesn't exhibit this; a no-op
    there since Available already equals Configured. Returns True if a
    correction was applied, False if nothing needed fixing or the phy/
    driver doesn't expose antenna control."""
    phy = _phy_for_iface(iface)
    if not phy:
        return False
    try:
        out = _run(["iw", "phy", phy, "info"])
    except RadioError:
        return False
    avail = re.search(r"Available Antennas:\s*TX\s*(0x[0-9a-fA-F]+)\s*RX\s*(0x[0-9a-fA-F]+)", out)
    configured = re.search(r"Configured Antennas:\s*TX\s*(0x[0-9a-fA-F]+)\s*RX\s*(0x[0-9a-fA-F]+)", out)
    if not avail or not configured or avail.groups() == configured.groups():
        return False
    try:
        _run(["iw", "phy", phy, "set", "antenna", avail.group(1), avail.group(2)])
        return True
    except RadioError:
        return False  # some chipsets don't support runtime antenna reconfig — non-fatal


# Same interfering-process list airmon-ng's own "check kill" uses -- these
# are what actually race a raw AF_PACKET capture socket for control of the
# radio (NetworkManager + wpa_supplicant reassociating/rescanning,
# dhclient renewing a lease mid-capture, avahi re-probing on link changes).
# Plain process kill, not nmcli/systemctl -- confirmed live (2026-08-28)
# that NM left running on an interface will periodically randomize its MAC
# and cycle its supplicant state on its own schedule, which yanks the
# interface admin-down out from under a raw socket mid-capture -- the exact
# ENETDOWN failure previously misattributed to atwa's own races.
_AIRMON_INTERFERING_PROCESSES = (
    "NetworkManager", "wpa_action", "wpa_supplicant", "wpa_cli",
    "dhclient", "dhclient3", "dhcdbd", "udhcpc", "dhcpcd",
    "avahi-autoipd", "avahi-daemon",
)


def check_kill_interfering_processes() -> list[str]:
    """Kill the same processes airmon-ng's `airmon-ng check kill` does.
    Best-effort and system-wide, matching airmon-ng's own behavior exactly
    -- not scoped to one interface, no nmcli/systemctl involved, and no
    automatic restart afterward (airmon-ng doesn't restart NetworkManager
    for you either; that's a manual `systemctl start NetworkManager` once
    you're done). Returns the process names actually killed."""
    killed = []
    for name in _AIRMON_INTERFERING_PROCESSES:
        proc = subprocess.run(
            ["pkill", "-x", name], capture_output=True, stdin=subprocess.DEVNULL, timeout=10, check=False,
        )
        if proc.returncode == 0:
            killed.append(name)
    return killed


def set_monitor_mode(
    iface: str,
    randomize_mac: bool = False,
    patch_txpower: bool = True,
) -> tuple[str, str | None]:
    """Put iface into monitor mode (down → [randomize MAC] → type monitor
    → up). Returns (iface, permanent_mac_or_None) — caller should hang
    onto permanent_mac and pass it to set_managed_mode's restore_mac to
    put the real MAC back later.

    patch_txpower: auto-apply the ACHM EEPROM fix for mt76x0u adapters
    (no-op for other drivers). Pass False in unit tests to skip the
    debugfs dependency."""
    check_kill_interfering_processes()
    permanent_mac = get_permanent_mac(iface) if randomize_mac else None
    _run(["ip", "link", "set", iface, "down"])
    try:
        if randomize_mac:
            set_mac(iface, random_locally_administered_mac())
        _run(["iw", "dev", iface, "set", "type", "monitor"])
    finally:
        _run(["ip", "link", "set", iface, "up"])
    if patch_txpower:
        apply_achm_txpower_patch(iface)
    fix_antenna_mask(iface)
    return iface, permanent_mac


def set_managed_mode(iface: str, restore_mac: str | None = None) -> str:
    """Return iface to managed mode. Pass restore_mac (the permanent MAC
    from set_monitor_mode) to put the real hardware MAC back."""
    _run(["ip", "link", "set", iface, "down"])
    try:
        if restore_mac:
            set_mac(iface, restore_mac)
        _run(["iw", "dev", iface, "set", "type", "managed"])
    finally:
        _run(["ip", "link", "set", iface, "up"])
    return iface


def get_mode(iface: str) -> str:
    """Return iface's current 802.11 mode ('managed', 'monitor', ...)."""
    out = _run(["iw", "dev", iface, "info"])
    match = re.search(r"type\s+(\S+)", out)
    return match.group(1).lower() if match else "unknown"


def set_channel(iface: str, channel: int) -> None:
    """Set the radio channel on a monitor-mode interface.

    Sets it at the PHY level (`iw phy <phy> set channel`, NL80211_CMD_SET_WIPHY
    — the correct netlink call for this), not the interface level
    (`iw dev <iface> set channel`, NL80211_CMD_SET_CHANNEL)
    this used before. Confirmed live (2026-08-25): on wlan0 (rtw88_8814au),
    the interface-level command silently "succeeded" (iw reported the new
    channel, no error) while the radio never actually retuned — a clean,
    verified capture at a 5GHz channel set this way got zero frames, while
    the exact same channel set at the PHY level immediately captured real
    beacons. This had been wrongly written off as "5GHz doesn't work on this
    hardware" — wlan0 was never the hardware limit, this call was.
    wlan1 (mt76x0u) still gets zero 5GHz frames even with the PHY-level
    call — that part of the original finding holds; only wlan0 was wrong.
    Falls back to the old interface-level form if the phy can't be resolved.
    """
    phy = _phy_for_iface(iface)
    if phy is None:
        _run(["iw", "dev", iface, "set", "channel", str(channel)])
        return
    _run(["iw", "phy", phy, "set", "channel", str(channel)])


# Per-interface cache of the last channel we successfully set. Used by
# ensure_channel() to skip redundant `iw` calls and to surface a clear log
# only when the channel actually changes. Cleared automatically when a
# channel change fails (exception propagates before the cache is updated).
_last_channel: dict[str, int] = {}


def ensure_channel(iface: str, channel: int | None) -> bool:
    """Set the channel only if it differs from the cached last channel.

    Returns True when set_channel() was actually invoked, False when the
    channel was already cached (or channel is None, meaning "leave it").

    This eliminates the repeated `iw phy ... set channel` calls that
    happen when the GUI or Omni orchestrator issues the same channel many
    times in a row, and makes the "channel set to N" log line meaningful
    (it only fires on real changes).
    """
    if channel is None:
        return False
    if _last_channel.get(iface) == channel:
        return False
    set_channel(iface, channel)
    _last_channel[iface] = channel
    return True


def clear_channel_cache(iface: str | None = None) -> None:
    """Clear the ensure_channel() cache. Useful in tests and after an
    external process may have retuned the interface."""
    if iface is None:
        _last_channel.clear()
    else:
        _last_channel.pop(iface, None)


# 2.4GHz (1-13) + all 5GHz channels including UNII-2/2e DFS (52-140).
# DFS channels were previously excluded ("support varies, not worth the
# complexity") but that's a live, confirmed gap, not a theoretical one:
# a real wpa_supplicant scan on this exact hardware (2026-08-25) found
# a large share of nearby APs sitting on DFS channels (52, 100-140
# range) that this hop list simply never visited. DFS only gates
# *transmitting*/becoming an AP (the CAC requirement) — passive
# listening in monitor mode needs no such wait, so there's no real
# downside to including them for a scanner.
CHANNELS_24GHZ = list(range(1, 14))
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64,
                 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
                 149, 153, 157, 161, 165]
ALL_CHANNELS = CHANNELS_24GHZ + CHANNELS_5GHZ


@dataclass
class ChannelHopper:
    """Round-robin channel hopper with a fixed dwell time."""

    iface: str
    channels: list[int] = field(default_factory=lambda: list(ALL_CHANNELS))
    dwell: float = 0.3
    _idx: int = 0

    def hop(self) -> int:
        """Advance to the next channel, set it, and sleep for the dwell time.

        Not every adapter/regulatory domain supports every 5GHz channel in
        the default list — set_channel failing on one unsupported channel
        must not kill the whole hop loop, just skip it and try the next.
        """
        channel = self.channels[self._idx % len(self.channels)]
        try:
            set_channel(self.iface, channel)
        except RadioError:
            pass
        self._idx += 1
        time.sleep(self.dwell)
        return channel
