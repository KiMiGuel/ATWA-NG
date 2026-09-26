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


_driver_cache: dict[str, str | None] = {}


def get_driver(iface: str) -> str | None:
    """iface's kernel driver name via ethtool -i, or None if undetermined.

    Note (2026-09-14): ethtool is deprecated upstream. Evaluated
    replacements and deliberately kept it for now -- the sysfs driver
    symlink (/sys/class/net/<iface>/device/driver, same trick
    _phy_for_iface() uses) covers `ethtool -i`, and `ip link`'s permaddr
    field covers `ethtool -P`, but both need testing against the real
    Alfa pair before a swap; ethtool is present everywhere Kali is.

    Cached per interface -- a driver never changes without a hot-unplug/
    replug (a fresh device node, i.e. a different iface name in the
    common case, or an explicit clear_driver_cache() call after one),
    so repeated calls against the same iface (dual-Alfa detection,
    apply_achm_txpower_patch on every set_monitor_mode()) don't need a
    fresh `ethtool -i` subprocess each time.
    """
    if iface in _driver_cache:
        return _driver_cache[iface]
    try:
        out = _run(["ethtool", "-i", iface])
    except RadioError:
        driver = None
    else:
        match = re.search(r"^driver:\s*(\S+)", out, re.MULTILINE)
        driver = match.group(1) if match else None
    _driver_cache[iface] = driver
    return driver


def clear_driver_cache(iface: str | None = None) -> None:
    """Clear the get_driver() cache. Useful in tests and after a hot-unplug/
    replug that might reuse the same interface name with different hardware."""
    if iface is None:
        _driver_cache.clear()
    else:
        _driver_cache.pop(iface, None)


# PINCER is a public dual-Alfa feature. The user's known lab pair is
# wlan1=mt76x0u and wlan0=rtw88_8814au, but the gate must not require those
# exact models for other users.
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
# USB vendor IDs used by Alfa adapters and common Alfa re-badged MediaTek
# hardware. Driver-only detection is too narrow: a stranger may own two
# different Alfa radios whose Linux drivers are not the two chipsets in our
# lab. 0x0e8d is MediaTek's USB vendor ID and is also what the user's
# AWUS036ACHM exposes; it cannot by itself prove the enclosure brand, so this
# is a compatibility fallback after the known-driver path, not a claim that
# every Mediatek/Realtek product is an Alfa.
ALFA_USB_VENDORS = {"0cf3", "0e8d"}


def get_usb_vendor_id(iface: str) -> str | None:
    """Return the interface's USB vendor ID, or None when unavailable."""
    try:
        out = _run(["udevadm", "info", "--query=property", f"--path=/sys/class/net/{iface}"])
    except RadioError:
        return None
    match = re.search(r"^ID_VENDOR_ID=([0-9a-fA-F]{4})$", out, re.MULTILINE)
    return match.group(1).lower() if match else None


def detect_alfa_pair(interfaces: list[str]) -> tuple[str, str] | None:
    """Return ``(scan_iface, attack_iface)`` for a usable dual-Alfa setup.

    Known lab drivers win: mt76x0u is the receive/scanner role and
    rtw88_8814au is the transmit/attack role. If both are present, return
    them. For other Alfa Networks USB adapters, fall back to the detected
    pair and assign the first as scanner and the second as attacker. The
    caller still performs the actual monitor/injection operations; this
    function is capability discovery, not a promise that every future Alfa
    driver has identical RF characteristics.
    """
    drivers = {iface: get_driver(iface) for iface in interfaces}
    known_scan = [iface for iface, driver in drivers.items() if driver in ALFA_SCAN_DRIVERS]
    known_attack = [iface for iface, driver in drivers.items() if driver in ALFA_ATTACK_DRIVERS]
    if known_scan and known_attack:
        return known_scan[0], known_attack[0]

    alfa = [
        iface for iface in interfaces
        if get_usb_vendor_id(iface) in ALFA_USB_VENDORS
    ]
    if len(alfa) >= 2:
        if known_scan:
            return known_scan[0], next(iface for iface in alfa if iface != known_scan[0])
        if known_attack:
            return next(iface for iface in alfa if iface != known_attack[0]), known_attack[0]
        return alfa[0], alfa[1]
    return None


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
        try:
            subprocess.run(
                ["mount", "-t", "debugfs", "none", str(debugfs_root)],
                capture_output=True,
                check=False,
                timeout=10,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return False
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
    """Kill known Wi-Fi-interfering processes, modeled after (not an exact
    port of) airmon-ng's `check kill` -- the real airmon-ng also stops
    NetworkManager/avahi-daemon/wicd via systemctl/service and covers a
    longer process list; this is a plain system-wide `pkill -x` loop over
    _AIRMON_INTERFERING_PROCESSES above, no nmcli/systemctl involved, and
    no automatic restart afterward (a manual `systemctl start
    NetworkManager` once you're done, same as airmon-ng requires).
    Returns the process names actually killed.

    pkill only *sends* SIGTERM -- the killed processes take a moment to
    actually exit and release the wireless device, and set_monitor_mode()
    calls this and then immediately touches the interface. Without waiting
    here, `iw set type monitor` right after a kill fails with "Device or
    resource busy" (confirmed live 2026-09-15: Start Monitor clicked
    immediately after launching the GUI failed; retrying a few seconds
    later worked, once the supplicant had finished dying). So: poll until
    every killed process is genuinely gone (up to ~3s), SIGKILL any
    survivor, and only then return."""
    killed = []
    for name in _AIRMON_INTERFERING_PROCESSES:
        proc = subprocess.run(
            ["pkill", "-x", name], capture_output=True, stdin=subprocess.DEVNULL, timeout=10, check=False,
        )
        if proc.returncode == 0:
            killed.append(name)

    survivors = _wait_until_dead(killed, 3.0)
    for name in survivors:
        # Refused to die on SIGTERM within the grace period -- SIGKILL
        # can't be caught or ignored, then give it one more short wait.
        subprocess.run(
            ["pkill", "-9", "-x", name], capture_output=True, stdin=subprocess.DEVNULL, timeout=10, check=False,
        )
    _wait_until_dead(survivors, 1.0)
    return killed


def _alive_names(names: list[str]) -> set[str]:
    """Which of `names` still have a running process, checked with a single
    `pgrep -x -l` call instead of one `pgrep` subprocess per name."""
    if not names:
        return set()
    pattern = "|".join(re.escape(name) for name in names)
    proc = subprocess.run(
        ["pgrep", "-x", "-l", pattern], capture_output=True, text=True,
        stdin=subprocess.DEVNULL, timeout=5, check=False,
    )
    found = set()
    for line in proc.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            found.add(parts[1])
    return found


def _wait_until_dead(names: list[str], timeout: float) -> list[str]:
    """Poll until none of `names` has a running process left, or `timeout`
    seconds elapse. Returns whichever names are still alive at the end."""
    survivors = list(names)
    deadline = time.monotonic() + timeout
    while survivors and time.monotonic() < deadline:
        alive = _alive_names(survivors)
        survivors = [name for name in survivors if name in alive]
        if survivors:
            time.sleep(0.1)
    return survivors


def disable_power_save(iface: str) -> bool:
    """Turn off the adapter's power-save mode (`iw dev <iface> set
    power_save off`). Aggressive power-save on Realtek/MediaTek chipsets
    is a documented source of erratic RX latency and dropped frames in
    monitor mode -- there's no legitimate reason to conserve power on an
    adapter that's actively doing packet-capture/injection work. Returns
    True if the command succeeded, False if the driver doesn't support
    the setting (non-fatal -- caller just proceeds without it)."""
    try:
        _run(["iw", "dev", iface, "set", "power_save", "off"])
        return True
    except RadioError:
        return False  # not every driver exposes power_save control


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
    disable_power_save(iface)
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


def set_txpower(iface: str, power_dbm: int) -> bool:
    """Set TX power for iface in dBm. Returns True on success."""
    try:
        _run(["iw", "dev", iface, "set", "txpower", "fixed", str(power_dbm * 100)])
        return True
    except RadioError:
        return False


def get_max_txpower(iface: str) -> int | None:
    """Return max TX power in dBm for iface, or None if undetermined."""
    phy = _phy_for_iface(iface)
    if phy is None:
        return None
    try:
        out = _run(["iw", "phy", phy, "info"])
    except RadioError:
        return None
    match = re.search(r"(\d+)\s*\.?\d*\s*dBm", out)
    return int(match.group(1)) if match else None


def get_channel_txpower(iface: str, channel: int) -> int | None:
    """Return the advertised TX limit for one channel, in dBm.

    ``get_max_txpower()`` historically returned the first number in
    ``iw phy info`` (usually a 2.4 GHz channel), which made PINCER request
    20 dBm even on a BO-permitted 30 dBm 5 GHz channel. Parse the exact
    ``[channel]`` row instead; ``None`` means unavailable or disabled.
    """
    phy = _phy_for_iface(iface)
    if phy is None:
        return None
    try:
        out = _run(["iw", "phy", phy, "info"])
    except RadioError:
        return None
    row = re.search(
        rf"\[[ ]*{re.escape(str(channel))}[ ]*\][^\n]*?\((\d+(?:\.\d+)?)\s*dBm\)",
        out,
    )
    return int(float(row.group(1))) if row else None


def get_allowed_channels(iface: str, requested: list[int] | None = None) -> list[int]:
    """Return requested channels that the current regulatory domain allows.

    Keep the caller's order and fail open if the PHY cannot be read: a
    transient ``iw`` failure must not silently stop a scan. The normal
    ``iw`` frequency rows include ``(disabled)``; DFS and radar-detection
    rows remain valid for monitor receive and are intentionally retained.
    """
    candidates = list(requested) if requested is not None else list(ALL_CHANNELS) if "ALL_CHANNELS" in globals() else list(CHANNELS_24GHZ) + list(CHANNELS_5GHZ)
    phy = _phy_for_iface(iface)
    if phy is None:
        return candidates
    try:
        out = _run(["iw", "phy", phy, "info"])
    except RadioError:
        return candidates

    allowed: set[int] = set()
    seen: set[int] = set()
    for line in out.splitlines():
        match = re.search(r"\[[ ]*(\d+)[ ]*\]", line)
        if not match:
            continue
        channel = int(match.group(1))
        if channel not in seen and "(disabled)" not in line.lower():
            allowed.add(channel)
            seen.add(channel)
    if not seen:
        return candidates
    return [channel for channel in candidates if channel in allowed]


def get_channel(iface: str) -> int | None:
    """Return iface's actual current channel via a live `iw dev <iface>
    info` read (not the ensure_channel() cache below) -- None if it isn't
    tuned to one at all (e.g. still managed and unassociated)."""
    out = _run(["iw", "dev", iface, "info"])
    match = re.search(r"channel\s+(\d+)", out)
    return int(match.group(1)) if match else None


def ensure_monitor_mode(iface: str) -> None:
    """Restore iface to monitor mode after external drift -- NetworkManager
    reasserting control, a driver reset, or anything else that knocks the
    interface back to managed underneath code that assumed it would stay
    exactly as it was left. Caller is expected to have already checked
    get_mode(iface) != "monitor"; this always performs the restore.

    Re-runs check_kill_interfering_processes() first, same as the initial
    set_monitor_mode() call, since a process reasserting itself is the
    actual mechanism that knocks an interface back to managed in the
    first place. Also clears the channel cache, since re-entering monitor
    mode resets the radio's tuned channel regardless of what atwa last
    set it to -- leaving the stale cache in place would make the next
    ensure_channel() call wrongly think nothing needs to change."""
    check_kill_interfering_processes()
    set_monitor_mode(iface)
    clear_channel_cache(iface)


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
    CORRECTION (2026-09-13): the line above claiming wlan1 (mt76x0u)
    "still gets zero 5GHz frames even with the PHY-level call" was
    disproved by a live re-test — 348 and 342 beacon/probe-resp frames
    captured on wlan1 at channel 149 (5GHz) in two separate 8s windows,
    using this exact PHY-level set_channel(). It was never re-verified
    after the 2026-08-26 stuck-USB-state correction above and had been
    carried forward as fact regardless. Both adapters are confirmed
    capable of 5GHz monitor-mode RX via this function.
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


def check_and_heal(iface: str, expected_channel: int | None = None) -> list[str]:
    """Detect and correct monitor-mode/channel drift on iface -- the same
    class of failure as any code that assumes an interface stays exactly
    as it was left, silently breaking once something external
    (NetworkManager reasserting control, a driver reset, another process
    retuning the radio) changes that state mid-session.

    Reads the real hardware state directly (not the ensure_channel()
    cache, which only reflects what atwa itself last requested and can't
    see a change made by anything else) -- meant for periodic checks in
    long-running loops (a persistent scan session, an attack's per-round
    loop), not every hot-path channel set.

    Returns a list of human-readable actions taken, empty if iface was
    already healthy, so callers can log exactly what happened rather than
    silently reacting to it."""
    actions = []
    if get_mode(iface) != "monitor":
        ensure_monitor_mode(iface)
        actions.append(f"{iface} had dropped out of monitor mode -- restored")
    if expected_channel is not None:
        actual = get_channel(iface)
        if actual != expected_channel:
            set_channel(iface, expected_channel)
            _last_channel[iface] = expected_channel
            actions.append(f"{iface} channel drifted (was {actual}, expected {expected_channel}) -- corrected")
    return actions


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
    # Matches airodump-ng's default hop delay (DEFAULT_HOPFREQ, 250ms) --
    # confirmed live (2026-09-07) both tools pay the same ~90-95ms
    # mt76x0u hardware-retune tax per hop regardless of dwell value (a
    # kernel-driver/firmware round trip, not fixable at the netlink call
    # site -- verified against pyRIC with a persistent socket too), so
    # this constant is the only lever.
    # FLAGGED, NOT RE-VERIFIED (2026-09-13): the "verified against pyRIC"
    # clause above is unconfirmed by anyone re-running it -- it's taken
    # on faith the same way the now-disproved "wlan1 zero 5GHz frames"
    # claim in set_channel() above was. Not shown wrong, just not
    # actually re-checked; treat this specific clause as unverified until
    # someone re-runs the hop-timing comparison against pyRIC directly.
    # The old 0.3 vs. this 0.25 meant
    # ~13% fewer channel visits per unit wall-clock time, which matched
    # a live side-by-side AP-count gap almost exactly (61 vs. 71 APs in
    # a 20s scan -> 86% coverage, vs. an 87% hop-rate ratio); dropping
    # to 0.25 closed it completely (71 vs. 71, same 20s window).
    dwell: float = 0.25
    _idx: int = 0

    def __post_init__(self) -> None:
        # Apply the active regulatory domain once at hopper creation rather
        # than burning an ``iw phy info`` call on every dwell. If filtering
        # leaves no channels, retain the requested list and let set_channel()
        # report the underlying error instead of failing with a modulo error.
        allowed = get_allowed_channels(self.iface, self.channels)
        if allowed:
            self.channels = allowed

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
