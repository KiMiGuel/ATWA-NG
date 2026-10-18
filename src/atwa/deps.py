"""Dependency check — trimmed to only what this project actually shells
out to. Attack logic (scan/deauth/PMKID/handshake/WEP/WPS) is native, so
the only real external-tool dependencies are the generic file/radio
utilities each Captures-tab feature calls, plus optional cracking
backends.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

# iface up/down + monitor mode + channel control (radio.py) — nothing in
# this app works without these.
REQUIRED_TOOLS = {
    "iw": {"apt": "sudo apt install -y iw", "feature": "monitor mode, channel control"},
    "ip": {"apt": "sudo apt install -y iproute2", "feature": "interface up/down"},
    # Shelled out unconditionally by radio.py (get_driver/get_permanent_mac
    # need ethtool; check_kill_interfering_processes needs pkill) -- previously
    # missing from this list entirely, so the dependency check could pass on
    # a system where radio control still failed.
    "ethtool": {"apt": "sudo apt install -y ethtool", "feature": "driver detection, permanent MAC"},
    "pkill": {"apt": "sudo apt install -y procps", "feature": "killing interfering processes (airmon-ng check kill)"},
}

# Strongly suggested: the feature set that depends on them is a headline
# capability (fast cracking, rogue AP), so a missing recommended tool gets a
# yellow warning rather than a silent skip. Still not a hard block.
RECOMMENDED_TOOLS = {
    "john": {"apt": "install John the Ripper jumbo (not always packaged as plain 'john' — see openwall.com/john)", "feature": "password cracking (22000 hashes, fast backend)"},
    "aircrack-ng": {"apt": "sudo apt install -y aircrack-ng", "feature": "password cracking (raw .cap, fast backend)"},
    "hostapd": {"apt": "sudo apt install -y hostapd", "feature": "rogue AP / evil-twin / downgrade attacks"},
    "dnsmasq": {"apt": "sudo apt install -y dnsmasq", "feature": "DHCP/DNS for rogue AP attacks"},
}

# Missing one of these disables the specific feature it backs; none of them
# affect core scanning/monitor-mode/deauth/capture.
OPTIONAL_TOOLS = {
    "hcxpcapngtool": {"apt": "sudo apt install -y hcxtools", "feature": "convert captures to 22000"},
    "pcapfix": {"apt": "sudo apt install -y pcapfix", "feature": "repair a malformed capture"},
    "mergecap": {"apt": "sudo apt install -y wireshark-common", "feature": "merge captures"},
    "wpa_supplicant": {"apt": "sudo apt install -y wpasupplicant", "feature": "WPS oneshot attack"},
}


@dataclass
class ToolStatus:
    name: str
    found: bool
    required: bool
    recommended: bool
    feature: str
    apt: str


def check_all() -> list[ToolStatus]:
    """Check every known tool; required, then recommended, then optional,
    in declared order."""
    results = []
    for name, info in {**REQUIRED_TOOLS, **RECOMMENDED_TOOLS, **OPTIONAL_TOOLS}.items():
        results.append(ToolStatus(
            name=name,
            found=shutil.which(name) is not None,
            required=name in REQUIRED_TOOLS,
            recommended=name in RECOMMENDED_TOOLS,
            feature=info["feature"],
            apt=info["apt"],
        ))
    return results


def missing_required(statuses: list[ToolStatus]) -> list[ToolStatus]:
    return [s for s in statuses if s.required and not s.found]


def missing_recommended(statuses: list[ToolStatus]) -> list[ToolStatus]:
    return [s for s in statuses if s.recommended and not s.found]
