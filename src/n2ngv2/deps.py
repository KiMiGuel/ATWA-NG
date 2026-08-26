"""Dependency check — trimmed to only what v2 actually shells out to.

v1's DependencyChecker (main.py:577-599) listed airmon-ng/airodump-ng/
aireplay-ng/wash/reaver/hashcat as required-or-optional because it wrapped
all of those as attack tools. v2 doesn't wrap any attack tool (scan/deauth/
PMKID/handshake/WEP/WPS are native), so none of those apply anymore — the
only real external-tool dependencies left are the generic file/radio
utilities each feature actually calls.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

# iface up/down + monitor mode + channel control (radio.py) — nothing in
# this app works without these.
REQUIRED_TOOLS = {
    "iw": {"apt": "sudo apt install -y iw", "feature": "monitor mode, channel control"},
    "ip": {"apt": "sudo apt install -y iproute2", "feature": "interface up/down"},
}

# Each of these gates exactly one Captures-tab action; missing one just
# disables that specific action; it does not affect scanning/attacks.
OPTIONAL_TOOLS = {
    "hcxpcapngtool": {"apt": "sudo apt install -y hcxtools", "feature": "convert captures to 22000"},
    "john": {"apt": "install John the Ripper jumbo (not always packaged as plain 'john' — see openwall.com/john)", "feature": "password cracking (22000 hashes)"},
    "aircrack-ng": {"apt": "sudo apt install -y aircrack-ng", "feature": "password cracking (raw .cap, simpler than John)"},
    "pcapfix": {"apt": "sudo apt install -y pcapfix", "feature": "repair a malformed capture"},
    "mergecap": {"apt": "sudo apt install -y wireshark-common", "feature": "merge captures"},
}


@dataclass
class ToolStatus:
    name: str
    found: bool
    required: bool
    feature: str
    apt: str


def check_all() -> list[ToolStatus]:
    """Check every known tool; required tools first, in declared order."""
    results = []
    for name, info in {**REQUIRED_TOOLS, **OPTIONAL_TOOLS}.items():
        results.append(ToolStatus(
            name=name,
            found=shutil.which(name) is not None,
            required=name in REQUIRED_TOOLS,
            feature=info["feature"],
            apt=info["apt"],
        ))
    return results


def missing_required(statuses: list[ToolStatus]) -> list[ToolStatus]:
    return [s for s in statuses if s.required and not s.found]
