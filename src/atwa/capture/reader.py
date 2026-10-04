"""Read a monitor-mode capture.

Scapy resolves linktype 127 (DLT_IEEE802_11_RADIO, what capture/lock.py
writes) lazily: the mapping is only registered once scapy.layers.dot11 has
been imported. A caller that reaches PcapReader before anything pulls in
the 802.11 layers gets the "unknown LL type [127]" warning and every
packet handed back as an opaque Raw -- silently, and with no exception --
so a capture full of beacons and EAPOL inspects as empty.

Importing the 802.11 layers here makes the dependency explicit and
orders it correctly, whatever the caller happened to have imported. That
is the whole fix; no table patching is needed and none is done, since
mutating conf.l2types would leak into unrelated callers.
"""

from __future__ import annotations

import warnings
from collections.abc import Iterator
from typing import Any

# Import for the side effect: this registers conf.l2types[127] = RadioTap,
# so a PcapReader below decodes radiotap frames instead of yielding Raw.
from scapy.layers.dot11 import Dot11, RadioTap  # noqa: F401
from scapy.utils import PcapReader


def read_capture(path: str) -> list[Any]:
    """Read a capture file into a list of packets.

    Materialised, not streamed: the GUI's inspect paths walk a capture
    exactly once, so a generator saves nothing and only risks a caller
    iterating outside the import ordering this module establishes.
    """
    with warnings.catch_warnings():
        # Harmless while linktype 127 is registered; noisy if a caller
        # passes a capture whose linktype genuinely is unknown.
        warnings.simplefilter("ignore")
        with PcapReader(str(path)) as packets:
            return list(packets)


def iter_capture(path: str) -> Iterator[Any]:
    """Stream a capture without materialising it (for large files).

    Only safe when the generator is fully consumed; prefer read_capture()
    unless memory is the binding constraint.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with PcapReader(str(path)) as packets:
            yield from packets


__all__ = ["iter_capture", "read_capture"]