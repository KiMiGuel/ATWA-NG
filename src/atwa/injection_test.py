"""Native injection self-test: confirms an adapter can actually transmit
frames that elicit real over-the-air replies, not just that the OS
accepted the send() call.

Ported from aircrack-ng's aireplay-ng --test (-9) attack
(do_attack_test() in aireplay-ng.c) rather than wrapping the binary --
same two-phase discovery + directed-ping methodology, reimplemented
natively:

1. Broadcast probe requests (3 attempts, ~600ms each) to discover any AP
   in range, unless a bssid was already given.
2. Directed ping test against that AP: for `count` attempts (default 30,
   matching aireplay-ng's REQUESTS constant), send a probe request + RTS
   + null-data + auth-request in sequence and count any reply addressed
   back to this attempt's random source MAC (probe response, CTS, ACK,
   or auth response) as a successful "ping".

A random source MAC per attempt is the correlation key, same as
aireplay-ng's per-attempt r_smac -- it's how a reply is matched to the
frame that provoked it rather than to background traffic.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from scapy.layers.dot11 import Dot11, Dot11Auth, Dot11Beacon, Dot11ProbeResp
from scapy.sendrecv import sendp, sniff

from .frames import BROADCAST, craft_auth, craft_null_data, craft_probe_req, craft_rts

ATIME = 0.2  # seconds to wait for an answer per attempt (aireplay-ng's atime=200ms)
BROADCAST_ATTEMPTS = 3
DEFAULT_REQUESTS = 30


def _random_mac() -> str:
    """Locally-administered random MAC, regenerated per attempt so a
    reply can be correlated to the frame that provoked it."""
    first = (random.randint(0, 255) & 0xFC) | 0x02
    rest = [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in [first, *rest])


@dataclass
class InjectionTestResult:
    bssid: str | None = None
    pings_sent: int = 0
    pings_answered: int = 0
    detail: str = ""

    @property
    def percent(self) -> float:
        return 100.0 * self.pings_answered / self.pings_sent if self.pings_sent else 0.0


def _is_reply_to(pkt, client_mac: str, bssid: str | None) -> bool:
    """True if pkt is one of {probe response, CTS, ACK, auth response}
    addressed back to client_mac -- the same four reply types
    aireplay-ng --test accepts as evidence injection worked."""
    dot11 = pkt.getlayer(Dot11)
    if dot11 is None or not dot11.addr1 or dot11.addr1.lower() != client_mac.lower():
        return False
    if pkt.haslayer(Dot11ProbeResp):
        return bssid is None or (dot11.addr3 or "").lower() == bssid.lower()
    if dot11.type == 1 and dot11.subtype in (12, 13):  # CTS, ACK (control frames)
        return True
    if pkt.haslayer(Dot11Auth) and dot11.subtype == 11:  # auth response
        return bssid is None or (dot11.addr2 or "").lower() == bssid.lower()
    return False


def _discover_ap(iface: str, timeout: float, sendp_fn, sniff_fn, progress_fn) -> str | None:
    """Broadcast probe-request discovery phase: returns the first
    responding/beaconing AP's bssid, or None if nothing answered."""
    found: list[str] = []

    def handler(pkt) -> None:
        if pkt.haslayer(Dot11ProbeResp) or pkt.haslayer(Dot11Beacon):
            dot11 = pkt.getlayer(Dot11)
            if dot11 and dot11.addr3 and dot11.addr3 not in found:
                found.append(dot11.addr3)

    progress_fn("trying broadcast probe requests...")
    for _ in range(BROADCAST_ATTEMPTS):
        client = _random_mac()
        sendp_fn(craft_probe_req(bssid=BROADCAST, client=client), iface=iface, verbose=False)
        sniff_fn(iface=iface, timeout=timeout, prn=handler, store=False)
        if found:
            break
    return found[0] if found else None


def injection_test(
    iface: str,
    bssid: str | None = None,
    count: int = DEFAULT_REQUESTS,
    per_attempt_timeout: float = ATIME,
    progress_fn=None,
    sendp_fn=sendp,
    sniff_fn=sniff,
) -> InjectionTestResult:
    """Run the two-phase injection test and return per-AP ping stats.

    If bssid is None, the broadcast discovery phase picks the first AP
    that answers or beacons; if none do, returns a zero-attempt result
    with detail explaining nothing was found.
    """
    log = progress_fn or (lambda msg: None)
    target = bssid or _discover_ap(iface, per_attempt_timeout * 3, sendp_fn, sniff_fn, log)
    if target is None:
        return InjectionTestResult(detail="no answer to broadcast probe requests -- no AP found")

    log(f"trying directed probe requests against {target}...")
    result = InjectionTestResult(bssid=target)
    for attempt in range(count):
        client = _random_mac()
        sendp_fn(craft_probe_req(bssid=target, client=client), iface=iface, verbose=False)
        sendp_fn(craft_rts(bssid=target, client=client), iface=iface, verbose=False)
        sendp_fn(craft_null_data(bssid=target, client=client), iface=iface, verbose=False)
        sendp_fn(craft_auth(bssid=target, client=client), iface=iface, verbose=False)

        answered = [False]

        def handler(pkt, answered=answered, client=client) -> None:
            if not answered[0] and _is_reply_to(pkt, client, target):
                answered[0] = True

        sniff_fn(iface=iface, timeout=per_attempt_timeout, prn=handler, store=False,
                  stop_filter=lambda p, answered=answered: answered[0])
        result.pings_sent += 1
        if answered[0]:
            result.pings_answered += 1
        log(f"{result.pings_answered}/{attempt + 1}: {result.percent:.0f}%")

    if result.pings_answered:
        result.detail = "injection is working"
    else:
        result.detail = f"no answer from {target} in {count} attempt(s)"
    return result
