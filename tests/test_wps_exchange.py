"""attacks/wps.py: low-level WPS exchange helpers.

Tests the two correctness gaps vs. real WPS tools (Reaver) that prevent the
native WPS PIN brute-forcer from completing a live M2->M3 exchange:

1. Received EAP/WSC frames must be destined to us (addr1 == client), not just
   sourced from the AP (addr2 == bssid). Without this check, monitor mode can
   pick up EAP frames destined to other stations and misattribute them as our
   reply.

2. After sending M2 we must proactively resend it on a fixed timer while
   waiting for M3/NACK. Some APs do not retransmit M1 when our M2 is lost; a
   purely reactive "resend on duplicate M1" strategy then sits silent until
   timeout.
"""
from __future__ import annotations

import threading
import time
from typing import Callable

import pytest
from scapy.layers.dot11 import Dot11, Dot11AssoResp, Dot11Auth
from scapy.packet import Packet

import atwa.attacks.wps as wps_module
import atwa.wps.eap as eap
import atwa.wps.messages as messages

BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT = "11:22:33:44:55:66"
OTHER_CLIENT = "22:33:44:55:66:77"


def _make_ap_eap_frame(
    bssid: str = BSSID,
    client: str = CLIENT,
    identifier: int = 1,
    opcode: int = eap.WSC_OP_MSG,
    payload: bytes = b"",
) -> Packet:
    """Build a frame that looks like it came from the AP to `client`.

    `craft_wsc_msg` builds station->AP frames by default; we swap addr1/addr2
    to flip the direction while keeping the same EAPOL/EAP structure.
    """
    pkt = eap.craft_wsc_msg(bssid, client, identifier, opcode, payload)
    pkt.addr1, pkt.addr2 = client, bssid
    return pkt


class _MockSniffer:
    """Deterministic AsyncSniffer replacement for unit tests.

    Production code now polls for `found`/`result` state instead of
    blocking in sniffer.join() (so a stop_event can interrupt mid-wait),
    so packet delivery has to happen on a background thread from start()
    -- a synchronous join() is never called by the code under test.
    """

    def __init__(self, packets: list[Packet], delay: float = 0.0):
        self.packets = list(packets)
        self.delay = delay
        self.kwargs: dict = {}
        self._prn: Callable | None = None
        self._stop_filter: Callable | None = None
        self._thread: threading.Thread | None = None

    def __call__(self, *, prn, stop_filter, **kwargs):
        self.kwargs = kwargs
        self._prn = prn
        self._stop_filter = stop_filter
        return self

    def start(self) -> None:
        def run():
            if self.delay:
                time.sleep(self.delay)
            assert self._prn is not None and self._stop_filter is not None
            for pkt in self.packets:
                self._prn(pkt)
                if self._stop_filter(pkt):
                    break

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def join(self) -> None:
        if self._thread is not None:
            self._thread.join()

    def stop(self) -> None:
        pass


def test_wait_for_rejects_frame_destined_to_other_station(monkeypatch):
    """A frame from the AP but addressed to another station must not match."""
    monkeypatch.setattr(wps_module, "AsyncSniffer", _MockSniffer([
        _make_ap_eap_frame(client=OTHER_CLIENT, opcode=eap.WSC_OP_MSG, payload=b"x"),
    ], delay=0.01))

    parsed = wps_module._wait_for(
        "wlan0", BSSID, CLIENT,
        lambda p: p.opcode == eap.WSC_OP_MSG,
        timeout=0.2,
    )

    assert parsed is None


def test_wait_for_accepts_frame_destined_to_us(monkeypatch):
    """A frame from the AP addressed to us must match."""
    monkeypatch.setattr(wps_module, "AsyncSniffer", _MockSniffer([
        _make_ap_eap_frame(client=CLIENT, opcode=eap.WSC_OP_MSG, payload=b"m3"),
    ], delay=0.01))

    parsed = wps_module._wait_for(
        "wlan0", BSSID, CLIENT,
        lambda p: p.opcode == eap.WSC_OP_MSG,
        timeout=0.2,
    )

    assert parsed is not None
    assert parsed.opcode == eap.WSC_OP_MSG
    assert parsed.payload == b"m3"


def test_wait_for_dot11_rejects_auth_for_other_station(monkeypatch):
    """Dot11Auth responses addressed to another station must be ignored."""
    pkt = Dot11(addr1=OTHER_CLIENT, addr2=BSSID, addr3=BSSID, type=0, subtype=11) / Dot11Auth(status=0)
    monkeypatch.setattr(wps_module, "AsyncSniffer", _MockSniffer([pkt], delay=0.01))

    result = wps_module._wait_for_dot11("wlan0", BSSID, CLIENT, Dot11Auth, timeout=0.2)

    assert result is None


def test_wait_for_dot11_accepts_auth_for_us(monkeypatch):
    """Dot11Auth responses addressed to us must be accepted."""
    pkt = Dot11(addr1=CLIENT, addr2=BSSID, addr3=BSSID, type=0, subtype=11) / Dot11Auth(status=0)
    monkeypatch.setattr(wps_module, "AsyncSniffer", _MockSniffer([pkt], delay=0.01))

    result = wps_module._wait_for_dot11("wlan0", BSSID, CLIENT, Dot11Auth, timeout=0.2)

    assert result is not None
    assert result.getlayer(Dot11Auth).status == 0


def test_send_until_m3_proactively_resends_m2(monkeypatch):
    """M2 must be resent periodically even when the AP does not retransmit M1."""
    sent: list[tuple] = []

    def fake_send_wsc(iface, bssid, client, identifier, opcode, payload, version=1):
        sent.append((identifier, opcode, payload, version))

    monkeypatch.setattr(wps_module, "_send_wsc_message", fake_send_wsc)
    # No M3, no M1 retransmit; sniffer returns after a short delay.
    monkeypatch.setattr(wps_module, "AsyncSniffer", _MockSniffer([], delay=0.18))

    m2 = b"\x02"
    result = wps_module._send_until_m3(
        "wlan0", BSSID, CLIENT, m2, identifier=7,
        timeout=0.3, resend_interval=0.05, version=1,
        send_fn=lambda: sent.append(("initial",)),
    )

    assert result is None
    assert any(s == ("initial",) for s in sent)
    proactive = [s for s in sent if s != ("initial",)]
    # 0.18s window with 0.05s interval => at least 2 proactive resends.
    assert len(proactive) >= 2
    for identifier, opcode, payload, version in proactive:
        assert identifier == 7
        assert opcode == eap.WSC_OP_MSG
        assert payload == m2
        assert version == 1


def test_wait_for_aborts_promptly_on_stop_event(monkeypatch):
    """A long timeout must not block Stop -- stop_event should abort the
    wait almost immediately instead of running to `timeout` (2026-08-27
    user report: OMNI's Stop button did nothing during the WPS stage's
    60s M3 wait)."""
    monkeypatch.setattr(wps_module, "AsyncSniffer", _MockSniffer([], delay=5.0))
    stop_event = threading.Event()

    def trigger_stop():
        time.sleep(0.1)
        stop_event.set()

    threading.Thread(target=trigger_stop, daemon=True).start()
    start = time.monotonic()
    result = wps_module._wait_for(
        "wlan0", BSSID, CLIENT, lambda p: True, timeout=5.0, stop_event=stop_event,
    )
    elapsed = time.monotonic() - start

    assert result is None
    assert elapsed < 1.0


def test_send_until_m3_aborts_promptly_on_stop_event(monkeypatch):
    monkeypatch.setattr(wps_module, "_send_wsc_message", lambda *a, **k: None)
    monkeypatch.setattr(wps_module, "AsyncSniffer", _MockSniffer([], delay=5.0))
    stop_event = threading.Event()

    def trigger_stop():
        time.sleep(0.1)
        stop_event.set()

    threading.Thread(target=trigger_stop, daemon=True).start()
    start = time.monotonic()
    result = wps_module._send_until_m3(
        "wlan0", BSSID, CLIENT, b"\x02", identifier=7, timeout=60.0, stop_event=stop_event,
    )
    elapsed = time.monotonic() - start

    assert result is None
    assert elapsed < 1.0


def test_send_until_m3_stops_resending_once_m3_arrives(monkeypatch):
    """No further proactive resends once M3 has been received."""
    sent: list[tuple] = []

    def fake_send_wsc(iface, bssid, client, identifier, opcode, payload, version=1):
        sent.append((identifier, opcode, payload, version))

    monkeypatch.setattr(wps_module, "_send_wsc_message", fake_send_wsc)

    from atwa.wps import tlv
    m3_payload = tlv.encode_tlv(tlv.ATTR_MSG_TYPE, bytes([tlv.WPS_M3]))
    # Inject M3 after a short delay; the handler should stop the exchange.
    m3_pkt = _make_ap_eap_frame(client=CLIENT, opcode=eap.WSC_OP_MSG, payload=m3_payload)
    monkeypatch.setattr(wps_module, "AsyncSniffer", _MockSniffer([m3_pkt], delay=0.08))

    m2 = b"\x02"
    result = wps_module._send_until_m3(
        "wlan0", BSSID, CLIENT, m2, identifier=7,
        timeout=0.3, resend_interval=0.05, version=1,
        send_fn=lambda: sent.append(("initial",)),
    )

    assert result is not None
    # Only the initial send plus at most one timer fire before M3 arrived.
    proactive = [s for s in sent if s != ("initial",)]
    assert len(proactive) <= 2
