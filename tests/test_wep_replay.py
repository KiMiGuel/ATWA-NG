"""attacks/wep.replay_arp: low_rate forces a fresh RadioTap rate instead
of replaying the captured frame's own (RX) RadioTap header."""
from __future__ import annotations

from scapy.layers.dot11 import Dot11, RadioTap

import atwa.attacks.wep as wep_module


def _fake_captured_frame():
    return RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff")


def test_replay_arp_low_rate_forces_radiotap_rate(monkeypatch):
    sent = []
    monkeypatch.setattr(wep_module, "sendp", lambda pkt, **kw: sent.append(pkt))

    wep_module.replay_arp("wlan0mon", _fake_captured_frame(), count=1, low_rate=True)

    assert sent[0].getlayer("RadioTap").Rate == 4  # 2 Mbps in 500kbps units


def test_replay_arp_default_leaves_captured_radiotap(monkeypatch):
    sent = []
    monkeypatch.setattr(wep_module, "sendp", lambda pkt, **kw: sent.append(pkt))
    original = _fake_captured_frame()

    wep_module.replay_arp("wlan0mon", original, count=1)

    assert sent[0] is original
