"""EAPOL access for dissect.Frame.

The scan hot path works on raw bytes rather than Scapy packets, so
dissect.Frame.body is the input here while attacks/pmkid.py and the GUI
hand Scapy packets straight to eapol.utils. Both routes converge on one
parser in utils.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import utils

if TYPE_CHECKING:
    from ..frames.dissect import Frame

_LLC_SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"  # 802.2 LLC/SNAP, ethertype 0x888E (802.1X)


def eapol_body(frame: Frame) -> bytes | None:
    """The EAPOL PDU of a data frame's body, or None.

    Over-the-air EAPOL sits behind an 8-byte LLC/SNAP header; the
    fixtures this project's tests build attach the PDU straight to the
    MAC header, so both shapes are accepted.
    """
    body = frame.body
    if body[:8] == _LLC_SNAP_EAPOL:
        return body[8:]
    if len(body) >= 4 and body[0] in (1, 2, 3) and body[1] in (0, 1, 2, 3):
        return body
    return None


def is_eapol(frame: Frame) -> bool:
    """True if the frame carries a well-formed EAPOL-Key frame."""
    return utils.is_eapol(eapol_body(frame) or b"")


def eapol_key_info(frame: Frame) -> tuple[bool, bool] | None:
    """(mic_set, ack_set) from a WPA key EAPOL frame, else None."""
    return utils.eapol_key_info(eapol_body(frame) or b"")


def parse(frame: Frame) -> utils.EapolKey | None:
    """The full parsed EAPOL-Key frame, or None."""
    return utils.parse_eapol_key(eapol_body(frame) or b"")


def message_number(frame: Frame) -> int | None:
    """Handshake message number 1-4 for this frame, else None."""
    return utils.message_number(eapol_body(frame) or b"")