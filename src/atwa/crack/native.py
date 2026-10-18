"""Native WPA/WPA2-PSK cracker — zero external dependencies.

Default cracking backend for ATWA-NG. Reuses the existing WPA key-derivation
primitives in ``wpa/crypto.py`` (PMK/PTK/MIC) and the EAPOL parser in
``eapol/utils.py``; reads captures with scapy (already a core dependency).

Scope matches ``wpa/crypto.py``: CCMP/AES (Key Descriptor Version 2,
HMAC-SHA1-128 MIC) only. TKIP and Suite-B/SHA-384 (24-byte MIC) are out
of scope and are skipped rather than mis-cracked.

Performance: pure-Python PBKDF2 via hashlib (C-backed) is ~10-100x slower
than John/aircrack-ng. This backend is the always-available default; the
optional fast backends remain preferred when installed.
"""

from __future__ import annotations

import time

# Importing these scapy submodules registers their dissectors for the
# link types ATWA captures use (105 = raw 802.11); without them packets
# come back as Raw and the 802.11/EAPOL layers are never decoded.
from scapy.layers import dot11 as _scapy_dot11  # noqa: F401
from scapy.layers import eap as _scapy_eap  # noqa: F401
from scapy.utils import PcapReader


# Imported lazily via importlib to avoid a static crack -> eapol import edge,
# which would close the crack -> eapol -> capture -> crack cycle flagged by
# tests/test_package_layering.py. eapol.utils is the single parser impl.
def _eapol_utils():
    import importlib
    return importlib.import_module("atwa.eapol.utils")
from ..storage import bssid_from_path
from ..wpa.crypto import compute_mic, derive_pmk, derive_ptk

# CCMP MIC width (HMAC-SHA1-128). Out of scope: TKIP (MD5) and Suite-B (24).
_MIC_LEN = 16
_MIC_OFFSET = 81


class NativeCrackerError(RuntimeError):
    """Base for native-cracker failures."""


class NativeNoHandshakeError(NativeCrackerError):
    """No usable 4-way handshake (M1+M2 or M2+M3) found in the capture."""


class NativeNoEssidError(NativeCrackerError):
    """ESSID could not be resolved from the capture or the caller."""


def _open_capture(path: str):
    """Return a PcapReader for pcap or pcapng. Raises on open failure."""
    return PcapReader(path)


def _macs_from_frame(pkt) -> tuple[str, str, str] | None:
    """Return (addr1, addr2, addr3) lowercased, or None if not 802.11."""
    try:
        from scapy.layers.dot11 import Dot11

        if not pkt.haslayer(Dot11):
            return None
        d = pkt[Dot11]
        return (str(d.addr1).lower(), str(d.addr2).lower(), str(d.addr3).lower())
    except Exception:  # noqa: BLE001
        return None


def _eapol_raw(pkt):
    """Return the EAPOL PDU bytes from a packet, or None."""
    try:
        if pkt.haslayer("EAPOL"):
            return bytes(pkt["EAPOL"])
    except Exception:  # noqa: BLE001, S110
        pass
    try:
        from scapy.layers.eap import EAPOL

        if pkt.haslayer(EAPOL):
            return bytes(pkt[EAPOL])
    except Exception:  # noqa: BLE001, S110
        pass
    return None


def _is_to_ds(pkt) -> bool:
    try:
        from scapy.layers.dot11 import Dot11

        if pkt.haslayer(Dot11):
            fc = pkt[Dot11].FCfield
            return bool(getattr(fc, "to_DS", False))
    except Exception:  # noqa: BLE001
        return False
    return False


def _extract_handshake(path: str, bssid_filter: str | None):
    """Walk a capture and return (aa, spa, anonce, snonce, mic, frame_zeroed, bssid)
    for the first complete 4-way handshake, or None."""

    anonce = None
    # candidate M2/M4 frames: (snonce, mic, raw_zeroed, aa, spa)
    candidates: list[tuple[bytes, bytes, bytes, str, str]] = []
    aa_found = None

    try:
        reader = _open_capture(path)
    except Exception:  # noqa: BLE001
        return None

    with reader:
        for pkt in reader:
            macs = _macs_from_frame(pkt)
            if macs is None:
                continue
            a1, a2, a3 = macs
            raw = _eapol_raw(pkt)
            if raw is None:
                continue
            eu = _eapol_utils()
            key = eu.parse_eapol_key(raw)
            if key is None:
                continue
            msg = eu.message_number(raw)
            if msg is None:
                continue
            # Determine AP/client MACs from ToDS/FromDS.
            to_ds = _is_to_ds(pkt)
            bssid = a3  # addr3 is BSSID in most data frames
            if bssid_filter and bssid != bssid_filter.lower():
                # also try addr2/addr1
                if bssid_filter.lower() not in (a1, a2, a3):
                    continue
                bssid = bssid_filter.lower()
            aa = bssid
            spa = a2 if to_ds else a1
            if aa == spa:
                # fallback: addr2 is transmitter
                spa = a2 if a2 != aa else a1

            nonce = eu.extract_nonce(raw)
            if msg in (1, 3) and nonce is not None and anonce is None:
                anonce = nonce
                aa_found = aa
            if msg in (2, 4) and key.mic_set:
                # CCMP only: 16-byte MIC at fixed offset 81. Read raw bytes
                # directly rather than extract_mic(), whose width heuristic
                # can misclassify frames that carry key data.
                mic = raw[_MIC_OFFSET:_MIC_OFFSET + _MIC_LEN]
                if mic and mic != b"\x00" * _MIC_LEN and key.key_version in (1, 2):
                    frame_zeroed = bytearray(raw)
                    frame_zeroed[_MIC_OFFSET:_MIC_OFFSET + _MIC_LEN] = b"\x00" * _MIC_LEN
                    snonce = nonce if nonce is not None else key.nonce
                    if not snonce or snonce == bytes(32):
                        snonce = key.nonce
                    candidates.append((snonce, mic, bytes(frame_zeroed), aa, spa))

    if anonce is None or not candidates:
        return None
    # Use the first candidate (M2 preferred naturally as it appears first).
    snonce, mic, frame_zeroed_bytes, aa, spa = candidates[0]
    if aa_found is not None:
        aa = aa_found
    return aa, spa, anonce, snonce, mic, frame_zeroed_bytes


def _extract_essid(path: str, bssid: str | None) -> str | None:
    """Resolve ESSID: beacon scan in the capture. Returns None if not found."""
    try:
        from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
    except Exception:  # noqa: BLE001
        return None

    bssid_l = (bssid or "").lower()
    try:
        reader = _open_capture(path)
    except Exception:  # noqa: BLE001
        return None
    with reader:
        for pkt in reader:
            try:
                if not pkt.haslayer(Dot11Beacon):
                    continue
            except Exception:  # noqa: BLE001, S112
                continue
            try:
                d = pkt[Dot11]
            except Exception:  # noqa: BLE001, S112
                continue
            if bssid_l and str(d.addr3).lower() != bssid_l:
                continue
            # Walk IEs for SSID (ID 0).
            try:
                el = pkt[Dot11Elt]
            except Exception:  # noqa: BLE001
                el = None
            while el is not None:
                try:
                    if getattr(el, "ID", None) == 0:
                        info = getattr(el, "info", b"")
                        if isinstance(info, (bytes, bytearray)):
                            ssid = bytes(info).decode("utf-8", errors="replace")
                        else:
                            ssid = str(info)
                        if ssid:
                            return ssid
                except Exception:  # noqa: BLE001, S110
                    pass
                # advance
                nxt = getattr(el, "payload", None)
                if nxt is not None and hasattr(nxt, "ID"):
                    el = nxt
                else:
                    break
    return None


class NativeCracker:
    """Native WPA/WPA2-PSK cracker (CCMP, zero external deps)."""

    def __init__(self, bssid: str | None = None, essid: str | None = None):
        self.bssid = bssid
        self.essid = essid

    def _resolve(self, hashfile: str):
        bssid = self.bssid
        if bssid is None:
            bssid = bssid_from_path(hashfile)
        handshake = _extract_handshake(hashfile, bssid)
        if handshake is None:
            raise NativeNoHandshakeError(
                "no usable 4-way handshake found in capture "
                "(need M1+M2 or M2+M3 with a valid MIC)"
            )
        aa, spa, anonce, snonce, mic, frame_zeroed = handshake
        if bssid is None:
            bssid = aa
        essid = self.essid
        if not essid:
            essid = _extract_essid(hashfile, aa)
        if not essid:
            raise NativeNoEssidError(
                "ESSID could not be resolved from the capture (no beacon present) "
                "and was not provided; pass essid= or use hcxpcapngtool"
            )
        return aa, spa, anonce, snonce, mic, frame_zeroed, essid

    def crack(self, hashfile: str, wordlist: str, timeout: float = 3600.0) -> dict[str, str]:
        aa, spa, anonce, snonce, mic, frame_zeroed, essid = self._resolve(hashfile)

        deadline = time.monotonic() + timeout if timeout and timeout > 0 else None
        found: dict[str, str] = {}
        with open(wordlist, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if deadline is not None and time.monotonic() > deadline:
                    break
                word = line.rstrip("\r\n")
                if not word:
                    continue
                try:
                    pmk = derive_pmk(word, essid)
                except ValueError:
                    continue
                ptk = derive_ptk(pmk, bytes.fromhex(aa.replace(":", "")),
                                 bytes.fromhex(spa.replace(":", "")), anonce, snonce)
                kck = ptk[:16]
                if compute_mic(kck, frame_zeroed) == mic:
                    found[aa] = word
                    break
        return found

    def run_streaming(self, capfile: str, wordlist: str, on_line=None, proc_holder=None) -> dict[str, str]:
        """Streaming counterpart (best-effort progress); same result as crack()."""
        aa, spa, anonce, snonce, mic, frame_zeroed, essid = self._resolve(capfile)
        found: dict[str, str] = {}
        aa_bytes = bytes.fromhex(aa.replace(":", ""))
        spa_bytes = bytes.fromhex(spa.replace(":", ""))
        count = 0
        with open(wordlist, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                word = line.rstrip("\r\n")
                if not word:
                    continue
                count += 1
                try:
                    pmk = derive_pmk(word, essid)
                except ValueError:
                    continue
                ptk = derive_ptk(pmk, aa_bytes, spa_bytes, anonce, snonce)
                if compute_mic(ptk[:16], frame_zeroed) == mic:
                    found[aa] = word
                    if on_line:
                        on_line(f"KEY FOUND! [ {word} ]\n")
                    break
                if on_line and count % 1000 == 0:
                    on_line(f"tested {count} passwords...\n")
        if not found and on_line:
            on_line("No password recovered.\n")
        return found