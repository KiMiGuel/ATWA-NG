"""PMKID extraction from EAPOL message 1.

Lives in eapol/ rather than attacks/ because it is pure EAPOL key-data
parsing: scan.py needs it opportunistically during a passive scan, and
having to reach into attacks/ for it inverted the layering.
"""

from __future__ import annotations

RSN_PMKID_SUITE = 16  # element ID inside the RSN KDE carrying the PMKID


def extract_pmkid(eapol_raw: bytes) -> bytes | None:
    """Pull the 16-byte PMKID from the RSN KDE of an EAPOL M1, or None.

    Scans for the KDE vendor IE (OUI 00:0f:ac, type 4) rather than
    indexing a fixed key-data offset, so it survives the 24-byte-MIC
    SHA-384 descriptor layout where that offset shifts.
    """
    marker = b"\xdd"
    idx = 0
    while True:
        idx = eapol_raw.find(marker, idx)
        if idx < 0 or idx + 2 >= len(eapol_raw):
            return None
        length = eapol_raw[idx + 1]
        kde = eapol_raw[idx + 2 : idx + 2 + length]
        if len(kde) >= 20 and kde[:4] == b"\x00\x0f\xac\x04":
            return kde[4:20]
        idx += 1