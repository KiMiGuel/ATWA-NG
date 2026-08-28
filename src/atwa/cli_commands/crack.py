"""Cracking subcommands: John backend and vendored aircrack-ng backend."""

from __future__ import annotations

import sys

from ..crack.convert import cap_to_22000
from ..crack.john import JohnCracker
from . import CAPCRACK_BIN, EAPOLDUMP_BIN, _run_bounded


def _cmd_crack(args) -> int:
    hashfile = args.hashfile
    if hashfile.endswith((".cap", ".pcap", ".pcapng")):
        hashfile = cap_to_22000(hashfile, hashfile + ".22000")
        print(f"converted to {hashfile}")
    results = JohnCracker().crack(hashfile, args.wordlist)
    for hash_id, password in results.items():
        print(f"{hash_id}: {password}")
    return 0 if results else 1


def _cmd_crack_cap(args) -> int:
    """WPA/WEP cracking via a locally-compiled cracking engine — an
    additional backend alongside John (the existing `crack` command),
    explicitly not hashcat per the user's direction."""
    if not CAPCRACK_BIN.exists():
        print(f"error: {CAPCRACK_BIN} not built", file=sys.stderr)
        return 1
    cmd = [str(CAPCRACK_BIN), "-w", args.wordlist]
    if args.bssid:
        cmd += ["-b", args.bssid]
    cmd.append(args.capfile)
    rc, out, err = _run_bounded(cmd, timeout=args.timeout)
    print(out)
    if rc != 0 and err:
        print(err, file=sys.stderr)
    return rc


def _cmd_verify_handshake(args) -> int:
    cmd = [str(EAPOLDUMP_BIN), args.capfile]
    if args.mac:
        cmd.append(args.mac)
        cmd += [str(n) for n in args.frames]
    rc, out, err = _run_bounded(cmd, timeout=30.0)
    print(out)
    if rc != 0 and err:
        print(err, file=sys.stderr)
    return rc
