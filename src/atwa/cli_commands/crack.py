"""Cracking subcommands: John backend and vendored aircrack-ng backend."""

from __future__ import annotations

import sys
from pathlib import Path

from ..crack.convert import cap_to_22000
from ..crack.john import JohnCracker, JohnParseError, JohnUnavailableError
from ..storage import record_cracked_password
from . import CAPCRACK_BIN, _run_bounded


def _cmd_crack(args) -> int:
    hashfile = args.hashfile
    if hashfile.lower().endswith((".cap", ".pcap", ".pcapng")):
        hashfile = cap_to_22000(hashfile, hashfile + ".22000")
        print(f"converted to {hashfile}")
    try:
        results = JohnCracker().run_streaming(hashfile, args.wordlist, lambda line: print(line, end=""), {},
                                               rules=getattr(args, "rules", ""))
    except (JohnUnavailableError, JohnParseError) as exc:
        # Both messages are written FOR the operator ("john not found in
        # PATH", "0 hashes loaded -- not a wrong wordlist. Try aircrack-ng
        # instead.") -- john is an optional dependency, so dying with a
        # raw RuntimeError traceback was the wrong UX on a box without it.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for hash_id, password in results.items():
        print(f"{hash_id}: {password}")
        record_cracked_password(Path(args.hashfile).parent, "john", hash_id, password)
    if not results:
        print("No passwords recovered.")
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
    if args.frames and not args.mac:
        print("error: --frames requires --mac", file=sys.stderr)
        return 2
    from ..eapol.dumper import EapolDumper

    dumper = EapolDumper(args.capfile)
    frames = dumper.frames(mac=args.mac) if args.mac else dumper.frames()
    if not frames:
        print("no EAPOL-Key frames found")
        return 1
    # The original shelled out to eapol_dump.sh + tshark for an overview,
    # then per-frame nonce/MIC for the frame numbers given. Same output,
    # computed from the shared parser instead of tshark field expressions.
    print(f"{'Frame':>6}  {'Src MAC':<18} -> {'Dest MAC':<18} {'Msg':<4}")
    print("-" * 70)
    for r in frames:
        print(f"{r.index:>6}  {r.bssid:<18} -> {r.client:<18} "
              f"{('M' + str(r.message)) if r.message is not None else '--':<4}"
              f"  [{r.key_info_flags()}]")
    for n in args.frames:
        match = next((r for r in frames if r.index == n), None)
        if match is None:
            print(f"\nDetails for frame #{n}: not an EAPOL-Key frame in this capture")
            continue
        print(f"\nDetails for frame #{n}")
        print("-" * 70)
        print(f"  Message      : {('M' + str(match.message)) if match.message else '--'}")
        print(f"  Descriptor   : {match.descriptor_type}")
        print(f"  Key Info     : 0x{match.key_info:04x} ({match.key_info_flags()})")
        print(f"  Nonce        : {match.nonce_hex() or '(none)'}")
        print(f"  MIC          : {match.mic_hex() or '(none)'}")
    return 0
