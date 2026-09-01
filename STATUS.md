# ATWA-NG — Status (as of 2026-08-31)

Rewritten fresh on 2026-08-31 (user request — the previous version had
grown stale, last touched 2026-08-27 while `CHECKPOINT.md` kept
advancing, causing real confusion between the two files). This is a
current-state snapshot, not a running log — for session-by-session
history, see `CHECKPOINT.md` (recent) and `NOTES_ARCHIVE.txt` (everything
before 2026-08-31, including this file's own full prior content).

## What ATWA-NG is, right now

Native Python WiFi security auditing tool, package `atwa`. Current
released version: **v2.2** (github.com/KiMiGuel/ATWA-NG, tagged
releases). Scanning, monitor-mode control, and packet injection are
**fully native — zero vendored-binary fallback**: `airodump-ng` and
`aireplay-ng` were both deliberately, completely cut over (Phase 6b/6c,
2026-08-27) with the old code paths deleted, not flagged off. The only
remaining vendored/wrapped components are **cracking backends** (John
the Ripper jumbo — primary; `aircrack-ng` — optional alternate) and
cap/pcap-format utilities (`hcxpcapngtool`, `wpapcap2john`) — this is a
deliberate, permanent project policy, not a gap.

## Attack surface (native, implemented)

- **OMNI / Smart** — adaptive per-target chain: profile → PMKID →
  WPS → handshake capture → online guess → crack. Smart short-circuits
  on first success; OMNI runs the full chain.
- **PMKID** (clientless) — native scapy, PMF-aware.
- **Handshake capture** — native EAPOL sniff, AUTHORIZED-vs-CHALLENGE
  verification gate, both feed the crack stage.
- **WPS** — Null-PIN, Pixie-Dust, Bruteforce (destination-MAC-validated,
  proactive M2 resend, lockout-aware).
- **WEP** — fake-auth + ARP replay + native PTW key recovery; Caffe
  Latte for client-only targets; chopchop is disabled natively (its
  ICV-correction math doesn't work, confirmed offline) and instead
  drives the vendored `aireplay-ng -4` binary directly.
- **Evil Twin** — real rogue AP + captive portal, PMF-aware
  client-targeted deauth toward it.
- **Online password guess** — live per-password 4-way handshake
  attempts against the real AP.
- **PINCER (dual-radio)** — GUI button and wiring exist (greyed out
  without two Alfa adapters detected), **but the underlying native
  two-adapter attack logic is still the old v1 prototype, known buggy**
  — this is the one flagship feature that is not actually done yet. See
  Roadmap below.

## Known-good vs. not-live-tested

Live-witnessed end-to-end on real hardware (own gear, authorized):
64-frame deauth bursts, AUTHORIZED handshake capture + crack-ready
22000 conversion, PMF correctly blocking deauth-based capture,
NetworkManager/wpa_supplicant interference fixed via airmon-ng-style
process kill.

**Not yet live-tested** (unit/lint-clean, no real-hardware run yet):
- The 2026-08-31 OMNI/WPS `AsyncSniffer` crash fix (was breaking every
  OMNI run at the WPS stage, not just WEP targets — root cause and fix
  are solid, just not re-run against a real AP since).
- The 2026-08-31 conservative BPF filter (`not type ctl`) added to both
  scan loops — compiles correctly, logic it preserves is unchanged, but
  not confirmed against a real busy channel yet.
- WPA ONLINE stage's real M2→M3 exchange against a live AP.

## Performance / CPU

User-reported real issue: noticeable CPU load and fan noise during
scanning on a MacBook Air host. Two things done so far, one bigger thing
still open:
- **Done (v2.2):** `get_driver()` now caches per-interface (was
  re-shelling `ethtool` on every call); `not type ctl` BPF filter now
  drops control frames before scapy dissects them.
- **Researched, not built:** swapping scapy for **pypacker** in
  `scan.py`'s dissection hot path — benchmarked ~24x faster lazy
  dissection, natively understands Radiotap/802.11. This is the
  strongest remaining lever and the most likely actual fix for the
  fan/CPU complaint; scapy's dissection cost, not I/O, is the suspected
  root cause. Not yet built — touches the live capture path, needs
  real-hardware verification before landing (same caution class as the
  2026-08-29 PyRIC revert).
- **No plan exists anywhere in this project's history to rewrite any
  module in C.** If pypacker alone isn't enough, the next lever would be
  a small Cython/C-extension for just the dissection hot loop — not a
  rewrite of any existing module.

## Roadmap (open items, unchanged priority order)

- [ ] **Dual-Alfa / PINCER native reimplementation** — the flagship
      two-adapter attack currently only has a GUI stub; real logic is
      still the buggy old v1 prototype.
- [ ] **pypacker swap in scan.py** — the actual fix candidate for the
      CPU/fan complaint above.
- [ ] **5 queued WPA3/PMF-bypass research items** (from
      `research-2026-08-30.md` / vault `pending-investigations.md`):
      rogue-AP EAPOL corruption (higher confidence, PoC bytes exist),
      CSA spoofing (exploratory, no PoC), `downgrade_twin` (confirmed
      dead stub in `secure.py`), Dragonblood SAE side-channel (bigger,
      novel build), OWE transition-mode downgrade.
- [ ] Color-theme/logo integration — **substantially complete already**
      as of 2026-08-27 (see vault `decisions.md`); this line is kept
      only in case further real brand-asset work is explicitly
      requested, not because nothing has happened yet.

## Housekeeping notes

`AGENTS.md`/`CLAUDE.md` is being re-audited separately (2026-08-31,
same pass as this rewrite) for a few confirmed stale/contradictory
lines — see that discussion rather than this file for the outcome.
