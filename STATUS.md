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
scanning on a MacBook Air host. Landed so far, one bigger thing still
open:
- **Done (v2.2):** `get_driver()` now caches per-interface (was
  re-shelling `ethtool` on every call); `not type ctl` BPF filter now
  drops control frames before scapy dissects them.
- **Done (2026-08-31, post-v2.2):** `set_monitor_mode()` now calls
  `disable_power_save()` (`iw dev <iface> set power_save off`) right
  after bringing the interface up. Aggressive driver power-save on
  Realtek/MediaTek chipsets is a documented source of erratic RX
  latency and dropped frames — no reason to conserve power on an
  adapter actively capturing/injecting. Non-fatal if a driver doesn't
  expose the setting.
- **Researched, not built — the strongest remaining lever:** swapping
  scapy for a faster dissection library in `scan.py`'s hot path. Two
  real candidates now, not just one:
  - **pypacker** — ~24-50x faster than scapy in benchmarks, natively
    understands Radiotap/802.11, has explicit 802.11 test coverage.
  - **dpkt** — a second, independently-verified candidate (2026-08-31
    research dive): native `dpkt.radiotap.Radiotap(buf).data` support
    for 802.11, benchmarked even faster than pypacker in some tests
    (dpkt 12,431 p/s vs pypacker 17,938 p/s vs scapy 726 p/s in one
    comparative test; another source measured dpkt >100x faster than
    scapy on pure parsing throughput). Worth comparing against pypacker
    before picking one — same rewrite scope either way (`process_packet`,
    `security_profile`, `wps_profile`, `frames.py` helpers all currently
    built on scapy's named-field object model, neither library offers
    that).
  Both need real-hardware verification before landing (same caution
  class as the 2026-08-29 PyRIC revert below).
- **Researched, not built — TPACKET_V3 mmap ring buffers**
  (2026-08-31): memory-mapped `AF_PACKET` raw sockets with a shared
  kernel/userspace ring buffer, avoiding per-packet kernel→userspace
  copies. Real, well-documented Linux technique, genuinely not
  previously considered in this project. Bigger lift than the
  dpkt/pypacker swap — manual `socket`/`mmap`/`ctypes` work, no
  scapy-level shortcut exists for it.
- **AF_XDP** (zero-copy kernel-bypass capture) — the actual "next lever
  if pypacker/dpkt aren't enough" answer, confirmed via 2026-08-31
  research: no native Python binding exists, would need real C exposed
  via `ctypes`/`cffi`/`pybind11`. Judged unlikely to ever be needed —
  802.11 monitor-mode capture is RF-channel-bandwidth-bottlenecked
  (a few Mbps at most), not socket-throughput-bottlenecked at the scale
  AF_XDP is built to solve (multi-gigabit NIC line-rate capture). **No
  plan exists anywhere in this project's history to rewrite any
  existing module in C** — this would be new, narrowly-scoped code, not
  a rewrite, and is a low-priority "if all else fails" option.
- **`iw`/nl80211-netlink for radio.py (PyRIC/pyroute2)** — checked again
  2026-08-31, still not recommended. **PyRIC was actually tried in this
  exact project on 2026-08-29** (migrated `radio.py`'s channel/mode/MAC
  ops off `iw`/`ip` subprocess calls) and broke real 5GHz scanning on
  the actual hardware in use (mt76x0u/AWUS036ACHM): 60-70 networks found
  normally → only 1 on 5GHz. Suspected but *never confirmed* cause:
  PyRIC's `freqset()`/`chset()` uses the legacy HT-era
  `NL80211_ATTR_WIPHY_CHANNEL_TYPE` attribute instead of the modern
  chandef API (`NL80211_ATTR_CHANNEL_WIDTH`/`NL80211_ATTR_CENTER_FREQ1`).
  Reverted rather than debugged blind with no hardware to iterate
  against — root cause is still genuinely unresolved, not "PyRIC is
  broken," but nobody has gotten it working here. `pyroute2` was
  rejected without even trying — own docs call its nl80211 support
  "very initial state," same risk class. The `get_driver()` cache added
  this session already addresses part of what motivated trying PyRIC
  (repeated subprocess spawn cost), weakening the case for revisiting it.

  **⚠️ Verified fact, from this session's own research dive — do not
  re-doubt or re-litigate without new evidence:** three CVEs
  independently checked against real sources on 2026-08-31 and
  confirmed genuine (not hallucinated, despite pattern-matching as
  suspicious at first glance): **CVE-2025-27558** (FragAttacks
  evolution, mesh A-MSDU — affects 802.11s mesh specifically, not
  ATWA-NG's current attack surface), **CVE-2026-20494** (MediaTek WiFi
  OOB read — requires local System privilege already, info-leak/ASLR
  bypass, not a remote primitive), **CVE-2026-26048** (deauth/disassoc
  DoS from missing PMF — this is the formal CVE for the exact mechanism
  ATWA-NG's own deauth attack already exploits and is already
  PMF-aware-gated for). Also verified real but with caveats: package
  `pywifi-controls` exists on PyPI but is managed-mode-only client
  control (wrong fit for ATWA-NG's monitor-mode architecture); package
  `pylibpcap` exists but is unmaintained since Dec 2021 (use
  `pylibpcap3`/`python-libpcap`/`cypcap` instead if ever needed).

## Roadmap (open items, priority order)

- [ ] **Dual-Alfa / PINCER — verify + harden, NOT a from-scratch
      build.** Correction from an earlier stale claim in this same
      section: the native two-adapter attack logic (`attack_runner.py
      pincer()`) already fully exists — monitor-mode setup on both
      radios, channel-parking, a continuous EAPOL listener thread on
      the scan radio while looping real deauth rounds on the attack
      radio, PMF-aware, per-round client-targeting, proper teardown —
      and is wired end-to-end into a real GUI button. Checked the
      vendored v1 source directly: no pincer/dual-adapter code exists
      there at all, so "reimplement from the old v1 prototype" was
      never accurate. What's actually missing: zero automated test
      coverage (no file exists for `attack_runner.py`; a DI-mocking
      harness was explicitly deferred once already as disproportionate)
      and it has never been live-tested with two real Alfa adapters
      connected simultaneously.
- [ ] **dpkt vs. pypacker swap in scan.py** — the actual fix candidate
      for the CPU/fan complaint; see Performance section above for both
      options and the TPACKET_V3/AF_XDP alternatives.
- [ ] **5 queued WPA3/PMF-bypass research items** (from
      `research-2026-08-30.md` / vault `pending-investigations.md`):
      rogue-AP EAPOL corruption (higher confidence, PoC bytes exist),
      CSA spoofing (exploratory, no PoC), `downgrade_twin` (confirmed
      dead stub in `secure.py`), Dragonblood SAE side-channel (bigger,
      novel build), OWE transition-mode downgrade.
- [x] Color-theme/logo integration — substantially complete as of
      2026-08-27 (see vault `decisions.md`). Re-open only if new
      brand-asset work is explicitly requested.
- [x] `AGENTS.md`/`CLAUDE.md` stale-content audit (2026-08-31) — done,
      4 contradictions fixed (native-architecture Objective line,
      publish-decision roadmap item, branding roadmap item, capture-path
      rule).
- [x] `wps-recon` CLI native port (2026-08-31) — done, no longer shells
      out to the vendored `wash` binary; uses `scan.py`/
      `secure.wps_profile()`'s existing native beacon parsing instead.
