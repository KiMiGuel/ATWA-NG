# ATWA-NG Vendor Binary Inventory

This document maps every external binary that `src/atwa/` currently spawns,
notes whether it is a **vendored** binary (shipped under `vendor/`) or a
**system** dependency, and rates the difficulty of replacing it with native
Python. It is the starting point for Phase 6 of the refactor plan.

**Project-wide wrapper policy (confirmed 2026-08-27, extended 2026-09-04):**
the acceptable wrappers in ATWA-NG are cracking backends (John,
`aircrack-ng`), cap/pcap-format tools (`hcxpcapngtool`, `hcxhashtool`,
`pcapfix`, `mergecap`), and `eapol_dump.sh` (see below) — everything else
(scanning, injection, WPS, monitor-mode control) must be native Python,
with no legacy-fallback flags. **Scanning, injection, and WPS (both
attack and recon) are all done** — the last wrapper outside these
exceptions (`wash`, for `wps-recon`) was closed out 2026-08-31.

### `eapol_dump.sh` (accepted exception, 2026-09-04)

`vendor/eapol_dump/eapol_dump.sh` (third-party, "(c) 2016 __franky") is
spawned by `atwa verify-handshake` (`src/atwa/cli_commands/crack.py:42`,
`EAPOLDUMP_BIN` in `cli_commands/__init__.py:38`) to dump per-frame
EAPOL nonce/MIC values from a `.cap` file for manual inspection — a
diagnostic/inspection tool, not a scanning, injection, or attack
primitive, so it sits outside the spirit of the native-only mandate
(which targets the actual attack surface) the same way `hcxpcapngtool`/
`pcapfix` do. Flagged as an undisclosed gap during the 2026-09-02 live
test (not listed here, didn't cleanly fit either pre-existing
exception category); resolved by extending the exception list above
rather than replacing it with a native EAPOL dumper. Kept as-is —
works correctly, low-risk, one-off diagnostic use only.

## Vendor roles

| Vendor directory | What ATWA-NG uses it for | Long-term plan |
|---|---|---|
| `vendor/aircrack-ng` | `aircrack-ng` (WPA/WEP cracking) only — `airodump-ng` (removed 2026-08-27) and `aireplay-ng` (removed 2026-08-27) are **no longer used anywhere** | Keep `aircrack-ng` as an **optional cracking backend** alongside John — the one permanent exception to the native-only policy. |
| `vendor/eapol_dump` | `eapol_dump.sh` — per-frame EAPOL nonce/MIC dump for `atwa verify-handshake` | Accepted exception (2026-09-04) — diagnostic/inspection tool, not attack surface. Leave as-is. |
| `vendor/n2-ng-v1-research` | Research notes only (WPA3, PMKID, WPS, evil-twin, password-cracking papers) | No code to port; use as design reference. Remove/update any docs that still say "n2-ng". |
| `vendor/n2-ng-v1-src` | Legacy v1 Python source (`main.py`, `scanner.py`, `omni.py`, `capture.py`, `display.py`, `utils.py`) | Mine for reusable helpers (CSV parsing, capture-path helpers, security profiling), rewrite into `src/atwa/` modules, ignore duplicates. |
| `vendor/reaver` | Historical reference only now — `reaver`'s WPS state machine/PIN exchange was ported into native Python (`src/atwa/attacks/wps.py`, pixie-dust/bruteforce/M2→M3 fix, developed 2026-08-27 onward) and `wash`'s recon role was closed out 2026-08-31 (`wps-recon` now uses `scan.py`/`secure.wps_profile()`). No remaining call sites spawn anything from this directory. | Kept vendored for reference/comparison only; not a build dependency for anything atwa currently runs. |

## Status: scanning is fully native (2026-08-27)

`airodump-ng` has been **removed entirely** from ATWA-NG — not deprecated,
not behind a flag, deleted. `scan_engine.py`, `scan_worker.py`, and
`scanner.py` (the three modules that spawned it) no longer exist.

- **`atwa scan` (CLI)** now calls `scan.scan()` directly (native scapy
  `AsyncSniffer` + `ChannelHopper`), printing `AccessPoint` fields
  (`security`, `signal`, `beacon_count`, `ssid`) instead of the old CSV
  `Network` fields (`privacy`/`cipher`/`auth`/`beacons`/`essid`).
- **GUI live scan** was already native before this pass — `App._start_scan`
  has always driven `scan.process_packet()` directly, never `airodump-ng`.
- **GUI channel-lock capture** (`App._start_lock_capture`) now uses
  `lock_capture.LockCapture`: a native `AsyncSniffer` filtered to the
  locked BSSID, writing matching frames to a `.pcap` via `PcapWriter`. The
  CSV half of the old output was checked and confirmed unused by anything
  downstream, so it isn't reproduced.
- `AccessPoint` (`scan.py`) gained `beacon_count`, `first_seen`,
  `last_seen` to close the only real field gap vs. the old CSV output.
  `iv_count` was **not** ported — it's WEP-specific and already tracked
  correctly by `wep.py`'s `PTWVoteTable` during an actual WEP attack;
  carrying it on every `AccessPoint` was an artifact of airodump's
  single-CSV format, not a real requirement.

## Status: injection is fully native, `aireplay-ng` removed (2026-08-27)

`aireplay-ng` has been **removed entirely** — same full-cutover treatment
as `airodump-ng`, no legacy flag.

- **`deauth-inject` CLI subcommand deleted outright** rather than ported —
  it was a pure duplicate of the already-native `deauth` subcommand (same
  feature, vendored backend vs. `attacks/deauth.py`). No reason to carry
  two commands doing the same thing.
- **`injection-test` CLI subcommand rewritten natively**, ported from
  `aireplay-ng`'s actual `--test`/`-9` algorithm
  (`do_attack_test()` in `aireplay-ng.c`), not reinvented: a broadcast
  probe-request discovery phase (find any AP in range, unless `--bssid`
  given), then a directed ping phase against that AP — for each of
  `--count` attempts (default 30, matching aireplay-ng's `REQUESTS`),
  send a probe request + RTS + null-data + auth-request and count any of
  {probe response, CTS, ACK, auth response} addressed back to that
  attempt's random source MAC as a successful ping. New module:
  `src/atwa/injection_test.py`.
- New frame primitives in `frames.py`: `craft_probe_req()`, `craft_rts()`,
  `craft_null_data()` — ported from aireplay-ng's `PROBE_REQ`/`RTS`/
  `NULL_DATA` byte constants. `craft_auth()` (already existed, used by
  PMKID) covers the auth-request part.
- `cli_commands/__init__.py`'s `INJECTOR_BIN` constant removed.

## Binary call-site inventory

### Vendored binaries

| Binary | Source file:line | Purpose | Parsed output / success signal | Native-replacement difficulty | Priority |
|---|---|---|---|---|---|
| `aircrack-ng` | `src/atwa/cli_commands/crack.py:23` | Crack `.cap` directly (`crack-cap`) | Return code + stdout | Keep as option | N/A — stays optional backend |
| `aircrack-ng` | `src/atwa/crack/aircrack.py:67,80` | GUI cracking backend (`AirCracker`) | stdout parsed for key | Keep as option | N/A — stays optional backend |
| ~~`wash`~~ | ~~`src/atwa/cli_commands/scan.py`~~ | ~~WPS recon (`wps-recon`)~~ | — | Done (2026-08-31) | Closed — `wps-recon` now native |
| `eapol_dump.sh` | `src/atwa/cli_commands/crack.py:42` | Per-frame EAPOL nonce/MIC dump (`verify-handshake`) | stdout, human-inspected | N/A — accepted exception | N/A — diagnostic tool, not attack surface |

### System / third-party binaries

These are not under `vendor/`, but they are still external tool wrappers. They
are listed for completeness; the Phase-6 mandate focuses on the vendored ones.

| Binary | Source file:line | Purpose | Notes |
|---|---|---|---|
| `iw` / `ip` / `ethtool` | `src/atwa/radio.py` | Monitor mode, MAC, channel, antenna fix | Keep as system primitives (native netlink is future work) |
| `hostapd` | `src/atwa/attacks/eviltwin.py:300` | Rogue AP for Evil Twin | System package; porting is out of scope for now |
| `dnsmasq` | `src/atwa/attacks/eviltwin.py:310` | DHCP/DNS for Evil Twin | System package; out of scope |
| `wpa_supplicant` | `src/atwa/wps/oneshot.py` | Managed-mode WPS (`wps-oneshot`) | Already native Python orchestration around system binary; optional to port later |
| `hcxpcapngtool` / `hcxhashtool` | `src/atwa/crack/convert.py` | Convert captures/hash formats | Generic utilities; keep as dependencies |
| `pcapfix` / `mergecap` | `src/atwa/crack/convert.py` | Repair/merge captures | Generic utilities; keep as dependencies |
| `john` | `src/atwa/crack/john.py` | John the Ripper cracking | Primary cracking backend; keep |
| `airmon-ng` | referenced in docs/legacy, no direct spawn | (no direct call in current source) | — |

## Native replacement roadmap

1. **Scanning (`airodump-ng`)** — ✅ **done (2026-08-27).**

2. **Injection / deauth (`aireplay-ng`)** — ✅ **done (2026-08-27).** See
   "Status: injection is fully native" above.

3. **Monitor-mode control** — replace any `airmon-ng` wrapper calls (currently
   none in source) with direct `iw`/`ip` sequences in `radio.py`. Already
   mostly native.

4. **WPS (`wash` / `reaver`)** — ✅ **done.** Attack logic (pixie-dust,
   PIN bruteforce, M2→M3 exchange) was native from 2026-08-27 onward in
   `src/atwa/attacks/wps.py`; the recon half (`wash`) was closed out
   2026-08-31 by routing `wps-recon` through `scan.py`/
   `secure.wps_profile()`'s existing native beacon parsing instead of
   spawning the binary.

5. **Cracking backend** — `aircrack-ng` remains an optional backend alongside
   John; no replacement needed. This is the one deliberate, permanent
   exception to the native-only mandate.

## Aircrack-ng / John option status

Confirmed: the GUI crack dialog (`src/atwa/gui/crack_dialog.py`) and the App
(`src/atwa/gui/app.py:_crack_with_john` / `_crack_with_aircrack`) both support
selecting `john` or `aircrack-ng`. The CLI `crack` command uses John; the
`crack-cap` command uses the vendored `aircrack-ng`. This satisfies the
requirement that aircrack-ng stays available as a cracking option.
