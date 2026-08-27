# ATWA-NG Vendor Binary Inventory

This document maps every external binary that `src/atwa/` currently spawns,
notes whether it is a **vendored** binary (shipped under `vendor/`) or a
**system** dependency, and rates the difficulty of replacing it with native
Python. It is the starting point for Phase 6 of the refactor plan.

**Project-wide wrapper policy (confirmed 2026-08-27):** the only acceptable
wrappers in ATWA-NG are cracking backends (John, `aircrack-ng`) and
cap/pcap-format tools (`hcxpcapngtool`, `hcxhashtool`, `pcapfix`,
`mergecap`) — everything else (scanning, injection, WPS, monitor-mode
control) must be native Python, with no legacy-fallback flags. Scanning
and injection are done; WPS is the remaining sub-part.

## Vendor roles

| Vendor directory | What ATWA-NG uses it for | Long-term plan |
|---|---|---|
| `vendor/aircrack-ng` | `aircrack-ng` (WPA/WEP cracking) only — `airodump-ng` (removed 2026-08-27) and `aireplay-ng` (removed 2026-08-27) are **no longer used anywhere** | Keep `aircrack-ng` as an **optional cracking backend** alongside John — the one permanent exception to the native-only policy. |
| `vendor/n2-ng-v1-research` | Research notes only (WPA3, PMKID, WPS, evil-twin, password-cracking papers) | No code to port; use as design reference. Remove/update any docs that still say "n2-ng". |
| `vendor/n2-ng-v1-src` | Legacy v1 Python source (`main.py`, `scanner.py`, `omni.py`, `capture.py`, `display.py`, `utils.py`) | Mine for reusable helpers (CSV parsing, capture-path helpers, security profiling), rewrite into `src/atwa/` modules, ignore duplicates. |
| `vendor/reaver` | `wash` / `reaver` binaries for WPS recon and attack | Do not wrap. Port the WPS state machine + PIN exchange from C source into native Python (`src/atwa/attacks/wps_native.py`). Full cutover once ported, no legacy flag — matching the scanning/injection precedent. |

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
| `wash` | `src/atwa/cli_commands/scan.py` | WPS recon (`wps-recon`) | Prints AP table text | Medium | Next up (Phase 6e) |

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

4. **WPS (`wash` / `reaver`)** — hardest, and the only remaining wrapper
   outside the cracking-backend exception. Port the minimal WPS state
   machine from `vendor/reaver/src/wps/` and `exchange.c` into
   `src/atwa/attacks/wps_native.py`. Full cutover once ported — no legacy
   flag, matching the scanning/injection precedent.

5. **Cracking backend** — `aircrack-ng` remains an optional backend alongside
   John; no replacement needed. This is the one deliberate, permanent
   exception to the native-only mandate.

## Aircrack-ng / John option status

Confirmed: the GUI crack dialog (`src/atwa/gui/crack_dialog.py`) and the App
(`src/atwa/gui/app.py:_crack_with_john` / `_crack_with_aircrack`) both support
selecting `john` or `aircrack-ng`. The CLI `crack` command uses John; the
`crack-cap` command uses the vendored `aircrack-ng`. This satisfies the
requirement that aircrack-ng stays available as a cracking option.
