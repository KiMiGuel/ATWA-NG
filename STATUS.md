# ATWA-NG — Status

Hybrid rebuild: real aircrack-ng suite source (vendored + compiled locally,
not the distro package) + native Python orchestration/parsing logic
(ported, not copy-pasted) + native-Python attack code where that's already
solid and tested (WPS pixie-dust, PMKID, crypto, WEP PTW, GUI).
"Source not wrappers": the aircrack-ng binaries in use are built from
vendored source sitting right here, not `apt install`.

## Update — 2026-08-27, test-suite repair via mcp-debugpy + WPA online MIC re-verified

Debugged live through the mcp-debugpy MCP server (`dap_launch` /
`dap_locals` / `dap_continue` against the real `atwa` CLI and the failing
test under `debugpy`), then repaired the suite.

- Root cause: the earlier mypy pass changed `attacks/online.py`'s
  `_build_m2()` to return a `Packet` instead of `bytes` without updating
  `tests/test_online.py` (suite deliberately not run that pass). The test
  then passed a Packet into the `EAPOL()` dissector →
  `TypeError: a bytes-like object is required, not 'EAPOL'`, a
  collection-time crash that also masked 56 other tests (only 69 of 125
  were running).
- Fix (test-only, production untouched — returning a `Packet` for
  `sendp()` is correct): three `EAPOL(frame)` calls became
  `EAPOL(bytes(frame))` at `tests/test_online.py:29,53-54`.
- Verified through the debugger before editing: `_build_m2` builds the
  EAPOL-Key M2 correctly (SNonce, RSNE, replay counter, MIC computed —
  observed `eda034c7…` on the test vector); EAPOL `len` field also
  auto-fills correctly on serialization (99 = 103-byte frame − 4-byte
  header), so neither frame shape nor MIC is a suspect for the WPA
  online stage's untested live M2→M3.
- Full suite via `run_tests_json`: **125/125 passed**, exit 0. The WPA
  online M2 MIC round-trip (embedded MIC == recompute over zeroed-MIC
  frame; wrong KCK → different MIC) is verified offline again.
- Tooling note: mcp-debugpy is configured user-globally in
  `~/.kimi-code/mcp.json` (`/home/KaliMa/mcp-debugpy/.venv/bin/
  mcp-debug-server`) and works; `dap_launch` takes no CLI args, so
  debugging a subcommand/`pytest -k` target needs a tiny wrapper script
  (`/tmp/dbg_m2_test.py` pattern).

Still open: live-test both untested M2→M3 paths — the WPA ONLINE stage
(`attacks/online.py`, never run against a real AP) and the Phase 6e
WPS brute-forcer fix.

## Update — 2026-08-27, mypy type-clean pass

Cleared the remaining `mypy` errors across `src/atwa`.

- `src/atwa/crack/john.py`: asserted `proc.stdout is not None` before iterating.
- `src/atwa/gui/crack_dialog.py`: annotated `pad` as `dict[str, Any]`.
- `src/atwa/attacks/online.py`: `_build_m2()` now returns a `Packet` instead of `bytes`.
- `src/atwa/gui/attack_runner.py`: added `_iface`/`_mac` helpers that fail fast on `None`, and guarded `online_guess()` against a missing wordlist.
- `src/atwa/gui/app.py`: guarded channel-lock on unknown channel, asserted monitor interface in lock capture / auto-deauth, and fixed the attack-confirm `after_id` list annotation.

Verification: `mypy src/atwa --ignore-missing-imports --show-error-codes` → **Success: no issues found in 54 source files**; `ruff check src/atwa` → clean. Full `pytest` suite not run per user direction.

## Update — 2026-08-27, Phases 1-5 + 6a: internal refactor + vendor inventory

**Phase 1:** Added `radio.ensure_channel()` to cache the last-set channel per
interface; every attack entry point now routes channel setup through it.

**Phase 2:** Split `cli.py` into `src/atwa/cli_commands/{__init__,scan,attacks,crack,misc}.py`;
`cli.py` now only parses arguments and dispatches.

**Phase 3:** Split `attacks/wep.py` into `wep.py` (primitives),
`wep_replay.py`, and `wep_crack.py`.

**Phase 4:** Extracted `ScanEngineWorker` into `src/atwa/scan_worker.py` and
renamed `HOPSCAN_BIN` → `SCAN_ENGINE_BIN`.

**Phase 5:** Extracted GUI attack orchestration into
`src/atwa/gui/attack_runner.py`; `gui/app.py` now handles only Tkinter state,
confirmation dialogs, and `_run_bg()` scheduling.

**Phase 6a:** Added `docs/vendor_inventory.md` mapping every spawned vendor
binary, its role, and native-replacement priority. Aircrack-ng confirmed as
an optional cracking backend alongside John.

Verification: `pytest -q` 122 passed; `ruff check src/atwa --select F401,F541`
clean; `atwa gui --demo` launches without import errors.

## Update — 2026-08-27, Phase 6b: scanning is fully native, `airodump-ng` removed

`airodump-ng` is no longer used anywhere in ATWA-NG — not deprecated, not
behind a flag, the code that spawned it is deleted. This was a full
cutover per explicit direction, not a `--legacy-scan` transition.

- Deleted `scan_engine.py`, `scan_worker.py`, `scanner.py` (and their
  tests) — the three modules that shelled out to the vendored binary.
- `atwa scan` (CLI) now calls `scan.scan()` directly (native scapy
  `AsyncSniffer` + `ChannelHopper`); output fields changed from the old
  CSV shape (`privacy`/`cipher`/`auth`/`beacons`/`essid`) to `AccessPoint`
  fields (`security`/`signal`/`beacon_count`/`ssid`).
- GUI live scan was already native before this pass (`App._start_scan`
  always drove `scan.process_packet()` directly).
- GUI channel-lock capture now uses new `lock_capture.LockCapture`: a
  native `AsyncSniffer` filtered to the locked BSSID, writing matching
  frames to `.pcap` via `PcapWriter`. The old CSV output was confirmed
  unused downstream and isn't reproduced.
- `AccessPoint` gained `beacon_count`, `first_seen`, `last_seen`.
  `iv_count` was deliberately not ported — WEP IV tracking already lives
  correctly in `wep.py`'s `PTWVoteTable`.
- `vendor/aircrack-ng`'s `aircrack-ng` (cracking) and `aireplay-ng`
  (injection, still CLI-only) binaries are untouched — this pass was
  scoped to scanning only.

Verification: `pytest -q` 102 passed (test counts differ because
`test_scan_engine.py`/`test_scanner.py` were deleted and
`test_scan.py`/`test_lock_capture.py` gained new coverage);
`ruff check src/atwa --select F401,F541` clean; `atwa gui --demo` and
`atwa scan --help` both work without import errors.

Next: Phase 6c — native injection (`deauth-inject`/`injection-test` CLI
paths still shell out to `aireplay-ng`), same full-cutover approach.

## Update — 2026-08-27, Phase 6c: injection is fully native, `aireplay-ng` removed

Same full-cutover treatment as scanning — `aireplay-ng` is no longer used
anywhere. Confirmed project-wide wrapper policy: only cracking backends
(John, `aircrack-ng`) and cap/pcap-format tools are acceptable wrappers;
everything else (scanning, injection, WPS, monitor control) must be
native, no legacy-fallback flags.

- **`deauth-inject` CLI subcommand deleted** — it was a pure duplicate of
  the already-native `deauth` subcommand, just backed by the vendored
  binary. No reason to carry two commands for one feature.
- **`injection-test` CLI subcommand rewritten natively**, ported from
  `aireplay-ng`'s real `--test`/`-9` algorithm
  (`do_attack_test()` in `aireplay-ng.c`, read directly rather than
  guessed): broadcast probe-request AP discovery, then a directed ping
  phase (probe request + RTS + null-data + auth-request per attempt,
  counting any of {probe response, CTS, ACK, auth response} as a hit).
  New module: `src/atwa/injection_test.py`.
- New frame primitives in `frames.py`: `craft_probe_req()`, `craft_rts()`,
  `craft_null_data()`.
- `cli_commands/__init__.py`'s `INJECTOR_BIN` removed; `wps-recon`/
  `crack-cap` (the two remaining wrapper paths) untouched — out of scope
  for this pass.

Verification: `pytest -q` 114 passed; `ruff check src/atwa --select
F401,F541` clean; `atwa --help`/`atwa injection-test --help` show the
updated command list; `atwa gui --demo` launches clean. Grep confirms
zero remaining references to `INJECTOR_BIN` or a spawned `aireplay-ng`
process (only explanatory prose comments mention the name).

## Update — 2026-08-27, Phase 6e: native WPS M2→M3 bug fixed + `wash` parity added

Diagnosed `wps_pin_bruteforce()`'s failure to complete a live M2→M3
exchange against Reaver's actual source (`vendor/reaver/src/exchange.c`,
`sigalrm.c`) and fixed two concrete correctness gaps:

1. **Destination-MAC validation on received EAP/WSC frames.**
   `_wait_for()` / `_wait_for_dot11()` now require `pkt.addr1 == client`
   in addition to `pkt.addr2 == bssid`. Without this, monitor mode can
   capture EAP frames the AP is exchanging with other stations (or our
   own TX echo) and misattribute them as replies to us. Matches Reaver's
   `process_packet()` checks in `exchange.c`.

2. **Proactive timer-based M2 resend.** `_send_until_m3()` now resends
   M2 periodically (default 500 ms) while waiting for M3/NACK, in
   addition to the existing reactive resend on AP-retransmitted M1.
   Reaver uses the same pattern (`start_timer()` in `sigalrm.c`,
   ~200 ms resend) so the exchange survives M2 loss even when the AP
   does not retransmit M1.

`wash` reconnaissance parity: `secure.py`'s `wps_profile()` now returns
a full dict (`state`, `manufacturer`, `model_name`, `model_number`,
`device_name`) decoded from the WPS IE, and `scan.py`'s `AccessPoint`
gains matching fields. No more need to shell out to `wash` just to read
AP metadata from beacons.

New test coverage: `tests/test_wps_exchange.py` (6 tests for the two
fixes) and `tests/test_secure.py` (5 tests for WPS IE parsing).

Verification: `pytest -q` 125 passed; `ruff check src/atwa --select
F401,F541` clean; `atwa gui --demo` launches without import errors.

Next: live test the patched WPS brute-forcer against a real WPS-enabled
AP to confirm the M2→M3 exchange now completes.

## Pre-rename history archived

The `n2ngv2`/`N2-NGv2` predecessor-project status snapshot that used to
sit here — "What's real and tested right now" through "GUI copied in" /
"made fully self-contained" / "Remaining, not blocking" — described a
13-command CLI, `scan_airodump.py`, `scanner.py`, and a GUI copied in
from a sibling project. None of that file layout exists in this repo any
more: the native scan/injection rewrite (Phases 6b/6c below) deleted
those modules, and the project was renamed to `atwa`/ATWA-NG on
2026-08-25. Also archived: the explicitly-retracted "wlan1 can't do
5GHz" claim. Full original text (including the CORRECTED note and the
struck-through wrong claim) is in `NOTES_ARCHIVE.txt`.

Current fact: both `wlan0` and `wlan1` are fully capable of 5GHz
monitor-mode RX — see the 2026-08-26 audit section below.

## Build reproduction
```
cd vendor/aircrack-ng
autoreconf -i
./configure --prefix=<anywhere>
make -j$(nproc)
# binaries land at the top of vendor/aircrack-ng/ (airodump-ng, etc.)
```

## Update — 2026-08-26 audit + live hardware test session

Full source audit (engine + GUI + tests) done, then extensive live-hardware
testing against real APs (root access, cached sudo). Real bugs found and
fixed, not just flagged:

- **`radio.py` `set_channel()` — major fix.** Was setting channel via
  `iw dev <iface> set channel` (interface/wdev-level, `NL80211_CMD_SET_CHANNEL`).
  On `wlan0` (rtw88_8814au) this silently "succeeded" (no error, `iw dev info`
  showed the new channel) while the radio never actually retuned for 5GHz —
  confirmed via a clean capture at a channel with a verified-broadcasting AP
  getting zero frames. Real airodump-ng's own `linux_set_channel_nl80211()`
  (`vendor/aircrack-ng/lib/osdep/linux.c`) sets channel at the **PHY level**
  (`iw phy <phy> set channel`, `NL80211_CMD_SET_WIPHY`) instead — doing the
  same fixed this immediately, verified end-to-end through the project's own
  `scan()`: one 15s scan on wlan0 now finds real APs on both bands (11
  2.4GHz + 11 5GHz, including DFS channels 52/56/132) where it silently
  found zero 5GHz before. This had been wrongly written off as "wlan0 is
  fine, only mt76x0u/wlan1 can't do 5GHz" in earlier session notes — wlan0
  was never actually re-tested after that assumption was made.
  **UPDATE, same session:** `wlan1` (mt76x0u/AWUS036ACHM) initially
  retested as zero 5GHz frames even with the PHY-level fix applied
  (multiple attempts, including the real vendored airodump-ng binary
  directly) — this was NOT a hardware/driver limit either. It was a
  stuck USB device state left over from the 2026-08-25 power outage that
  no software-level reset cleared (`ip link` up/down, monitor-mode
  toggling, interface recreate, MAC changes, even a full reboot). A
  **physical USB unplug/replug** of the adapter fixed it immediately —
  clean 5GHz beacons captured right after (`Indepentester-666`,
  `NETGEAR79-5G`, `Totalplay-CAAF` at 5180MHz/ch36). Both adapters are
  fully capable of 5GHz monitor-mode RX; neither has a real limitation.
  If either ever appears to fail at 5GHz again, try a physical
  unplug/replug before concluding anything about capability — see
  memory `project_5ghz_monitor_mode_fix` for the full account. Same
  `set_channel()` PHY-level bug confirmed present, unfixed, in sibling
  `n2ng2` project (`~/N2-NG_v2/src/n2ng2/radio.py`) — user wants it
  ported "not right now."

- **`omni.py`/`attacks/handshake.py`** — `OmniOrchestrator.stop()` didn't
  actually stop an in-progress handshake capture (blocking `sniff()`, no
  stop_event support) — leaked a live sniffer thread/socket after the
  caller moved on. Fixed: `capture_handshake()` now uses `AsyncSniffer` +
  accepts `stop_event`; wired through omni.py and 3 GUI call sites
  (Handshake Capture button, auto-deauth, PINCER) with the same bug.

- **`attacks/eviltwin.py`** — captive-portal `HTTPServer` socket was never
  closed in `cleanup()` (leaked every run); also a redundant double-cleanup
  call on the hostapd-dies-immediately path. Fixed. Live-verified full
  pipeline (hostapd+dnsmasq+portal+deauth) + clean teardown (no orphaned
  processes, no leftover iptables rules, IP flushed) — used `wlan0` as AP
  iface specifically to avoid the documented mt76x0u+hostapd kernel-freeze
  risk.

- **`radio.py` `_run()`** — missing `stdin=DEVNULL`/timeout, unlike every
  other subprocess call in this tree (same bug class already fixed
  elsewhere per this file's own history). Fixed.

- **WPS fragmentation** — `wps/eap.py`'s `craft_wsc_msg` never fragmented
  (hardcoded flags=0). Implemented real WSC-spec fragmentation
  (`fragment_wsc_vendor_payload`, `craft_wsc_msg_fragment`, `WSC_FRAG_ACK`
  detection via the pre-existing-but-unused `WSC_OP_FRAG_ACK` constant),
  wired into all of `wps.py`'s M2/M4/M6 sends. Verified offline (byte-format
  round-trip + full packet round-trip through `parse_eap`). Not live-needed
  in practice — this project's own M2 (~400 bytes) never exceeds any real
  fragmentation threshold — but real protocol completeness now, not a gap.

- **GUI stale `self._stop_event`** — was only cleared before OMNI/Smart/
  PINCER; any Caffe Latte/Chopchop/Evil Twin/Handshake-Capture run after a
  single prior "Stop Attack" click would instantly abort (flag already
  set). Fixed at the one common choke point (`_run_bg`).

- **`attacks/wep_client.py` `chopchop()`** — ICV-correction math was
  provably broken (confirmed via two independent offline tests against
  this project's own validated WEP crypto — a pasted "fix" attempt failed
  500/500 on a real end-to-end round-trip). **Disabled with a clear
  `NotImplementedError`** instead of silently running a doomed guess loop;
  GUI relabeled. Real fix path (documented, not attempted — needs live
  hardware to get right): this project's own vendored/self-compiled
  `aireplay-ng -4`/`--chopchop` already has a working implementation
  (confirmed present in `vendor/aircrack-ng/src/aireplay-ng/aireplay-ng.c`,
  `do_attack_chopchop()`, KoreK 2004) — needs driving from Python, not
  reimplementing.

- **`wps/messages.py` device-info TLVs** — broadcast `"n2ng2"` (manufacturer/
  model/device name) to the target AP in the clear on every WPS attempt —
  real OPSEC issue for a project meant to stay untraceable, not cosmetic.
  Fixed to generic `"Unknown"`.

- **`crack/convert.py` `cap_to_22000()`** — found live via the test
  checklist: crashed `omni`/`smart` (both CLI and GUI, same code path)
  with an uncaught `FileNotFoundError` whenever `hcxpcapngtool` exits 0 but
  writes no output file — a real, unremarkable outcome (confirmed live: a
  genuine capture with real EAPOL pairs still gets "no hashes written"
  when it lacks beacon/probe-response frames for the ESSID). Fixed with an
  explicit existence/non-empty check, matching the guard already present
  in the sibling `hc22000_to_john()`. Re-verified live: clean failure
  message instead of a crash, `smart` now exits 0 as designed.

- Dead code removed: `attacks/wep_client.py`'s two non-functional/uncalled
  WEP helpers (`_redirect_arp_to_client`, `_flip_ciphertext_bytes`) and
  their unused constants; unused import in `gui/elevate.py`; unused
  constant in `eviltwin.py`; redundant assignment in `gui/app.py`.

- One retracted finding: `deps.py` looked dead from a narrow grep but is
  live (`gui/app.py`'s dependency checker) and correctly scoped — no
  change needed.

**Packaging / test-checklist / known-gaps notes from this session were
pre-rename** (`n2ngv2` launcher script, `~/N2-NG_v2/TEST_CHECKLIST.md`,
missing README/LICENSE/.gitignore, hardcoded `n2ng2`/`n2ngv2` strings) —
all resolved or superseded by the 2026-08-25 rename and later packaging
work (README.md/.gitignore now exist; the rename sweep removed the
hardcoded strings). Full original text archived in `NOTES_ARCHIVE.txt`.

## Update — 2026-08-27, second-opinion cleanup + John Jumbo integration

Post-rename maintenance pass. Goal was to clean up obvious drift and wire in
a local John the Ripper jumbo build without presenting ATWA-NG as a wrapper
around other tools.

**Code quality / hygiene:**
- `ruff` + `pyflakes` unused-import sweep across `src/atwa/` — 19 issues
  auto-fixed (eviltwin, wep_client, wps, scanner, radio, cli, wps/oneshot,
  wps/messages, wps/eap).
- Pointless f-string fixed in `crack/john.py`.
- Dev dependencies declared in `pyproject.toml`: `ruff>=0.15`, `mypy>=1.10`,
  `pyflakes>=3.2` under `[project.optional-dependencies] dev`.
- Project description in `pyproject.toml` reworded to remove "reaver source"
  framing.

**John Jumbo integration:**
- `JohnCracker` now resolves `john` in this order: explicit binary argument,
  PATH lookup, then fallback to `~/john/run/john` and `~/John/run/john` if
  the binary is executable.
- Verified: with no system `john` on PATH, `_resolve_john_binary()` finds the
  freshly-built `/home/KaliMa/john/run/john` and `john --list=formats`
  reports `wpapsk` support.
- `JohnCracker.run_streaming()` hardened: `stdin=subprocess.DEVNULL` to avoid
  inherited-stdin hangs; guaranteed `terminate()`/`kill()` cleanup in a
  `finally` block so a stopped GUI crack doesn't leave a zombie John.

**Rebrand / "not a wrapper" cleanup (safe-only):**
- Rephrased Reaver-specific comments in `wps/messages.py`, `wps/eap.py`, and
  `attacks/wps.py` to describe the protocol behavior directly rather than
  citing another tool.
- Renamed `_REAVER_ROOT` → `_WPSRECON_ROOT` in `cli.py`.
- Held off on renaming `HOPSCAN_BIN` / the compiled binary filename and the
  `vendor/reaver` directory itself — those touch the build system and tests,
  and the user asked to avoid dangerous changes.

**Verification:**
- Full test suite: `115/115` passing before and after the cleanup.
- `ruff check src/atwa --select F401,F541` → 0 errors.
- Remaining `ruff`/`mypy` warnings are broad `except Exception:` blocks,
  missing `check=False` on subprocess calls, import sorting, and pre-existing
  type issues — not blockers, but worth a dedicated pass later.

**Vault / graphify note:**
- `~/CCM2/graphify/ATWA-NG/` and the Obsidian vault need regeneration to
  reflect these source changes. User is checking Kimi Code's vault access
  configuration; do not treat the graph as current until it is rebuilt.
- Local project docs (`STATUS.md`, `CHECKPOINT.md`) updated first as the
  canonical session record.

## Update — 2026-08-27, live-GUI bugfix pass + full reskin toward v1 look

Two-phase session driven by the user actually running `atwa gui --demo`
and reporting back what was broken/wrong live, then a long iterative
visual reskin toward the original n2-ng v1 tool's look — explicitly kept
on ATWA-NG's own metallic-blue branding rather than v1's green.

**Phase 1 — bug fixes (from live use):**
- Stop Attack didn't stop anything while OMNI was running its WPS
  pixie-dust stage. Root cause: `attacks/wps.py` blocked on
  `sniffer.join()` with no way to interrupt a 60s M3 wait, and two call
  sites (`omni.py` `_stage_wps`, `gui/attack_runner.py`
  `wps_null_pin`/`wps_pixie`) weren't even passing `stop_event` down into
  the attack functions in the first place. Fixed with a new poll-based
  `_sniff_until()` (checks `stop_event` every 0.05s) threaded through the
  whole WPS call chain, plus wiring `stop_event` through the two call
  sites that were dropping it.
- Signal graph rendered as a static dot instead of a growing line. Real
  cause was a reset loop in `gui/app.py`'s `_on_target_select`:
  `_render_targets()` calls `selection_set()` on every scan tick, which
  re-fires `<<TreeviewSelect>>` even when the selection didn't actually
  change, clearing the graph's sample buffer each time. Also fixed
  `gui/widgets.py`'s `SignalGraph._draw()` X-axis step math
  (`w / (maxlen - 1)`, not `w / (len(samples) - 1)`) so the line now
  genuinely grows left-to-right and scrolls once full, with a live-marker
  dot on the newest sample.
- Added the missing right-click context menu on the client list.
- Reworded a log line that implied entering monitor mode was itself "an
  attack."
- New regression tests: `test_wait_for_aborts_promptly_on_stop_event`,
  `test_send_until_m3_aborts_promptly_on_stop_event`
  (`tests/test_wps_exchange.py`).

**Phase 2 — full GUI reskin (25+ live-screenshot-verified iterations):**
- Layout: collapsed the old tabbed/paned layout to a single pane
  (matches v1's structure), toolbar restructured and reordered
  (stacked Adapter/AP-iface combos, Start/Stop Scan, Start/Stop Monitor,
  WPS Scan, Unlock, toolbar logo), status pill replaced with plain
  colored text, wasted space trimmed throughout.
- Palette (`gui/theme.py`): near-black background, one vivid saturated
  accent color for body text (replacing a prior pale ice-blue that read
  as washed out), white outlines on every box/button/combobox/treeview
  (v1 reference), bold fonts bumped a size up, widened tree row-banding
  for readability.
- New features: WPS Scan dialog (`_open_wps_scan` — interactive, unlike
  v1's click-dead equivalent popup), PINCER attack button (greyed out
  unless dual-Alfa requirements are met), menu-bar tagline ("Airwave
  Teardown Wireless Auditing-NG"), rewritten About dialog (custom
  centered `tk.Toplevel`, contact links restored).
- Mouse-wheel scrolling made reliable and independent across all three
  scrollable regions (AP tree, target panel, Captures list) via a new
  `_bind_wheel_recursive()` helper, replacing a prior Enter/Leave-bound
  approach that broke on any child widget.
- Logo integration: metallic-recolored variant of the user-supplied logo
  chosen over a neon A/B alternative; regenerated all `gui/assets/icon_*`
  PNGs at 8-bit depth (16-bit silently fails to load in `tk.PhotoImage`)
  plus a new `logo_toolbar.png`; wired into window icons, toolbar
  (click-to-About), and CLI background.

**Verification:**
- `pytest -q` → `127 passed` (up from 125 — two new stop_event
  regression tests).
- `ruff check src/atwa --select F401,F541` → clean.
- `atwa gui --demo` launched and screenshotted at the very end of the
  session (`/tmp/final_verify.png`) to confirm the final combined state
  renders with no errors: scan tree, target panel, growing signal graph
  with live-marker dot, log pane all correct.

**Vault note:** `~/CCM2/ATWA-NG/architecture/decisions.md`'s "Branding"
section is now stale (says no logo integration has happened) — update
alongside this entry.
