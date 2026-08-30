# CHECKPOINT — ATWA-NG (formerly .simulation/N2-NGv2)

Last updated: 2026-08-27, Phase 1 bugfixes + full GUI reskin toward v1 look.
Project renamed/relocated 2026-08-25 per AGENTS.md; this file now tracks
`~/ATWA-NG` (`atwa` package), not the sibling `n2ng2` project.

## State right now

- Full test suite green: `pytest` **127/127 passed**. `ruff check
  src/atwa --select F401,F541` clean. GUI demo-launches clean,
  screenshot-verified (`/tmp/final_verify.png`).
- Phase 1 — live-GUI bug fixes (resolves the "GUI live-feedback notes"
  block below, now closed):
  - Stop Attack unresponsive during OMNI: `attacks/wps.py` blocking
    `sniffer.join()` replaced with a poll-based `_sniff_until()` (checks
    `stop_event` every 0.05s), threaded through `_wait_for`,
    `_wait_for_dot11`, `_send_until_m3`, `_send_eapol_start_adaptive`,
    `_associate`, `attempt_pin`, `pixie_attempt`, `null_pin_attack`,
    `wps_pin_bruteforce`. Root cause was specifically OMNI's WPS
    pixie-dust stage (`omni.py` `_stage_wps`) not passing `stop_event`
    into `pixie_fn`, and `gui/attack_runner.py`'s `wps_null_pin`/
    `wps_pixie` not passing it into `null_pin_attack`/`pixie_attempt`.
  - Signal graph showing a dot instead of a growing line: real bug was a
    reset-loop in `app.py` `_on_target_select` — `_render_targets`'s
    `selection_set()` re-fires `<<TreeviewSelect>>` even with no real
    selection change, clearing `SignalGraph.samples` every scan tick.
    Also fixed the graph's own X-axis math in `gui/widgets.py`
    (`step = w / (maxlen - 1)`, not `w / (len(samples) - 1)`, so the
    line now genuinely grows left-to-right before scrolling).
  - Added client-list right-click context menu (was missing entirely).
  - Reworded the monitor-mode-check log line so it no longer implies
    monitor mode itself is "an attack."
  - New regression tests in `tests/test_wps_exchange.py`
    (`test_wait_for_aborts_promptly_on_stop_event`,
    `test_send_until_m3_aborts_promptly_on_stop_event`).
- Phase 2 — full visual reskin toward the original n2-ng v1 look, with
  ATWA-NG's own metallic-blue branding (not v1's green), driven by 25+
  individual live-screenshot-verified user requests over the session.
  Highlights:
  - `gui/theme.py`: near-black palette, single vivid accent fg, white
    (`#e8f4ff`) outlines on every box/button/combobox/treeview, bold
    11-13pt fonts throughout, widened tree row-banding for contrast,
    new `Toolbar.TButton`/`Toolbar.Accent.TButton`/`Bordered.TFrame`
    styles.
  - `gui/app.py`: single-pane layout (tabs removed), toolbar
    restructured (Adapter/AP-iface stacked combos → Start/Stop Scan →
    Start/Stop Monitor → WPS Scan → Unlock → toolbar logo), new WPS
    Scan dialog (`_open_wps_scan`, editable/interactive — v1's
    equivalent window was click-dead), new PINCER attack button
    (greyed out unless dual-Alfa requirements met), status pill
    replaced with plain colored text, MAC address moved out of the
    (width-clipped) combobox dropdown into a plain label, menu-bar
    tagline ("Airwave Teardown Wireless Auditing-NG"), rewritten About
    dialog (custom centered `tk.Toplevel`, not `messagebox`, with
    `github.com/KiMiGuel` / `indepentest.pro` restored).
  - Mouse-wheel scrolling fixed and made independently reliable across
    all three scrollable regions (AP tree, right-side target panel,
    Captures list) via a new `_bind_wheel_recursive()` helper — the
    previous Enter/Leave-bound-to-canvas approach broke the instant the
    pointer crossed onto any child widget.
  - Logo integration: regenerated `gui/assets/icon_16.png`…
    `icon_256.png` at 8-bit depth (16-bit PNGs silently fail to load in
    `tk.PhotoImage`) plus new `logo_toolbar.png`, from a metallic
    recolor of the user-supplied logo (A/B'd against a neon variant,
    metallic chosen) — used for window icons, toolbar logo (click →
    About dialog), and CLI background.

## Next (unchanged, still open)

- Live test the WPA ONLINE stage's real M2→M3 exchange against a real AP
  (never live-tested; offline MIC verification restored 2026-08-27).
- Live test the patched WPS brute-forcer against a real WPS-enabled AP.
- Dual-Alfa/PINCER mode: button now exists in the GUI (greyed out
  without two Alfa adapters) but the underlying native two-adapter
  attack logic is still the old v1 prototype (buggy) — reimplementation
  is still on the roadmap, not done this session.
- Vault `~/CCM2/ATWA-NG/architecture/decisions.md`'s "Branding" section
  says no logo/image integration has been done — stale as of this
  session, needs updating (see vault log entry for the same date).

## GUI live-feedback notes — 2026-08-27 (RESOLVED 2026-08-27, see "State
right now" above — kept for historical record)

From the user running the GUI live:

1. **Network scan tree colors clash** — the baby-blue text sits on a blue
   background and doesn't read. User wants the font color changed to
   green. Candidates in code: untagged rows use `THEME["fg"]` `#e8faff`
   (pale ice blue); tagged rows: open = `accent` `#00f3ff` (cyan), wpa3 =
   `info` `#7df9ff` (baby blue) — `gui/app.py` `_build_target_tree()`
   tag_configure block, palette in `gui/theme.py`.
2. **Same window: background needs more visibility/contrast** — tree
   background is `THEME["bg"]` `#050b14` with odd-row banding
   `panel_alt` `#010308`; user wants the background itself more visible.
3. **GUI has a lot of wasted space — rearrangement wanted.** Current
   layout (`_build_body`): horizontal PanedWindow, left = AP tree
   (weight 2), right = Notebook with Target/Captures tabs (weight 3),
   plus a separate bottom log pane. Options to explore: move the log
   into the notebook as a tab (kills the bottom strip), two-column
   Target tab (controls right of details instead of stacked), merge
   Captures into Target. Direction to be picked with the user.


## Update — 2026-08-27, WPS M2→M3 fix + `wash` parity pass

- WPS exchange bug diagnosed against Reaver source and fixed in
  `src/atwa/attacks/wps.py`:
  - `_wait_for()` / `_wait_for_dot11()` now validate destination MAC.
  - `_send_until_m3()` now proactively resends M2 on a timer.
- `wash` parity added: `src/atwa/secure.py` `wps_profile()` returns
  manufacturer/model/device-name from beacon WPS IEs;
  `src/atwa/scan.py` `AccessPoint` stores them.
- New tests: `tests/test_wps_exchange.py` (6), `tests/test_secure.py` (5).
- Full test suite: `pytest -q` 125 passed.
- `ruff check src/atwa --select F401,F541` clean.

## Update — 2026-08-27, mypy type-clean pass

- `mypy src/atwa --ignore-missing-imports --show-error-codes` is clean
  (54 source files, 0 errors).
- `ruff check src/atwa` is clean.
- Type fixes applied to:
  - `src/atwa/crack/john.py` — stdout non-None guard.
  - `src/atwa/gui/crack_dialog.py` — `pad` dict annotation widened.
  - `src/atwa/attacks/online.py` — `_build_m2()` returns `Packet`.
  - `src/atwa/gui/attack_runner.py` — `_iface`/`_mac` helpers + wordlist guard.
  - `src/atwa/gui/app.py` — channel/iface guards + `after_id` annotation.
- Full test suite not run this pass (user direction) — this let the
  `_build_m2` return-type change silently break `tests/test_online.py`;
  repaired in the mcp-debugpy pass recorded at the top of this file.

---

## Historical notes below (pre-rename, 2026-08-26 and earlier)

Full text ("State right now" / "Open, unresolved" wlan1-5GHz item /
"Deferred, by explicit user choice" / "Resume point" / "2026-08-26 GUI
polish punch list" / "2026-08-25 interface-contention fix" / "2026-08-25
GUI punch list items 2-7 done + packaging + repo init") archived
verbatim in `NOTES_ARCHIVE.txt`. All of it describes the pre-rename
`n2ngv2` state; the open "wlan1 5GHz" question was later resolved (a
stuck USB device state left over from a power outage, not a hardware
limit — see `radio.py`'s `ALFA_SCAN_DRIVERS` comment).

---

## 2026-08-26 — Stop Attack fix + attack log verbosity overhaul

User report: "Stop attack does not work, Log needs way more verbosity.
I believe none of the attacks work." Full account in
`~/CCM2/ATWA-NG/logs/2026-08-26-stop-attack-and-log-verbosity-fixes.md`;
summary here.

**Real bug found and fixed:** `attacks/pmkid.py`'s `capture_pmkid()` had
no `stop_event` support at all (blocking `sniff()`, no way to abort) —
Stop Attack genuinely did nothing during a PMKID capture (the fastest,
most commonly tried attack, and OMNI/Smart's first stage). Switched to
`AsyncSniffer` + poll loop, same pattern as `capture_handshake()`.
Live-verified on real hardware (wlan1/mt76x0u): a 10s-timeout capture
with stop_event set at t=2s now returns at 2.0s.

**Root cause of "none of the attacks work":** `progress_fn` (the live
per-attack log callback) was only ever wired up for WEP and Caffe
Latte. PMKID, handshake capture, WPS null-pin/pixie/bruteforce, and the
entire OMNI/Smart chain gave zero attack-specific feedback — just a
generic "still running (Ns)" heartbeat every 10s. OMNI especially could
run for minutes with nothing in the log until the final summary at the
very end. Fixed by adding `progress_fn` throughout:
- `capture_pmkid()`, `capture_handshake()`: log channel/send/sniff
  phases and each new EAPOL message seen.
- `wps_pin_bruteforce()`: logs every attempt's outcome (throttled to
  every 10th for uninteresting results, always logs milestones/
  lockout/success) — previously silent across up to 11,000 attempts.
- `attempt_pin()`, `pixie_attempt()`, `null_pin_attack()`: per-phase
  logging for single-shot WPS attacks.
- `OmniOrchestrator`: logs every stage transition live in both `run()`
  and `run_smart()`, threaded through to every sub-stage's own calls.
- `gui/app.py`: wired the above into every attack call site that was
  missing it; also added a monitor-mode sanity check at the start of
  every `_run_bg` attack (logs a WARNING if `mon_iface` isn't actually
  in monitor mode — previously a silent failure mode indistinguishable
  from "ran fine, found nothing").

**Bonus fix:** `self._progress_fn` was only ever set inside `_run_bg`,
so auto-deauth (which bypasses `_run_bg` by design) would raise
`AttributeError` if run as the very first action of a session. Now
defaulted to a no-op at `__init__`.

67/67 tests still pass. Live-verified PMKID stop-responsiveness on real
hardware; verified WPS-bruteforce stop/logging and full OMNI
stage-by-stage logging with stubbed functions (no radio needed).

**Not done this session:** re-running the actual PINCER live test
(needs both Alfa adapters connected); auditing `deauth()`'s frame-count
return value (currently just echoes the `count` argument, not a real
confirmation of transmission).

---

## 2026-08-27 — Desktop-snippet review, opt-in low-rate injection, vault catch-up commit

User pasted 6 standalone Python snippets from `~/Desktop/` (driver
detection, dual-band channel hopping, Alfa-tuned deauth injection, a
main-wiring example, a WEP interactive ARP replayer, and a
reaver-wrapping WPS pixie-dust script) and asked for a comparison
against this project's actual source, adding anything genuinely
missing.

**Finding:** all six were already covered here, mostly more robustly —
`radio.py`'s driver detection/monitor-mode/`ChannelHopper` supersedes
the first four outright (real driver strings, MAC randomization, ACHM
txpower patch, antenna-mask fix, DFS-inclusive channel list, PHY-level
channel set), and the native `wps/pixie.py`/`wps/oneshot.py` supersede
the reaver-wrapping script (native crypto, stronger lockout detection
via two independent signals vs. a bare string match) — the
reaver-shelling approach is the opposite of this project's native-only
mandate, not an upgrade.

**One real gap found and fixed:** none of the injection code anywhere
forced a slow/reliable TX rate — every crafted frame left RadioTap
Rate unset. The pasted deauth/WEP scripts both do this deliberately
(forcing 6 Mbps / 2 Mbps OFDM) for more reliable injection on
Realtek/Alfa hardware. Added `frames.with_forced_rate()` and wired an
opt-in `low_rate` flag through `attacks/deauth.deauth()`,
`attacks/wep.replay_arp()`/`crack_wep()`, and
`attacks/wep_client.caffe_latte()`/`hirte()`. Default stays off (costs
airtime) — not wired into CLI/GUI yet. 113/113 tests pass (2 new test
files: `test_deauth.py` additions, `test_wep_replay.py`).

**Vault catch-up:** working tree had a large body of *prior*-session
work sitting uncommitted — the 2026-08-26 Stop-Attack/logging overhaul
above, plus a native WPA 4-way-handshake online dictionary-attack stage
(`wpa/crypto.py` + `attacks/online.py`, wired into `OmniOrchestrator`'s
new ONLINE stage) that had never been committed *or* logged to the
vault. Verified full suite green before committing, confirmed no
remote configured (no push risk), then committed everything together
as `d58dfd9`. Vault (`decisions.md`/`pending-investigations.md`,
graphify graph) was correspondingly behind — see
`~/CCM2/ATWA-NG/logs/2026-08-27-catchup-online-stage-and-low-rate-injection.md`
for the full sync.

**Not done this session:** CLI/GUI exposure of `low_rate`; live testing
of the ONLINE stage against a real AP (status unknown — inherited
untested from whatever prior session wrote it).

---

## 2026-08-27 — Second-opinion cleanup, John Jumbo fallback, source-code rebrand sweep

User asked for a "second-opinion doctor" scan of `src/` plus tests, then
directed cleanup of drift and wrapper-like branding.

**Findings from the scan:**
- Full test suite green: `115/115`.
- `py_compile` clean.
- `pyflakes` flagged 19 unused imports + 1 pointless f-string; no syntax
  errors, no `os.system`/`eval`/`exec`, no bare `except:`.
- Subprocess/privilege/storage logic is solid for WiFi tooling (timeouts,
  `stdin=DEVNULL`, SUDO_USER-aware capture paths, PHY-level channel set).

**Changes made:**
- `crack/john.py`: added fallback resolution to `~/john/run/john` and
  `~/John/run/john`; hardened `run_streaming()` cleanup; fixed pointless
  f-string.
- `pyproject.toml`: added `[project.optional-dependencies] dev` with
  `ruff`, `mypy`, `pyflakes`; reworded description to drop "reaver source".
- Unused-import sweep across `src/atwa/` (auto-fixed via `ruff`).
- Rephrased Reaver-specific comments in `wps/messages.py`, `wps/eap.py`,
  `attacks/wps.py`; renamed `cli.py:_REAVER_ROOT` → `_WPSRECON_ROOT`.

**Held back (user asked to avoid dangerous changes):**
- `HOPSCAN_BIN` constant rename and the `vendor/aircrack-ng/airodump-ng`
  compiled binary filename.
- `vendor/reaver` directory rename.
- Aggressive `except Exception:` narrowing or broad import-sorting churn.

**Verification:**
- `pytest -q` → `115 passed`.
- `_resolve_john_binary('john-not-in-path')` correctly returns
  `/home/KaliMa/john/run/john` (freshly built by user during this session).

**Vault / graphify status:**
- `~/CCM2/graphify/ATWA-NG/` and the Obsidian vault are now behind the
  source tree. User is checking Kimi Code's vault access configuration;
  once configured, regenerate with
  `/graphify src --obsidian --obsidian-dir ~/CCM2/graphify/ATWA-NG` and
  update `~/CCM2/ATWA-NG/architecture/decisions.md` as needed.
- Local docs (`STATUS.md`, `CHECKPOINT.md`) updated as the canonical
  session record.

---

## 2026-08-27 — Phase 1 of approved refactor: `ensure_channel()` helper

Implemented the first phase of the approved 6-phase architectural refactor
plan (`forager-cable-wolfsbane.md`).

**Changes:**
- Added `ensure_channel(iface, channel)` and `clear_channel_cache()` to
  `src/atwa/radio.py`. `ensure_channel()` wraps `set_channel()` with a
  per-interface cache so repeated calls to the same channel are no-ops and
  only real changes invoke `iw`.
- Replaced direct `set_channel()` calls with `ensure_channel()` in every
  attack entry point: `attacks/pmkid.py`, `attacks/deauth.py`,
  `attacks/handshake.py`, `attacks/online.py`, `attacks/wps.py`,
  `attacks/wep.py`, `attacks/wep_client.py`, and both GUI sites in
  `gui/app.py` (channel lock + PINCER dual-radio setup).
- Left `radio.ChannelHopper` and `radio.set_channel()` itself unchanged;
  `set_channel()` remains the low-level primitive.
- Added `tests/test_radio.py` covering cache hits, misses,
  per-interface independence, and exception-safety.
- Updated `tests/test_deauth.py` to monkeypatch `radio.set_channel`
  because `deauth.py` now routes through `radio.ensure_channel`.

**Verification:**
- `pytest -q` → `122 passed`.
- `ruff check src/atwa --select F401,F541` → clean.

**Next:** Phase 2 — split `src/atwa/cli.py` into
`src/atwa/cli_commands/{scan,attacks,crack,misc}.py`.

---

## 2026-08-27 — Phases 2-5 of approved refactor + Phase 6a vendor inventory

Completed the remaining internal-coupling phases of the approved refactor
plan and produced the vendor-audit deliverable that kicks off Phase 6.

**Phase 2 — CLI split:**
- New `src/atwa/cli_commands/` package:
  - `__init__.py` — shared binary paths (`INJECTOR_BIN`, `CAPCRACK_BIN`,
    `WPSRECON_BIN`) and `_run_bounded()` helper.
  - `scan.py` — `_cmd_scan`, `_cmd_injection_test`, `_cmd_wps_recon`.
  - `attacks.py` — native attack subcommands (`deauth`, `pmkid`, `handshake`,
    `omni`, `smart`, `wep`, `wps-pixie`, `wps-oneshot`, `eviltwin`).
  - `crack.py` — `_cmd_crack` (John) and `_cmd_crack_cap` (vendored
    aircrack-ng).
  - `misc.py` — `_cmd_gui`, `_cmd_deauth_inject`.
- `src/atwa/cli.py` now only builds the parser and dispatches via
  `args.func()`; no command logic lives there.
- Updated `tests/test_cli.py` imports to reference the new modules.

**Phase 3 — WEP split:**
- `src/atwa/attacks/wep.py` keeps frame-parsing / fake-auth primitives.
- New `src/atwa/attacks/wep_replay.py` holds `replay_arp()`.
- New `src/atwa/attacks/wep_crack.py` holds `crack_wep()`.
- Updated `cli_commands/attacks.py` and `tests/test_wep_replay.py` imports.

**Phase 4 — scan worker refactor:**
- Renamed `HOPSCAN_BIN` → `SCAN_ENGINE_BIN` in `scan_engine.py`,
  `gui/app.py`, and tests.
- Extracted `ScanEngineWorker` into new `src/atwa/scan_worker.py`.
- `scanner.py` is now a thin wrapper/helpers module.
- Added injectable `popen_factory` to `ScanEngineWorker` for tests.
- Updated `tests/test_scanner.py` and `tests/test_scan_engine.py`.

**Phase 5 — App decoupling:**
- New `src/atwa/gui/attack_runner.py` with `AttackRunner` class holding
  runtime state and one method per GUI attack.
- `gui/app.py` `_attack_*` methods are now thin confirmation/UI wrappers
  that call `self._runner().<method>(...)` inside `_run_bg()`.
- PINCER dual-radio logic moved entirely into `AttackRunner.pincer()`.
- App keeps Tkinter state, confirmation dialogs, `_run_bg()` machinery,
  logging, and stop handling.

**Phase 6a — vendor inventory:**
- Added `docs/vendor_inventory.md` mapping every spawned vendor/system
  binary, its role, parsed output, native-replacement difficulty, and
  priority.
- Confirmed aircrack-ng remains an optional cracking backend alongside John
  (GUI radio + CLI `crack-cap`).

**Verification:**
- `pytest -q` → `122 passed`.
- `ruff check src/atwa --select F401,F541` → clean.
- `atwa gui --demo` launches without import errors.

**Next:** Phase 6b — native scapy-based scanner, or pause here and refresh
the vault/graphify first.

---

## 2026-08-27 — Phase 6b: scanning fully native, `airodump-ng` removed

User directed a full cutover, not a `--legacy-scan` transition: no fallback
flag, no partial cutoff. `airodump-ng` is now unreachable from any code
path in ATWA-NG.

**Discovery before writing code:** a native scapy scanner (`src/atwa/scan.py`)
already existed and already powered OMNI/Smart profiling. It was `scan.py`
(native) vs. `scan_engine.py`/`scan_worker.py`/`scanner.py`
(airodump-ng-backed) as two parallel scanning stacks. The GUI's main live
scan loop (`App._start_scan`) was *already* calling `scan.process_packet()`
directly — airodump-ng only remained for the CLI `scan` command and the
GUI's channel-lock capture feature.

**Changes:**
- `scan.py`: added `AccessPoint.beacon_count`/`first_seen`/`last_seen` and
  a `channels_for_band()` helper (native replacement for airodump-ng's
  `--band bg/a/abg` flag). `iv_count` deliberately not ported — it's
  WEP-specific and already tracked by `wep.py`'s `PTWVoteTable`.
- `cli_commands/scan.py`: `_cmd_scan` now calls `scan.scan()` directly;
  output fields changed to match `AccessPoint`.
- New `src/atwa/lock_capture.py`: `LockCapture` class — native
  `AsyncSniffer` filtered to one BSSID, writing matches to `.pcap` via
  `PcapWriter`. Replaces `gui/app.py`'s `_start_lock_capture`/
  `_stop_lock_capture` airodump-ng `Popen` calls. `_lock_capture_proc` now
  holds a `LockCapture` instance instead of a `subprocess.Popen`.
- Deleted `src/atwa/scan_engine.py`, `scan_worker.py`, `scanner.py`, and
  `tests/test_scan_engine.py`, `tests/test_scanner.py` — confirmed via
  full-repo grep that nothing else referenced them first.
- Added `tests/test_lock_capture.py` and extended `tests/test_scan.py`
  for the new fields/helper.
- Updated `docs/vendor_inventory.md`: scanning marked done, `airodump-ng`
  row removed from the binary table, roadmap items reworded to drop
  "legacy fallback" language throughout (matches the user's explicit
  no-fallback direction for future phases too).

**Verification:**
- `pytest -q` → `102 passed` (down from 122 — `test_scan_engine.py`/
  `test_scanner.py` deletion removed ~35 tests; new files added ~15).
- `ruff check src/atwa --select F401,F541` → clean.
- `atwa gui --demo` launches; `atwa scan --help`/argument parsing verified.
- Full-repo grep confirms zero remaining references to `SCAN_ENGINE_BIN`
  or `airodump-ng` outside explanatory comments.

**Out of scope this session (left for later Phase 6 sub-parts):**
- `deauth-inject`/`injection-test` CLI commands still shell out to
  `aireplay-ng` (Phase 6c).
- `wps-recon` CLI command still shells out to `wash` (Phase 6e).
- `aircrack-ng` (cracking) stays as the permanent, deliberate optional
  backend alongside John — not in scope for removal, ever.

**Next:** Phase 6c — native injection, same full-cutover approach (no
legacy flag).

---

## 2026-08-27 — Phase 6c: injection fully native, `aireplay-ng` removed

Confirmed project-wide policy from the user: the only acceptable wrappers
in ATWA-NG are cracking backends (John, `aircrack-ng`) and cap/pcap-format
tools. Scanning and injection are now both fully native; WPS is the
remaining sub-part.

**Changes:**
- Removed the `deauth-inject` CLI subcommand entirely (`cli.py`,
  `cli_commands/misc.py`) — it duplicated the already-native `deauth`
  command, just via the vendored binary. No native port needed, just
  deletion.
- Rewrote `injection-test` natively. Read `aireplay-ng`'s actual `--test`
  algorithm (`do_attack_test()` in `vendor/aircrack-ng/src/aireplay-ng/
  aireplay-ng.c`) directly rather than inventing a design — it's a
  two-phase test: broadcast probe-request AP discovery (3 attempts), then
  a directed ping phase against the found/given AP (default 30 attempts,
  matching aireplay-ng's `REQUESTS` constant): each attempt sends a probe
  request + RTS + null-data + auth-request and counts any of {probe
  response, CTS, ACK, auth response} addressed back to that attempt's
  random source MAC as a hit.
- New `src/atwa/injection_test.py` (`injection_test()`,
  `InjectionTestResult`, `_discover_ap()`, `_is_reply_to()`).
- New frame primitives in `frames.py`: `craft_probe_req()` (had to learn
  scapy's `FCfield` flag name is `to_DS` with an underscore, not a
  hyphen — first attempt raised `ValueError` on `FlagValue._fixvalue`),
  `craft_rts()`, `craft_null_data()`.
- Removed `INJECTOR_BIN` from `cli_commands/__init__.py`.
- Rewrote `tests/test_cli.py` (removed `deauth-inject` cases, added
  `injection-test` argument tests) and added `tests/test_injection_test.py`
  (15 tests: frame shapes, `_is_reply_to()` matching logic, discovery/
  ping orchestration with `sendp_fn`/`sniff_fn` injected).
- Updated `docs/vendor_inventory.md`: added the project-wide wrapper
  policy statement at the top, marked injection done, moved `wash`'s
  table row to "next up (Phase 6e)".

**Verification:**
- `pytest -q` → `114 passed`.
- `ruff check src/atwa --select F401,F541` → clean.
- `atwa --help` / `atwa injection-test --help` show the updated command
  list (no `deauth-inject`); `atwa gui --demo` launches clean.
- Grep confirms zero remaining references to `INJECTOR_BIN` or a spawned
  `aireplay-ng` process outside explanatory prose comments.

**User idea considered and narrowed:** dispatch an agent to read
reaver/bully/wash/oneshot and "combine into our own." Pushed back with a
concrete assessment instead of agreeing reflexively: `bully` isn't
vendored (would need an internet fetch), `oneshot` is already ported
(`wps/oneshot.py`), and reaver/bully's *attack* logic is already
redundant with `attacks/wps.py`'s native PIN/pixie-dust implementation.
The one genuinely useful comparison is reaver's actual M1-M7 state
machine against `wps_pin_bruteforce()`'s known bug (GUI's own confirm
dialog says it has never completed a real M2→M3 exchange live) — user
agreed to do that directly, no agent, in the next session slice.

**Next:** diagnose the `wps_pin_bruteforce()` M2→M3 bug by reading
`vendor/reaver/src/exchange.c`/`wps_common.c`/`session.c` against
`attacks/wps.py`'s `attempt_pin()`; separately, extend `secure.py`'s
`wps_profile()` with manufacturer/model/device-name to close the `wash`
gap (small, independent task).

## 2026-08-27: 1-frame-deauth root cause found (== the handshake-capture gap vs v1), client-tree selection bug, log verbosity, "Network is down" explained

User reported 4 live-use issues in one batch: a scapy "[Errno 100]
Network is down" warning on the terminal, the Clients box's row
highlight looking "stuck" on the center row with clicks on rows
above/below not registering, deauth attacks only sending 1 frame
instead of 64, and a repeat ask (raised before) for much higher LOG
verbosity — "see every deauth sent" when an attack runs.

**Root cause common to two of the four items — v1-parity was broken
during the native port, not by design:** grepped
`vendor/n2-ng-v1-src/n2ng/main.py`'s own deauth call sites and found the
comment `# count=1: aireplay-ng sends 64 deauth frames per count unit`.
v1's `count` param was in *aireplay-ng burst* units — `count=1` there
meant one aireplay-ng `-0 1` invocation, which itself fires 64 real
802.11 deauth frames. When deauth was rewritten natively (scapy
`sendp()` instead of shelling out to aireplay-ng), three call sites
(`gui/app.py` auto-deauth loop, `attack_runner.py` PINCER, `attacks/
eviltwin.py`'s deauth loop) kept the literal `count=1` from the old
call sites but lost the aireplay-ng multiplier context — so `count=1`
now means exactly one raw frame per round, a 64x weaker attack than
v1's equivalent. This is very likely *the* reason atwa-ng under-
performs v1 at handshake capture: a single deauth frame is easy for a
client to simply not receive (unencrypted management frame, no
retry/ack), while a 64-frame burst is what v1 relied on for
reliability. Fixed all three call sites to drop the explicit `count=1`
and fall through to `deauth()`'s own default of 64
([deauth.py](src/atwa/attacks/deauth.py),
[app.py:1711](src/atwa/gui/app.py:1711),
[attack_runner.py:292](src/atwa/gui/attack_runner.py:292),
[eviltwin.py:337](src/atwa/attacks/eviltwin.py:337)). `deauth_all()`/
`deauth_client()` (the manual "Deauth All Clients" / "Deauth Client"
buttons) already used `count=64` — only the three *automated/looping*
call sites had the bug.

**Log verbosity — third time this was raised, fixed at the actual
send layer this time.** Previous sessions added per-*round* summary
lines ("sent N deauth frame(s)"), but `deauth()` still handed the
whole batch to a single `sendp(pkt, count=N, inter=interval)` call
with no visibility into individual frames. Rewrote `deauth()` to open
one `conf.L2socket(iface=...)` and loop `sock.send(pkt)` itself, so
every single frame gets its own log line ("deauth frame i/N sent: bssid
-> client") as it goes out, not just a post-hoc count. Kept per-frame
error handling (a mid-loop `OSError` returns the partial count sent so
far rather than silently claiming the full count). Rewrote
`tests/test_deauth.py` to mock `conf.L2socket` instead of the now-gone
`sendp` import; 9/9 pass, no other tests touched `deauth_module.sendp`.

**Clients box "stuck" highlight — confirmed real bug, not a Tk
rendering glitch.** `_on_target_select` (already documented in its own
docstring as refiring on *every scan-tick redraw*, not just real
clicks — this was the mechanism behind an earlier signal-graph-reset
bug) unconditionally did
`client_tree.delete(*get_children())` + full re-`insert()` on every
single firing, including the non-click refires. Since a locked
target's client list is typically static between ticks, this meant
the Clients treeview was being torn down and rebuilt several times a
second — any selection a user made in the small window between two
scan ticks got silently wiped before the click could register,
reading as "stuck"/unresponsive rather than "selection keeps getting
reset." Fixed by only touching tree structure when the actual client
*set* changes (compare current child iids to the new sorted list); when
it's unchanged, only refresh signal values in place via `.item()` and
leave the existing selection alone. When the set does change, the
previous selection is now carried forward into the rebuild if that
client MAC is still present, instead of being dropped
([app.py:1239](src/atwa/gui/app.py:1239)).

**"[Errno 100] Network is down" — explained, not a new bug, already
non-fatal.** This is scapy's own diagnostic print (`WARNING: Socket
<...> failed with '[Errno 100] Network is down'. It was closed.`)
firing when the scan loop's `sniff(iface=mon_iface, timeout=dwell,
...)` call (`app.py:1056`) hits a socket read exactly as the adapter
(mt76x0u, confirmed flaky on fast 2.4→5GHz hops — see the code comment
at that line) transiently drops link mid-hop. The surrounding
try/except already exists specifically for this — logs "scan hop
failed, retrying" to the in-app Log panel and continues to the next
0.3s dwell; the scan session does not die. The two lines the user saw
are scapy's own stderr print (its global logger, independent of our
try/except), not evidence of an unhandled crash. Left as-is — no code
change — since it's cosmetic terminal noise around an already-mitigated
transient condition, not a functional defect; flagged to the user as
optional follow-up if they want scapy's log level raised to suppress
it from the terminal.

**Verification:** `pytest -q` → 128 passed (was 125 at the last
checkpoint + 3 net from the deauth test rewrite). `ruff check` and
`mypy` clean on all four changed files. Not yet live-tested against a
real AP this session — the deauth/handshake fix in particular needs a
live re-test to confirm it actually closes the capture-rate gap with
v1, not just restores the frame count on paper.

**Next:** live re-test auto-deauth/handshake capture against a real AP
now that deauth rounds are back to 64 frames, to confirm this actually
was the v1-parity gap and not just one contributing factor.

## 2026-08-27 (continued): live-tested the 64-frame fix, found + fixed a missing-beacon bug and an OMNI crack-gating bug, ported scan.py's persistent-socket fix into the GUI

Live re-test happened this session (user-authorized, own gear —
Indepentester/Indepentester-666/Totalplay-CAAF, confirmed by their own
sequential BSSIDs `22:87:ec:67:42:b0/b1/b4/b5` all being the same
physical router). Found and fixed a chain of real bugs along the way,
each confirmed against actual hardware, not just code-read:

**CORRECTION (later same session): the "wlan0 can't receive on channel
1" finding — invalidate it, don't cite it.** Root cause: two independent
processes (the user's own live `atwa gui`, 58%+ CPU per `ps aux`, plus
this diagnostic script) fighting over the same radio's channel/monitor-
mode state, not a hardware or RX defect — don't run adapter-level
diagnostics from a second session while a real `atwa` session already
holds the same interface. wlan0 was never actually broken on channel 1.
Full original wrong finding archived in `NOTES_ARCHIVE.txt`.

**The 64-frame deauth fix is now live-proven, not just theoretical.**
`atwa smart wlan1 22:87:ec:67:42:b1 --channel 1` got a full AUTHORIZED
handshake (M1+M2+M3) within round 1/6 — previously (1-frame rounds)
this target never completed a handshake at all in prior live sessions.

**New bug found via the live test: handshake captures were never
crackable even when AUTHORIZED.** `attacks/handshake.py`'s packet
writer only ever wrote EAPOL frames — never a beacon/probe-response —
so `hcxpcapngtool` refused every conversion ("does not contain BEACON
or PROBERESPONSE frames... mandatory to calculate a PMK"), confirmed
directly by running it on the real captured file. Fixed: `capture_handshake()`
now grabs exactly one beacon/probe-response frame (first seen) into the
same pcap alongside the EAPOL frames. Live-verified on a second run:
`hcxpcapngtool` wrote 2 real, valid 22000 hash lines from the resulting
file (one AUTHORIZED, one CHALLENGE).

**Auto-delete for genuinely empty captures.** `capture_handshake()` now
unlinks its own `outfile` when `cap.messages` ends up completely empty
(a deauth round that got no reconnect at all) — CHALLENGE-only (M1+M2)
is explicitly NOT deleted, since it's real material (see below).

**Second bug found from the same live run: OMNI/Smart's crack stage
was silently discarding CHALLENGE-only captures.** `_stage_handshake`
only ever fed `AUTHORIZED` captures to `_stage_crack`'s `hash_lines`;
CHALLENGE (M1+M2, unverified by the AP) was marked FAILED and never
even attempted. This is simply wrong — offline WPA cracking has never
needed M3, only the AP's own real-time confirmation does. Proven
directly: the same live capture that produced the AUTHORIZED hash also
had a CHALLENGE-only pair sitting next to it, and `hcxpcapngtool`
converted *both* into valid, crackable 22000 lines. Fixed: CHALLENGE
now gets `StageResult.SUCCESS` (labeled "unverified by the AP" in the
report) and feeds `hash_lines` the same as AUTHORIZED; `run()`'s
`material_captured` flag for skipping the ONLINE stage now checks
`hs_status is not HandshakeStatus.NONE` instead of
`is HandshakeStatus.AUTHORIZED`, so CHALLENGE material correctly skips
the (much slower) online-guessing fallback too, same as AUTHORIZED
always did.

**Lock-capture folder bloat — root-caused to something else entirely.**
User reported the `~/atwa-hs` capture folder "fills up super fast."
Checked directly: 55 files, 5.5MB, almost all `lock_*.pcap` scattered
across dozens of SSID folders the user never actually attacked — not
from empty handshake attempts (which the fix above already covers),
but from `LockCapture`, which starts a continuous background capture
on every single click in the target list (already a documented v1-
parity trade-off from an earlier session). Fixed per user's own
proposed approach: `_lock_channel` now only starts the lock capture
when the target already has at least one known client
(`ap.clients` non-empty) — a client-less network can never yield a
handshake anyway, so recording it was pure write-and-discard. Does
**not** affect PMKID/WPS/WEP attacks, which are genuinely clientless
and run their own independent capture, entirely separate from
`LockCapture`.

**Separately flagged and fixed: the GUI's own scan loop never got
scan.py's persistent-socket fix.** `scan.py`'s `scan()` function
already fixed the "fresh `sniff()` socket opened/closed every single
channel hop" bug (mt76x0u flaps promiscuous mode in lockstep with the
dwell timer, confirmed via dmesg in an earlier session) by holding one
persistent `AsyncSniffer` for the whole scan. The GUI's own
`_start_scan` loop in `gui/app.py` never got that same fix — it was
still doing a fresh blocking `sniff(iface=..., timeout=hopper.dwell,
...)` every hop. This is also the exact, live-reproduced mechanism
behind the "[Errno 100] Network is down" warning users see (an open
raw socket + a concurrent interface-down event = deterministic
ENETDOWN, confirmed by direct reproduction this session — not an
adapter-specific quirk as an older comment claimed). Ported the same
persistent-`AsyncSniffer` pattern into the GUI's loop, with a
restart-if-the-socket-dies check each iteration (since a persistent
socket, unlike a per-hop one, needs its own recovery path if it does
die mid-session). Side effect: `hopper.hop()` already sleeps for the
dwell period itself, so dropping the old code's *second*,
redundant dwell-length wait inside the per-hop `sniff(timeout=...)`
call roughly halves full-spectrum sweep time.

**`_on_close` race, confirmed live via a clean, deterministic
reproduction (not just code-reading):** started a real `AsyncSniffer`
on `wlan0`, called `set_managed_mode('wlan0')` (which does `ip link set
down`) while it was still running — got the exact same scapy
`L2ListenSocket ... [Errno 100] Network is down` warning on the first
try, with nothing in `dmesg` at all (confirmed this is generic Linux
raw-socket/ENETDOWN behavior, not a driver quirk — any open
`AF_PACKET` socket on an interface that goes admin-down behaves this
way, on any adapter). The `_on_close` fix from earlier this session
(join `_scan_thread` before calling `set_managed_mode`) is still
correct and now also benefits from the new loop's explicit
`sniffer.stop()` in its `finally` block, which gives a real, positive
confirmation of teardown rather than just "hope the timing works out."

**mcp-debugpy tried and abandoned for this work, by design, not a
failure:** attempted to use the newly-connected `mcp-debugpy` server to
step through a live scan — it crashed immediately with a
`PermissionError` opening the raw socket, since the debuggee process
has no `CAP_NET_RAW`/root. Reproduced the identical crash running the
same script plainly (no debugger) to confirm it wasn't debugger-
specific. User chose to keep using plain `sudo`-run scripts for
anything needing real packet capture rather than granting the venv's
python binary `CAP_NET_RAW` via `setcap` (a persistent, security-
relevant system change) — noted here so a future session doesn't
re-litigate this from scratch.

**Verification:** `pytest -q` → 138 passed (was 128; +10 net: 6 new
`tests/test_handshake.py` tests for the beacon-capture and
auto-delete behavior, 4 new `tests/test_omni_handshake_stage.py` tests
for the CHALLENGE-crack-stage fix). `ruff check` and `mypy` clean on
every changed file. The scan-loop rewrite in `gui/app.py` has **not**
been live-tested with the actual GUI running (no display available in
this session) — the underlying persistent-`AsyncSniffer` mechanism is
proven (same pattern already live-verified via `scan.py`'s `scan()`
this session), but the GUI-specific wiring around it (busy-gating,
restart-on-death, queue-push cadence) has only been syntax/lint/type
checked, not run against real hardware with a real window.

**Next:** live-test the rewritten GUI scan loop specifically (launch
`atwa gui` for real, watch Start Scanning behave, confirm restart-on-
death actually recovers if triggered); consider a debounce for
click-to-lock as a possible follow-up to the clients-gate fix if
users still find it noisy while browsing populated networks. (The
wlan0/channel-1 item below was retracted the same session — see the
correction further down — no longer an open item.)

## 2026-08-27 (same day, continued): Stop Attack couldn't touch a running crack; NetworkManager unmanaged-devices config removed

User was running a real live `atwa gui` session (own gear) during this
part of the session and hit a genuine, serious bug: **Stop Attack did
nothing while OMNI/Smart's crack stage was running John the Ripper.**
Screenshot evidence: "... Smart Attack on 22:87:ec:67:42:b1 still
running (320s)" with three identical "stop requested" log lines from
three separate clicks, none of which had any effect. Confirmed via
`ps aux`: a real `john --format=wpapsk --wordlist=...` process, 291%
CPU, 15+ minutes runtime, completely unreachable by anything in the
app. Killed it by hand (`sudo kill -TERM`, escalated to `-9`, since
`-TERM` didn't land — check needed) to give immediate relief.

**Root cause:** `omni.py`'s `_stage_crack()` called the plain blocking
`Cracker.crack()` — a `subprocess.run()` with no process handle exposed
anywhere. The *separate* Captures-tab "Crack Selected" button already
had a proper fix for exactly this (`Cracker.run_streaming()`, Popen +
a `proc_holder` dict `_stop_attack()` can reach into and `.terminate()`
— from the 2026-08-26 stop-attack session) but that fix was never
wired into OMNI/Smart's own internal crack stage, which is a
completely separate code path. So the *manual* crack flow had a real
Stop button and OMNI/Smart's *automatic* one (arguably the more common
way a crack actually gets run) did not.

**Fixed:** `OmniOrchestrator.__init__` now takes a `proc_holder: dict`
param (empty dict by default, never a shared mutable default — each
orchestrator gets its own unless the caller passes one in).
`_stage_crack()` now prefers `cracker.run_streaming()` over
`cracker.crack()` whenever the cracker exposes it (both `JohnCracker`
and `AirCracker` already do), clearing and populating that same
`proc_holder` the way the Captures-tab flow already did. Threaded
through: `AttackRunner.__init__` gains `crack_proc_holder`,
`App._runner()` passes `self._crack_proc_holder` (the *same* dict
`_stop_attack()` already checks), `attack_runner.py`'s `_omni_style()`
passes it into `OmniOrchestrator(...)`. No changes needed to
`_stop_attack()` itself — it already had the right kill logic, it just
never had anything to point at for this specific stage.

**NetworkManager side quest, from the same live session:** user
couldn't see wlan0/wlan1 in their normal WiFi UI at all after this
session's earlier live testing. Root cause: `/etc/NetworkManager/
conf.d/99-n2ng-unmanaged.conf` (`unmanaged-devices=driver:mt76x0u;
driver:rtw88_8814au`) — a standing config from before the rename,
presumably set up so NetworkManager wouldn't fight atwa for the
adapters during monitor-mode work. `nmcli device set managed yes` did
NOT stick (NM immediately re-applies the keyfile policy). User chose
to remove the file entirely (not just temporarily disable it) since
they use these adapters for normal WiFi too; removed + `nmcli general
reload`, confirmed both adapters back to normal `disconnected` (not
`unmanaged`) state. **Known follow-on risk, not yet addressed:** atwa's
own code doesn't proactively tell NetworkManager to back off an
adapter before putting it into monitor mode, so a future atwa session
may now have NetworkManager try to reclaim wlan0/wlan1 mid-attack.
Offered to add that (e.g. `nmcli device set <iface> managed no` inside
`set_monitor_mode()`, restored in `set_managed_mode()`) — not done yet,
no answer from the user on this specific follow-up yet.

**Verification:** new `tests/test_omni_crack_stage.py` (4 tests:
streaming-preferred-when-available, blocking-fallback-when-not,
proc_holder-cleared-before-each-run, default-proc_holder-not-shared-
between-instances) — all pass. Full suite 142/142. `ruff`/`mypy` clean
on all three changed files (`omni.py`, `gui/app.py`,
`gui/attack_runner.py`). **Not yet live-tested** — the fix logic is
sound and unit-tested, but hasn't been confirmed against a real,
actually-running John process being killed via a real Stop Attack
click in the live GUI (the user's own session was already being shut
down by the time this fix landed).

**Next:** live-test the Stop Attack fix specifically — start a real
OMNI/Smart run against a target with a wordlist big enough that John
is still running after a minute or two, hit Stop Attack, confirm the
process actually dies and the GUI unblocks. Decide on the
NetworkManager-adapter-handoff follow-up (self-manage unmanaged state
during monitor mode vs. leave the standing config file approach to the
user).

## SESSION PAUSED (usage limit hit) — state as of pause

**Uncommitted working tree** (nothing from this whole session has been
committed yet — user approved one commit mid-session for the earlier
deauth/client-tree batch, that one landed as `35a6fa0`; everything
since is still sitting as local changes):
```
 M CHECKPOINT.md
 M src/atwa/attacks/handshake.py
 M src/atwa/gui/app.py
 M src/atwa/gui/attack_runner.py
 M src/atwa/omni.py
?? tests/test_handshake.py
?? tests/test_omni_crack_stage.py
?? tests/test_omni_handshake_stage.py
```
All of it is tested and clean as of the last check: full suite
142/142, `ruff`/`mypy` clean on every touched file. Safe to commit as-
is whenever asked — nothing known-broken is sitting in the tree.

**Immediately pending, not started:** user asked for an audit of atwa
against a WiFi-pentesting reference doc they shared
(`~/Downloads/compass_artifact_wf-c4433f78-3ccc-50ac-8530-c763cf22fe6d_text_markdown.md`
— a solid technical write-up covering EAPOL/handshake fields, WEP
attack lineage, PMKID, WPA3-SAE/Dragonfly, KRACK, hashcat 22000 format,
tooling, staged build recommendations). They chose "audit atwa against
it, report gaps" — no code changes implied yet, just a gap report.
Session hit its usage limit right as this started; **next session
should pick this up first** — read the doc (already read once this
session, full text available), then check atwa's actual coverage
against each of its 9 numbered sections, particularly: WPA3-SAE/PMF
detection maturity (`secure.py`'s `security_profile()`/
`recommend_attack()` — already does *some* of this, extent unknown),
whether an authorization-scope-file (Stage 4 recommendation: "explicit
authorization gate — scope file of permitted BSSIDs") is worth adding
given this session's own back-and-forth about which BSSIDs were
authorized to test, and general WEP/KRACK/enterprise-rogue-AP coverage
comparison.

**Other open follow-ups from this session, not yet acted on:**
- NetworkManager: offered to make `atwa` self-manage the NM-unmanaged
  state around monitor mode (`nmcli device set <iface> managed no` in
  `set_monitor_mode()`, restored in `set_managed_mode()`) since the
  standing `99-n2ng-unmanaged.conf` config file that used to handle
  this was removed at the user's request this session. No decision
  from the user yet on whether to build this.
- The Stop Attack / OMNI crack-stage fix (`proc_holder` wiring) is
  unit-tested but **not live-tested** — the user's own live session
  had already been shut down by the time the fix landed. Worth a real
  OMNI/Smart run + Stop Attack click against a real slow crack before
  fully trusting it.
- The GUI scan-loop rewrite (persistent `AsyncSniffer` instead of
  per-hop `sniff()`) is also not live-tested with a real display.
- Debounce-on-click-to-lock was mentioned as a possible follow-up to
  the clients-gate fix if the current behavior still feels noisy in
  practice — not requested yet, just noted as an option.

**Corrections on record from this session — don't re-litigate:** the
"wlan0 can't receive on channel 1" finding earlier in this file is
retracted (see the correction earlier in this file, full original text
in `NOTES_ARCHIVE.txt`) —
it was cross-session process contention (the user's own live `atwa
gui` fighting a separate diagnostic script for the same radio), not a
hardware defect. wlan0 is fine on channel 1.

## 2026-08-28: real root cause of the ENETDOWN/hang reports — NetworkManager churn

Live testing (`atwa scan wlan1`) reproduced an unhandled crash:
`scapy.error.Scapy_Exception: Not running !` from `scan.py`'s
`sniffer.stop()`, triggered by the same `[Errno 100] Network is down`
warning the user had already been seeing. `journalctl -u
NetworkManager` for the exact crash timestamp showed NM actively
randomizing wlan1's MAC ("scanning") and cycling its supplicant state
at that instant — confirmed, not inferred. Since the user had NM
restored to managing wlan0/wlan1 earlier this session (removed the
standing `99-n2ng-unmanaged.conf`), NM was free to yank the interface
admin-down mid-capture on its own schedule, killing any raw
AF_PACKET socket regardless of atwa's own code. This is very likely
also the real explanation behind the separately-reported "OMNI loops
forever" / "Stop Attack does nothing" / "no handshake captured" live
bugs — NM silently killing the capture socket mid-attack could leave
a GUI worker thread dead without cleanly updating busy-state, which
would look exactly like a stuck attack from the user's side.

First fix attempt was a scoped `nmcli device set <iface> managed no`
toggle in `set_monitor_mode()`/`managed yes` in `set_managed_mode()`
— live-verified to fix the crash, but the user explicitly rejected
this approach ("match airmon-ng's check kill thats it it doesnt make
nmcli unmanaged") after correcting a wrong claim I made along the way
(I'd said killing NetworkManager would drop eth0/the ProtonVPN
tunnel — live-tested and confirmed false: killing the NM process
leaves already-up kernel interfaces, including the WireGuard tunnel,
fully functional; ping through `proton0` succeeded immediately after
the kill). Replaced with `radio.py`'s new
`check_kill_interfering_processes()` — plain `pkill -x` against the
same process list airmon-ng's own `check kill` uses (NetworkManager,
wpa_supplicant, wpa_action, wpa_cli, dhclient/dhclient3/dhcdbd,
udhcpc, dhcpcd, avahi-autoipd, avahi-daemon), wired into
`set_monitor_mode()`, no nmcli/systemctl involved, no auto-restart
(matches real airmon-ng — user must `systemctl start
NetworkManager` themselves when done). Live-verified: killed
NetworkManager + wpa_supplicant, eth0 and proton0 both kept their IPs
and worked, and the `atwa scan wlan1` crash was gone on re-run.

## 2026-08-28: live OMNI run against Indepentester — first real, user-witnessed handshake capture

`atwa omni wlan1 22:87:ec:67:42:b1 --channel 1` with all of the
above fixes plus the earlier deauth/beacon/CHALLENGE-gating fixes in
place: PMKID stage failed cleanly (2 attempts, no PMKID exposed — AP
doesn't leak it), WPS stage correctly detected AP Setup Locked and
skipped bruteforce, handshake stage sent a full 64-frame deauth burst
in round 1/6, and captured EAPOL M1+M2+M3 (AUTHORIZED) against a real
client on the first attempt. Report: `handshake: captured
/home/KaliMa/atwa-hs/2287ec6742b1.pcap`, batched to a 2-line 22000
hash file. This is the first handshake capture this project has
actually produced end-to-end against a live target with the user
watching, as opposed to a unit test or an isolated CLI check.

Also fixed in this same pass, each confirmed against real code paths
(not yet all live-tested individually, see below):
- `gui/crack_dialog.py`: the "Crack Handshakes" dialog's output `Text`
  widget had no scrollbar at all (only auto-scroll-to-end) — added one.
- `gui/app.py`: the Adapter dropdown embedded the MAC address inside
  the combobox's own values, which ttk truncates in the popdown list
  (a real, already-documented ttk limitation — the target-filter combo
  had already been fixed this way in an earlier session, but the
  Adapter combo itself was missed). Moved the MAC to its own label next
  to the combo, same pattern.
- `attacks/deauth.py`: dropped the artificial 0.05s `time.sleep()`
  between each of the 64 deauth frames (default `interval` 0.05 → 0.0).
  aireplay-ng's own `-0 64` fires its burst back-to-back with no
  per-frame delay; the old default stretched a 64-frame burst out to
  3.2s of individually-spaced sends instead of one dense burst, per
  user's live report ("deauth frame needs to be sized 64 NOT send 64
  1 packet frames").

**Not yet live-tested:** Stop Attack against a real OMNI run (the
`proc_holder`/`run_streaming` fix from the previous session is still
only unit-verified), the GUI's rewritten scan loop with an actual
display, and the crack-dialog scrollbar / adapter MAC label fixes
(code-reviewed and lint/type-checked, not clicked through live).

**Verification:** `pytest -q` → 142 passed. `ruff check` / `mypy`
clean on every changed file.

## 2026-08-28: crack-dialog font-color bug fixed, two real resize-clipping bugs found and fixed live under Xvfb

User pasted a generic AI-authored "UI/UX audit" doc (proposed a full
redesign with both Tkinter and CSS/Electron code — the CSS half doesn't
apply, this is a pure-Tkinter app) alongside three specific complaints:
GUI freezes after OMNI finishes, the crack module's output text is
"STILL blue" despite repeated requests to make it white, and buttons
get hidden by bad resizing. Investigated each against actual code
instead of the doc's generic prescriptions.

1. **Font-color bug — confirmed and fixed.** `gui/crack_dialog.py`'s
   output `Text` widget was hardcoded to `fg=THEME["fg"]` (`#33bbff`,
   the same electric-blue used for every other body-text widget) since
   the file was created (`git log -p` shows that line untouched across
   every commit touching the file) — every prior request to change it
   to white was never actually applied. Added a dedicated `THEME["bright"]`
   (`#ffffff`) token and pointed the crack output's `fg`/`insertbackground`
   at it instead of `THEME["fg"]`.

2. **Resize-clipping — two real bugs found, distinct from the toolbar's
   already-documented/accepted overflow tradeoff.** Launched
   `atwa gui --demo` under a scratch Xvfb (`:99`, isolated from the
   real desktop) and screenshotted/resized with `import`/`xdotool` to
   actually see what breaks, rather than guessing from the audit doc's
   description (which referenced a "Club_Totalplay_Wi..." SSID and
   generic language suggesting it wasn't run against this actual build).
   - `_build_captures_panel`'s Capture-dir/Wordlist `Entry` fields sat in
     a grid column with `weight=1` and no `minsize` — below ~800px
     window width the column collapsed straight to 0, making the entry
     fully invisible (label butted directly against the Browse button).
     Fixed with `columnconfigure(1, weight=1, minsize=100)`.
   - `capture_tree` (the Captures file list) lacked the `stretch=False`
     + horizontal-scrollbar treatment that `self.tree` (the AP list)
     already had — ttk was auto-compressing every column to fit,
     mangling "Kind"/"Size" headers into "Kin"/"Siz" at narrow widths.
     Mirrored the AP-list's existing fix: `stretch=False` on each
     column + a horizontal scrollbar wired to `xview`.
   - The toolbar's own overflow-when-narrow is pre-existing, deliberate,
     and already documented at the top of `gui/app.py`: every toolbar
     action also exists in the real menu bar, which can't be clipped by
     resizing. Left alone — re-verified the menu fallback still covers
     the same actions (Captures menu confirmed live).

3. **OMNI freeze — likely already fixed, not independently reproduced.**
   Traced `_run_bg`'s worker/queue architecture (used by every attack
   including OMNI) and found no synchronous main-thread blocking calls
   around attack completion. The one confirmed freeze bug matching this
   exact symptom — `_refresh_captures()` running its directory walk
   synchronously on the Tk thread — was fixed in the immediately
   preceding commit (`27da2df`, same day). Flagged to the user rather
   than assumed fixed: asked them to confirm whether the freeze persists
   now that they're on `27da2df` or later.

Did **not** implement the audit doc's proposed full redesign (Left-Rail
Dashboard / Tabbed Diagnostic concepts, new color palette) — out of
scope per this project's standing rule that color-theme/logo work needs
explicit sign-off, and the doc itself wasn't grounded in this app's
actual (Tkinter, not web) stack.

**Verification:** `pytest -q` → 142 passed. `ruff check` / `mypy` clean
on all three changed files. Font fix and both clipping fixes visually
confirmed live via screenshots under a scratch Xvfb display (`:99`),
not just code review — the real desktop (`:0.0`) was never touched.

## 2026-08-28: Target/Captures Notebook redesign, Inspect All + delete-empty-captures, theme softening, logo refresh

User explicitly waived the project's normal color-theme/logo
sign-off requirement for this pass ("dont worry about what the
project's CLAUDE.md says... be more flexible") after describing the
GUI as wasting resize space and hiding buttons on resize. Iterated
live against screenshots (demo-mode instance, `atwa.cli gui --demo`,
never the user's real `sudo atwa gui` session running concurrently on
the same desktop — confirmed which window was which via `wmctrl`/
`xdotool getwindowpid` before ever clicking).

1. **Layout**: `app.py`'s `_build_body` replaced the single
   unbounded-height scrollable column (Target details + Clients +
   Signal History + 14 attack buttons + the Captures file manager all
   stacked in one pane) with a top-level `ttk.Notebook`: "Target" tab
   (AP list | details/attacks split) and "Captures" tab (full width,
   AP list hidden while active). An intermediate vertical-PanedWindow
   attempt was tried first and rejected — still buried content below
   the fold; screenshot evidence in prior turns of this session.
   Attack buttons moved from a single-column stack to a 2-column grid.
   Captures' action-button row wraps into a 5-column grid instead of
   running off-screen.
2. **New feature**: "Inspect All" (Captures tab + Captures menu) scans
   every listed capture/hash file, reports PMKID/handshake material
   per file via a new `_show_scroll_dialog` helper (fixed 560x480,
   word-wrapped, scrollable — replaces unbounded-tall `messagebox`
   calls that grew one line per file), then offers to delete files
   with none found. Delete path wraps `Path.unlink()` in try/except
   and reports failures instead of swallowing them — real find: this
   user's `~/atwa-hs` capture files are root-owned, so deleting as a
   regular user throws `PermissionError`; the first cut of this
   feature silently ate that exception and looked like "I clicked Yes
   and nothing happened."
3. **Theme**: softened pure `#000000` bg/panel colors to a dark slate
   (`#0a0e14`/`#0f141c`/`#11161f`) and added a `border_dim` mid-tone
   for button hover/active states (was flashing full white). Added
   `TNotebook`/`TNotebook.Tab` ttk styles (previously unstyled --
   rendered white/gray under the `clam` theme, clashing hard).
4. **Logo**: user supplied a new high-res mark
   (`~/Pictures/atwa_logo2.jpg`, 3524x3524, black linework on white).
   Regenerated `icon_16/32/64/128/256.png` (window/taskbar icon) and a
   new `logo_about.png` shown in the About dialog, both white-on-
   transparent matching the existing asset style. Also fixed a real
   (not cosmetic) bug found along the way: the pre-existing toolbar
   logo *button* was being pushed off the visible window edge on
   screens narrower than ~1400px, because it shared row1 with the
   toolbar buttons and row1's own content already filled the width
   there. Moved it to its own dedicated row to fix that — then the
   user asked for the toolbar button removed outright ("messed up
   everything, i didnt ask for it"), so `_build_toolbar_logo` and its
   row were deleted entirely; `logo_toolbar.png` regenerated but now
   unused by any code path. Window icon and About-dialog logo were
   kept (not what was reported as broken). A true "logo behind
   everything" watermark was scoped and declined for this pass: ttk
   widgets are opaque and this layout has no genuinely empty
   background space left without a Canvas+`place()` rewrite; flagged
   as a separate future task rather than forced in.

**Verification:** `python -m ast` parse + PyCharm MCP
`get_file_problems` (no errors) on every changed `.py` file; visually
confirmed via demo-mode screenshots (Notebook tabs, Inspect All flow,
About dialog, toolbar logo) — not committed to running the real
hardware path.

## 2026-08-28: toolbar logo button removed, toolbar made fully width-responsive (wrap + stretch)

Two follow-ups from the same session, both user-driven:

1. User rejected the toolbar logo button outright ("the logo button
   messed up everything remove it. i didnt ask for it") even after the
   row-overflow bug above was fixed. Deleted `_build_toolbar_logo` and
   its dedicated row entirely. Window icon (`_set_window_icon`) and the
   About-dialog logo were kept — not what was reported as broken.
2. User then asked for a stronger guarantee: "if I choose to resize or
   minimize everything adapts to it meaning no buttons hide, same as
   fullscreen." The toolbar (Adapter/AP-iface column + 6 action
   buttons) previously overflowed off-window below ~1400px with no
   wrap — the menu bar duplicates every action as a fallback, but the
   user wants the toolbar itself to never clip. Implemented
   `_reflow_toolbar`: measures each item's `winfo_reqwidth()` and packs
   items into as many row frames as needed to fit the container's
   actual width, re-run on every `<Configure>`.

   Two real bugs surfaced building this, both only visible by actually
   launching and resizing live (not from code review):
   - **Reentrancy**: calling `item.update_idletasks()` inside the
     reflow loop let Tk dispatch the `<Configure>` event that packing a
     new row frame itself generates, recursively re-entering
     `_reflow_toolbar` mid-loop and destroying `self._toolbar_rows`
     out from under the outer call (`bad window path name` — reproduced
     first in a standalone repro script, then fixed the same way in
     `app.py`). Fixed with a `self._toolbar_reflowing` guard flag and
     by dropping the per-item `update_idletasks()` call entirely.
   - **Stacking order**: even after the reentrancy fix, the toolbar
     rendered completely blank despite debug logging confirming every
     item packed without error. Cause: row frames and toolbar items are
     Tcl siblings (all children of the same `container`, attached to
     their row only via `pack(in_=row)`, not true reparenting) — a
     freshly created sibling window stacks *above* older siblings by
     default in X11, so each new row frame's own opaque background was
     painting directly over the already-existing buttons "inside" it.
     Fixed with `row.lower()` right after creating each row frame.
   - **Wasted space**: the first working wrap left short trailing rows
     (e.g. "Unlock" alone) left-packed with a large blank gap after
     them (2026-08-28 user report: fixed the clipping but "now theres
     wasted empty spaces"). Switched from `pack(side=LEFT)` within each
     row to `grid` with `columnconfigure(col, weight=1)` per column and
     `sticky="ew"` per item, so a row's items always stretch to fill
     its full width — same pattern already used for the Captures
     action-button grid.

**Verification:** live-tested via demo-mode screenshots at multiple
window widths (default ~1360px, and a forced-narrow 700px via
`xdotool windowsize`) — confirmed the toolbar always renders fully
populated across 1–3 rows depending on width, with no clipped or
hidden buttons and no leftover blank gaps. `get_file_problems`: no
errors.

## 2026-08-30: pycryptodome RC4 swap (redo of the reverted 2026-08-29 attempt)

`wep/crypto.py`'s hand-rolled pure-Python RC4 KSA/PRGA replaced with
pycryptodome's C-accelerated `Crypto.Cipher.ARC4` — `cryptography`
(already a dependency) dropped RC4 entirely as insecure-by-design, and
WEP cracking (PTW voting) is CPU-bound enough for the C backend to
matter. `rc4_keystream`/`rc4_crypt` keep identical signatures (`ptw.py`
needed no changes); `rc4_ksa`/`rc4_prga` removed (no external callers).
Added `pycryptodome>=3.20` to `pyproject.toml`.

**Correction to the 2026-08-29 vault log**: that session's writeup said
"pycryptodome's `Cryptodome.Cipher.ARC4`" — wrong namespace. The
`pycryptodome` PyPI package ships the `Crypto` namespace;
`Cryptodome` is the separate `pycryptodomex` package. Import fixed to
`from Crypto.Cipher import ARC4` before this landed.

**Deliberately NOT done this session** (both touch the live monitor-mode
receive path and can't be verified without real hardware — same risk
class as the 2026-08-29 PyRIC revert): swapping scapy for `pypacker` in
`scan.py`'s packet-dissection hot path (research showed pypacker's lazy
dissection benchmarks ~24x faster than scapy, and it natively supports
Radiotap/IEEE80211 — the likely fix for scan-time CPU/fan load), and
adding a kernel-level BPF capture filter to drop 802.11 control frames
before scapy dissects them. Both are real candidates for the CPU/fan
complaint but need a live session with the actual adapters to verify
they don't silently degrade scan results, per the PyRIC lesson. pyroute2
was researched and rejected outright for `radio.py` — its own docs
describe the nl80211/IW module as "very initial state," same failure
class as PyRIC.

**Verification:** `pytest -q` → 147/147 passed.

## 2026-08-30: mac80211_hwsim mock env built, PMF-blocks-deauth theory confirmed live

Built a `mac80211_hwsim` virtual-radio harness (user-approved sudo, scoped
to this task) to test the broadcast-vs-targeted-deauth theory from earlier
this session without touching real hardware. Correction: this machine
actually has real Alfa adapters attached (`wlan0`=rtw88_8814au,
`wlan1`=mt76x0u, both up in managed mode) — not hardware-less as the
2026-08-29 log assumed; hwsim radios (`wlan2`/`wlan3`/`atk0`) were used
anyway for a controlled, repeatable test.

Ran `attacks/deauth.py:deauth()` **unmodified** (exactly as GUI/CLI call
it) against a real hostapd AP + wpa_supplicant client with a completed
4-way handshake, in two configs:

- **PMF off**: both broadcast and unicast-targeted deauth caused an
  immediate real disconnect (`dmesg`: `deauthenticated ... Reason:
  7=CLASS3_FRAME_FROM_NONASSOC_STA`), followed by sub-second
  auto-reconnect. Broadcast worked identically to targeted — no
  difference for this client stack, partially refuting that half of the
  original hypothesis.
- **PMF required** (`ieee80211w=2`, both sides): identical frames, zero
  effect — no disconnect logged either way, `wpa_state` stayed
  `COMPLETED`. **Confirms** the PMF half of the hypothesis decisively.

**Implication**: the previously-proposed fix (thread a discovered client
MAC into automated deauth calls) doesn't address what this test shows —
targeting made no difference in either PMF state. The real lever is PMF
detection/routing: a PMF-required target should skip deauth-based capture
entirely and go straight to the online-dictionary fallback, which already
exists for this reason. Whether `OmniOrchestrator` already routes this way
or just silently falls through after deauth fails — not checked yet.

Real harness mistake made and corrected mid-session, kept in the log
rather than erased: first attempt put the attacker interface on the same
phy as the client, so hwsim's virtual medium (which only connects
different simulated radios, matching real half-duplex RF) never delivered
anything — that run's "no effect" was a topology bug, not a finding.

Environment left running for further testing. Full writeup + raw logs:
`~/CCM2/ATWA-NG/logs/2026-08-30-hwsim-mock-env-pmf-deauth-theory-confirmed.md`.

## 2026-08-30: PMF-aware + client-targeted deauth applied to PINCER/auto-deauth/eviltwin

Checked `OmniOrchestrator` per user request: `_stage_handshake` (used by
both `run()` and `run_smart()`) **already** does both fixes the earlier
audit proposed — skips the whole deauth round loop outright when
`ap.pmf == "required"`, and threads `next(iter(ap.clients), BROADCAST)`
into the deauth call otherwise. No fix needed there.

Applied the same two-part pattern to the three call sites the original
audit found still hardcoded to `BROADCAST`:

- `gui/attack_runner.py:pincer()` — PMF check before any monitor-mode
  setup (skip returns before touching the radios at all, so nothing needs
  restoring); `client` now recomputed **per round** (not once at the
  start) since the persistent scan sniffer keeps updating `ap.clients`
  live even while an attack is busy — a client discovered mid-run is
  picked up on the next round.
- `gui/app.py:_auto_deauth_run()` — same PMF check + per-round client
  targeting. Caught a real bug while wiring this: the early-return path
  would have skipped the `finally` block's `("auto_deauth_done", None)`
  queue signal, leaving the "Auto-deauth until handshake" checkbox stuck
  checked forever even though the thread had already exited. Fixed by
  emitting that signal explicitly before the early return.
- `attacks/eviltwin.py:run_eviltwin()` — new `client: str = BROADCAST`
  parameter threaded into its own deauth loop; caller
  (`gui/attack_runner.py:eviltwin()`) passes the discovered client and
  logs a warning (not a skip) when PMF is required, since the rogue AP +
  captive portal still has some value if a client reconnects on its
  own — unlike PINCER/auto-deauth, evil-twin has no other capture
  mechanism to fall back to, so aborting outright would be too aggressive.

**Not done**: no new automated tests. `pincer()`/`_auto_deauth_run()`/
`run_eviltwin()` have no existing dependency-injection test harness the
way `OmniOrchestrator` does (all three are threading/monitor-mode-heavy
with no seam to mock deauth_fn/pmf cheaply) — building one was judged
disproportionate given this session's explicit token-conservation ask.
Verified instead by code reading plus the live hwsim result confirming
the underlying `deauth()` PMF/targeting mechanics this mirrors. Flagging
as a real gap, not silently claiming coverage.

`pytest -q` → 147/147 passed (unchanged — no test exercises these paths
either way).

## 2026-08-30: session paused/saved — bidirectional deauth fix + two scoped PMF-bypass builds queued next

Session paused here at user's request (no context/token visibility inside
PyCharm, long session). State as of pause:

**Landed this session** (all verified via `pytest -q` 147/147, still
uncommitted — see below):
- `wep/crypto.py`: pycryptodome C-accelerated RC4 (redo of the reverted
  2026-08-29 attempt, with the `Crypto` vs `Cryptodome` namespace bug
  fixed).
- PMF-aware deauth applied everywhere: `omni.py` already had it;
  `pincer()`, `_auto_deauth_run()`, `run_eviltwin()`, `deauth_all()`,
  `deauth_client()` now all skip/warn via the same `ap.pmf == "required"`
  check (`AttackRunner._pmf_block_message()` using
  `secure.recommend_attack()` for a consistent message). PINCER's confirm
  dialog text fixed to not overpromise "goes to monitor mode" on the
  skip path.
- `frames.py`/`attacks/deauth.py`: **bidirectional deauth** — targeted
  (non-broadcast) deauth now sends both AP->client and client->AP per
  round, matching the vendored aircrack-ng's own aireplay-ng behavior
  (confirmed by reading `vendor/aircrack-ng/src/aireplay-ng/aireplay-ng.c`
  directly). Packet construction verified correct byte-for-byte. Forward
  direction proven live (real disconnect+reconnect). **Reverse direction
  could not be confirmed physically transmitting in the hwsim lab** —
  traced to the attacker interface (`atk0`) unavoidably sharing a
  simulated radio with the AP (only 2 hwsim radios available this
  session) — hwsim doesn't deliver a frame back to a destination
  co-located with the sender's own simulated phy, matching real
  half-duplex RF. This is a lab-topology artifact, not a code doubt: on
  real hardware the attacking radio and the target AP are always
  separate physical devices (matches PINCER's own dual-Alfa assumption).
  Real-hardware confirmation still outstanding.
- Also confirmed the full PMF-blocks-deauth mock-environment finding from
  earlier this session, and confirmed n2-ng v1 (the predecessor project,
  vendored at `vendor/n2-ng-v1-src/`) has the identical limitation/routing
  already — not a regression.

**Researched, not yet built** — two scoped next steps, user's explicit
call on which to build first next session:
1. **Rogue-AP EAPOL corruption** (higher confidence): add the
   PMKID-tag-length-underflow trick from Schepers/Ranganathan/Vanhoef's
   WiSec 2022 paper ("On the Robustness of Wi-Fi Deauthentication
   Countermeasures", https://github.com/domienschepers/wifi-deauthentication)
   to `attacks/eviltwin.py`. Exact working PoC bytes are in that repo's
   `framework/test-deauthentication.py` (`PMFDeauthClientPMKIDTagLength`
   class) — a corrupted RSN PMKID tag length in a spoofed 4-way handshake
   Message 1/4, sent by the framework acting AS the AP. Scope: only
   affects clients connecting to ATWA-NG's OWN rogue AP (evil-twin
   scenario), not clients on someone else's real AP. Patched upstream in
   hostapd/IWD since ~2022-2023 and in Android since CVE-2023-21061
   (March 2023) — real-world value depends on how many actual target
   devices run outdated/unpatched stacks (plausibly common on
   unmaintained embedded/IoT Wi-Fi).
2. **CSA (Channel Switch Announcement) spoofing** (lower confidence,
   exploratory): same paper's vulnerability table also lists "Invalid
   Channel Switch Announcement" as working against Linux 5.15.0, macOS
   12.3, and iOS 15.4 — and unlike the EAPOL trick, this one could
   plausibly disconnect a client already associated with the REAL target
   AP (matches the original ask better). No published PoC bytes for this
   one in the repo ("not all proof-of-concepts are available due to
   ongoing disclosures") — only the general concept (spoof a CSA IE
   claiming to be from the real AP). Building this is exploratory: no
   proof it actually triggers the underlying bug vs. just producing a
   normal, correctly-handled channel switch. Also flagged independently
   via https://hackersmanifest.com/wireless-pentesting/06-deauth/ (mdk4's
   own deauth/disassoc modes, plus the same CSA/rogue-AP/auth-flood/
   beacon-flood technique list).

**Not committed**: all of this session's + the prior session's
already-uncommitted chopchop_vendor work is still sitting in the working
tree (`git status` confirms nothing new landed). Git/push commands were
handed to the user earlier this session (two commits: chopchop_vendor
wiring, then the pycryptodome swap) but not yet run as of this pause —
this save entry's own changes (PMF fixes, bidirectional deauth) aren't
included in those commands and will need their own commit(s) whenever
committing resumes. `origin` is confirmed live at
`github.com/KiMiGuel/ATWA-NG` (not the stale "local only" state
CLAUDE.md's TOP SECRET section still describes — flagged, not yet fixed
in CLAUDE.md itself).

**Environment left running** (hwsim mock, from earlier in session):
`wlan2`/`wlan3`/`atk0`/`sniff3` + hostapd (PMF-required config) +
wpa_supplicant. Teardown command given earlier:
`sudo pkill hostapd wpa_supplicant; sudo iw dev atk0 del; sudo iw dev
sniff3 del; sudo rmmod mac80211_hwsim` (last one needs the user to run it
— the auto-mode classifier blocks unattended `rmmod`).
