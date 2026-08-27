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

## State right now

- All fixes from this session are live in `src/n2ngv2/` — see STATUS.md's
  "Update — 2026-08-26" section for the full list (5GHz `set_channel` fix,
  omni/handshake stop-event fix, eviltwin socket leak, chopchop disabled,
  WPS fragmentation, `cap_to_22000` crash fix, GUI stale-stop_event fix,
  WPS device-info OPSEC string fix).
- Full test suite: 67/67 passing.
- Both `wlan0`/`wlan1` are back in clean managed mode, real MACs restored.
- 3 orphaned `tcpdump` processes may still be sitting around (PIDs from
  the last session, unkillable from within this agent's sandbox —
  "Permission denied" even under sudo). Harmless now that the interfaces
  are back in managed mode; `sudo pkill tcpdump` from a real terminal will
  clear them if they bother you.
- Packaging: `pip install -e .` verified clean (fixed a stale post-rename
  shebang in the venv's own `pip` script). Launcher installed:
  `~/.local/bin/n2ngv2` → run `n2ngv2 gui` (or any subcommand) from any
  terminal, sudo prompt included.

## Open, unresolved — do not treat as settled

**`wlan1` (mt76x0u/AWUS036ACHM) 5GHz monitor-mode reception.** Confirmed
zero frames repeatedly, including with the same PHY-level channel-set fix
that resolved `wlan0`'s identical symptom, and independently confirmed
with the real vendored `airodump-ng` binary directly (no Python in the
loop). But the AWUS036ACHM is specifically known/marketed for 5GHz
monitor-mode support, so **do not re-assert "hardware can't do it" as
fact** — this needs a real driver/firmware-level investigation (kernel
module parameters, firmware blob version, mt76 driver version/patches)
that wasn't reached this session. Checked and ruled out so far:
- Channel actually sets and stays stable (`iw dev info` confirms).
- Not a regulatory-domain block — 5GHz channels are listed as valid
  frequencies for both phys, with identical "(no IR)" flags on both
  (symmetric, not the differentiator).
- Not a `--band`+`-c` airodump-ng CLI flag interaction bug (that's a
  separate, real airodump-ng quirk found along the way — using `-c N`
  alone works normally; combining it with `--band` sent airodump-ng into
  a stuck redraw loop that never advanced past "Elapsed: 0s").
Next real steps if resumed: check `dmesg` for mt76x0u firmware-load
messages specifically (5GHz on some mt76x0u variants needs a separate
firmware blob from 2.4GHz), check loaded driver version against known
mt76 5GHz-monitor-mode fixes/patches, check antenna/hardware config via
`iw phy phy1 info`'s full capability dump for anything else asymmetric
vs `wlan0`'s phy.

## Deferred, by explicit user choice (not forgotten, just not now)

- Port the `set_channel()` PHY-level fix to `~/N2-NG_v2/src/n2ng2/radio.py`
  (sibling project has the identical bug, confirmed).
- Final project-name rename sweep (4 inconsistent hardcoded strings —
  see STATUS.md for the exact list) — planned as one pass at actual
  release time, not incrementally.
- `--version` CLI flag (sibling `n2ng2` has one).
- README.md / LICENSE / .gitignore (original HANDOFF.md packaging scope).

## Resume point

`~/N2-NG_v2/TEST_CHECKLIST.md` (written for `n2ng2`, run against `n2ngv2`
per user's direction) — §3 (attack-confirm dialog) and §8 (PINCER's full
dual-radio attack flow) are the only sections not independently verified
this session, both because GUI click-automation via `xdotool` proved
unreliable on this actively-shared desktop (real mouse contention with
the user, plus a coordinate-mapping confusion after a window move). If
resuming GUI verification, prefer CLI/direct-Python-call verification
over `xdotool` click automation — it was consistently more reliable this
session.

Real key recovery was confirmed working end-to-end this session (capture
→ hcxpcapngtool → John → real password) against the user's own
`Indepentester` network — deliberately not repeating the recovered
password value here; see conversation history if it's needed again.

## Update — 2026-08-26, GUI polish punch list (user live-testing session)

GUI fixes requested during/after that live session, **only #1 done, #2–6
NOT yet started** (agent stayed fully hands-off while user was actively
using the GUI):

1. ✅ **DONE** — Unknown-character "boxes" in SSID column: non-UTF8 SSIDs
   decode fine (frames.py's latin-1 fallback) but many bytes are
   non-printable and rendered as missing-glyph boxes. Fixed via new
   `App._display_ssid()` static method in `gui/app.py` (swaps
   non-printable chars for a single "·" placeholder) — **display only**,
   wired into `_render_targets()`'s tree insert. `ap.ssid` itself is
   untouched everywhere else (title bar, confirm dialogs, log lines,
   attacks) — user said "no stop" when this was about to be expanded to
   those other locations, so it's intentionally scoped to just the tree.
2. **NOT DONE** — BSSID/SSID/CH (and other) column headers need to be
   comfortably draggable/resizable, and all columns reachable without
   manually widening the whole window. Root cause already diagnosed
   earlier this session: `_build_target_tree()` in `gui/app.py` only has
   a vertical scrollbar, no horizontal one, so columns get clipped with
   no way to reach them if the pane is narrower than total column width.
   Planned fix: add a horizontal scrollbar to the target Treeview, and
   review `stretch=`/width defaults per column so manual resize sticks
   rather than being fought by auto-stretch redistribution.
3. **NOT DONE** — Row background alternating-band highlighting too
   subtle. Current colors in `gui/theme.py`'s `THEME` dict: `row_even` =
   `THEME["bg"]` (`#0a0f0a`), `row_odd` = `THEME["panel"]` (`#12170f`) —
   very close, barely distinguishable. User wants noticeably darker/more
   contrast. Tag config is in `gui/app.py`'s `_build_target_tree()`
   (`tag_configure("row_even"/"row_odd", ...)`).
4. **NOT DONE** — Signal graph (`gui/widgets.py`'s `SignalGraph` class,
   shown in the Target tab) not displaying anything during live use.
   Not yet investigated this session — `add_sample()`/`_draw()` logic
   looked correct on read-through earlier, so this needs live
   re-verification, not just a code re-read. Possibly related to the
   `signal_sample` queue event only firing when `self.locked_bssid` is
   truthy and currently in `result.aps` (see `_start_scan`'s scan loop in
   `gui/app.py`) — worth checking whether channel-lock state is actually
   being reached/matched during real use.
5. **NOT DONE** — "Stop Attack" button position: currently at the bottom
   of the Target tab's attack-button stack (`_build_target_panel()` in
   `gui/app.py`, the `buttons` list). User wants it moved up, directly
   under "Unlock" (in the title_row near the channel-lock pill) — a real
   safety/usability issue, not cosmetic: too slow to reach when an attack
   needs to be killed quickly.
6. **NOT DONE** — Row selection should immediately drive the Signal graph
   and a partial-capture-size (KB) readout, matching v1 (`n2ng2`)
   behavior:
   - **Single-click** a target row (select, not lock) → should
     immediately start updating the Signal graph for that BSSID, and show
     a live "captured so far" size in KB (v1 had this — check
     `~/N2-NG_v2/src/n2ng2` for the reference implementation/behavior).
     Currently the signal graph only seems tied to the locked BSSID (see
     item 4's note on `self.locked_bssid` in `_start_scan`'s scan loop,
     `gui/app.py`) — this needs to instead react to tree selection
     (`<<TreeviewSelect>>`) independent of lock state.
   - **Double-click** a target row → should "lock" it in directly
     (equivalent to today's Lock button), without needing the button.
   - The existing **Lock button** must keep working as an alternative
     trigger — both paths should coexist, neither replaces the other.
   - This overlaps directly with item 4 (Signal graph not rendering) —
     worth fixing both together, since the real root cause for item 4 may
     simply be that nothing drives the graph until a lock happens, and a
     lock during live use wasn't reliably reached/matched.
7. **NOT DONE** — Log panel (`App._log()`/`_append_log()` in `gui/app.py`)
   needs to be more verbose during attacks — user specifically wants
   lines like packets-sent counts. Confirmed concretely: `deauth()` in
   `attacks/deauth.py` already returns the frame count it sent
   (`return count`), but both call sites in `gui/app.py`
   (`_auto_deauth_run` line ~1389, `_pincer_run` line ~1527) discard that
   return value — currently nothing is logged per deauth round beyond the
   round number. Planned fix: capture the return value and log it (e.g.
   `f"sent {n} deauth frames to {ap.bssid}"`), and audit other attack
   loops (WPS attempt counter, handshake capture progress, PMKID
   attempts) for similar already-available-but-unlogged counters worth
   surfacing the same way.

None of items 2–7 have been touched in code yet. Resume by implementing
each in `gui/app.py`/`gui/theme.py`/`gui/widgets.py` as scoped above, then
get the user to re-verify live (GUI code changes need a real relaunch +
visual check, not just unit tests — none of this is covered by the
existing 67 hermetic tests). Item 7 (log verbosity) is not GUI-visual and
could reasonably be verified via existing/new hermetic tests on the
return-value plumbing, then confirmed live for readability.

## Update — 2026-08-25, interface-contention fix: live-verified with a correction

Ran a scripted live test against the real "Indepentester" AP (own
network), reproducing the exact fixed mechanism (busy flag gating the
scan loop; `deauth()`/`capture_handshake()` from the real attack
modules) without the full Tkinter GUI. Two things confirmed, one
original claim retracted:

**Confirmed fixed:** dmesg showed one clean, continuous ~13s
promiscuous-mode session on wlan1 during the busy-gated window — zero
flapping, vs. the original incident's ~30 flaps in 14s. The scan-loop
socket churn against a running attack is genuinely gone.

**Retracted:** the original diagnosis cited `ip -s link`'s TX packet
counter (0 TX packets) as evidence deauth frames weren't transmitting.
Re-tested that specifically with a second adapter (wlan0) as an
independent over-the-air witness while wlan1 sent 20 deauth frames —
**all 20 were seen in the air**, while `ip -s link` still reported 0 TX
throughout. That counter is simply not instrumented for this mt76x0u
driver's monitor-mode injection path — it was a misleading signal, not
evidence of a real TX bug. Do not cite `ip -s link` TX/RX counters as
evidence for monitor-mode interfaces on this hardware again; use an
independent-adapter witness instead if TX needs verifying.

**Net conclusion:** the actual original bug was on the RX/handshake-
capture side (the scan loop's rapid socket teardown stealing the
capture socket), not TX — TX was likely never broken. The fix is
correct and verified for what it actually targets. No real handshake
was captured in the test (expected — no client was reassociating during
the window; not a failure).

Test scripts (not part of the package, scratch/no need to keep):
`/tmp/claude-1000/-home-KaliMa-N2-NG-v2/b67427d2-9dfb-4d13-b381-f57191ec0a16/scratchpad/verify_interface_fix.py`
and `verify_tx_witness.py` in the same directory.

## Update — 2026-08-25, GUI punch list items 2-7 done + packaging + repo init

User approved a staged roadmap to "done" (functional fixes → packaging →
repo hygiene → rename sweep → publish decision, the last one explicitly
deferred) and said to run through it autonomously. Completed in this
run:

**GUI punch list, all items now done:**
- #2 columns: `_build_target_tree()` now has a horizontal scrollbar
  (`tree_frame` + grid layout) and every column is `stretch=False` so
  manual widths stick instead of being auto-compressed.
- #3 row banding: `row_odd` tag now uses `THEME["panel_alt"]` instead of
  `THEME["panel"]` — a real contrast jump vs. the old near-identical bg/panel.
- #4 + #6 signal graph + capture size, merged (same root cause): the
  scan loop's `signal_sample` event now fires on `self.selected_bssid`
  (not just `locked_bssid`), and `_on_target_select` seeds the graph
  immediately with `ap.signal` on single-click. Added
  `_start_selected_capture_watch()` — a lightweight per-selection
  watcher showing the KB total of any existing capture files for that
  target, backing off via `self._busy` so it never fights a running
  attack's own `_watch_capture_size`. Double-click-to-lock unchanged
  (already existed); Lock still also reachable via the existing flow.
  Note: "capture size on mere selection" doesn't have an exact v1
  precedent — v1's `_select_target` conflated select+lock entirely, so
  this is a best-effort interpretation (shows existing on-disk capture
  size for the target, live-updating), not a byte-for-byte port.
- #5 Stop Attack: moved from the bottom of the attack-button stack into
  `title_row`, next to Unlock. Removed from `attack_buttons` list;
  simplified `_set_busy()` since the text-match special-case is no
  longer needed.
- #7 log verbosity: both `deauth()` call sites (`_auto_deauth_run`,
  `_pincer_run`) now log the actual frame count returned instead of
  discarding it.

Visually spot-checked via a screenshot (GUI launched, no live APs
scanned) — Stop Attack position and horizontal scrollbar confirmed
correct. Row banding/signal graph/capture-size need a real scan session
to see against actual rows/data — not yet re-verified live with real
APs present, only code-level + a no-data smoke test.

**Packaging:** `README.md`, `.gitignore` added. `--version` wired up in
`cli.py`'s `build_parser()` (was already tracked in `__init__.py`, just
not exposed). LICENSE deliberately skipped — tied to the publish
decision (public vs. private), which is explicitly deferred, so
premature to pick one now.

**Repo hygiene:** `git init` + baseline commit (`d836273`, 52 files,
"Initial commit: n2ngv2 hybrid rebuild baseline"). Local only, no
remote configured, matching the TOP SECRET / no-GitHub-push rule.

67/67 hermetic tests still pass throughout.

**Next and only remaining item before the (separately deferred) publish
decision: the rename sweep.** Blocked on knowing the actual new name —
not yet given. The 4 hardcoded strings needing the sweep: `"n2-ng"`
(storage.py capture root), `"n2ng2"` (gui/settings.py config path),
`"n2ng_hostapd_"/"n2ng_dnsmasq_"` (eviltwin.py temp prefixes),
`"n2ng2_wps_"` (oneshot.py temp prefix).

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
