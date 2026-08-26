# CHECKPOINT — .simulation/N2-NGv2

Last updated: 2026-08-26, end of audit + live-hardware test session.
This file is for **`.simulation/N2-NGv2` (`n2ngv2`) only** — do not confuse
with `~/N2-NG_v2/STATUS.md`/`STATUS2.md`/`CHECKPOINT.md` at the repo root,
which belong to the sibling `n2ng2` project.

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
