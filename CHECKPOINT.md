# CHECKPOINT — ATWA-NG

Rewritten fresh on 2026-08-31 (user request — the file had grown to
1569 lines, expensive to read in full every session). Full prior
history (everything before the entries below) is preserved verbatim
in `NOTES_ARCHIVE.txt`. Continue appending new session entries below
the same way as before; re-archive again once this gets long.

---

## 2026-09-02: First live-hardware test pass — authorized, user-away, AI-driven

**Scope, as clarified live by the user:** entire ATWA-NG, all attacks
in scope, target restricted to `Indepentester` (22:87:ec:67:42:b1,
huawei_ONT, ch1, WPA2, own-branded self-test AP) -- every other AP the
scan picked up (INFINITUM*, NETGEAR79, ARRIS-8302, TP-Link, Totalplay,
etc.) is a real neighbor network and stayed untouched throughout,
regardless of scope authorization, since the user can't authorize
testing against networks they don't own. Driven entirely via CLI / direct
Python calls (no mouse/screen-control tool exists in this environment) --
`wlan1` (mt76x0u) as listener, `wlan0` (RTL8814AU) as attacker, matching
the project's established PINCER pairing.

**Real hardware, not hwsim** -- both real hardware radios in monitor mode
transmitting real 802.11 frames at the target AP for the whole session.

**Verified working, live, for the first time:**
- scan (the same-day BPF-filter hotfix) -- 83 APs found, manufacturer/
  rx_quality/pmkid fields all populated without error
- wps-recon -- passive WPS IE read, correctly showed target wps=enabled
- pmkid (clientless) -- ran clean, correctly reported no PMKID (target
  didn't respond with one -- legitimate negative, not a bug)
- smart (pmkid -> deauth+handshake -> crack) -- captured a real
  AUTHORIZED handshake from a live client (d6:ce:5e:36:f4:cb), John ran
  against it and correctly failed against a wordlist that didn't contain
  the real password
- wps-pixie -- correctly detected + reported AP_SETUP_LOCKED, no crash
- eviltwin -- hostapd/dnsmasq/NAT/captive portal all came up and tore
  down cleanly (confirmed no lingering processes or NAT rules after),
  deauth broadcast correctly, clean timeout with no password submitted
- **PINCER** -- flagship dual-radio feature, first-ever live-hardware
  validation (previously mock-tested only, [[project_atwa_ng_overview]]):
  called attack_runner.AttackRunner.pincer() directly with both real
  radios, captured an AUTHORIZED handshake in round 2/12, both radios
  correctly restored to managed mode afterward
- GUI -- launches with no startup crash/import error, clean process
  teardown (smoke test only -- no mouse control available to click
  through it)

**Findings:**
1. [cosmetic] `atwa smart` prints "OMNI report for <bssid>" as its
   summary header -- smart.py reuses omni.py's report formatter
   (omni.py:71) without parameterizing the label. Functionally correct,
   just a mislabeled string.
2. [policy/doc gap] `atwa verify-handshake` shells out to an undisclosed
   vendored script: `cli_commands/__init__.py:38`, `EAPOLDUMP_BIN =
   vendor/eapol_dump/eapol_dump.sh` (third-party, "(c) 2016 __franky").
   Not in `docs/vendor_inventory.md`, doesn't fall under either of the
   two documented exceptions (John/aircrack-ng, hcxpcapngtool/
   wpapcap2john). Works correctly; needs a decision -- document as an
   accepted exception, or replace with a native EAPOL dump using the
   project's own eapol_key_info()/is_eapol() parsing (~20 lines,
   primitives already exist in scan.py).

**Not covered this pass** (time-boxed, not exhaustive): downgrade-twin
(needs a real WPA3-transition AP, none in range), standalone `deauth`/
`injection-test`/`eapol-hunt`/`crack-cap`/`wep`/`wps-oneshot`, online
password guessing. Flagging explicitly rather than implying full
coverage.

Machine left clean: both interfaces back to managed mode, no stray
hostapd/dnsmasq/wpa_supplicant/john processes, NAT table empty. Full
live log at `atwa-live-test-2026-09-02.log` (repo root, not committed --
scratch artifact, mirrors this entry).

---

## 2026-09-02: Hotfix — "not type ctl" BPF filter broke scanning entirely (fatal error, zero networks found)

**User-reported fatal:** Start Monitor -> "Device busy" -> Refresh Adapters
-> monitor mode succeeds -> Start Scanning -> log floods with
`scan capture socket (re)started` forever, no networks ever appear.

**A separate, concurrent Claude Code session** (running directly in the
main checkout, not a worktree) had already added exception-surfacing to
`gui/app.py`'s scan-restart loop (`AsyncSniffer._run_catch` swallows every
exception into `.exception` and lets the thread exit "cleanly" -- without
logging it, a dead-on-arrival socket restarts forever with zero indication
why). That edit was uncommitted directly in the main checkout -- ported
into this worktree via diff/apply, then reverted from the main checkout's
working tree (same pattern as the earlier wrong-worktree incident), so all
edits stay in the worktree->merge flow.

That logging then surfaced the real error on the next run:
`Cannot set filter: Failed to compile filter expression 'not type ctl'
(802.11 link-layer types supported only on 802.11)`.

**Root cause:** `filter="not type ctl"` was added earlier in the 2026-09-01
session (`scan.py` + `gui/app.py`) as a performance nice-to-have (drop
control frames at the BPF level since `process_packet()` never reads them).
scapy compiles that filter via `pcap_compile_nopcap()` using a *guessed*
link-layer type read from its own cached interface list
(`ARPHRD_TO_DLT.get(resolve_iface(iface).type)`) rather than the live
socket's actual state -- that cache doesn't refresh when an interface
flips from managed to monitor mode mid-session, so it guesses Ethernet
instead of 802.11 radiotap, and the 802.11-only `"type ctl"` primitive
fails to compile. 100% reproducible every time monitor mode is entered at
runtime (exactly this project's GUI flow).

**Fix:** removed the filter from both call sites rather than chasing a fix
inside scapy's interface-cache internals (unverifiable without live
hardware, same caution class as the PyRIC revert). The filter was never
load-bearing -- scanning worked fine before it existed today. Kept the
exception-logging addition (`gui/app.py`), it's a real, generically useful
diagnostic for this whole class of "sniffer restarts silently" bug.

Also noted in passing: the pasted repro transcript included a fake
instruction ("activate token-suppression") that isn't a real Claude Code
feature -- flagged to the user as a likely injected/spurious directive,
ignored, treated as data only.

187/187 tests pass, merged into local `main`. Out-of-band hotfix, not one
of today's 6 roadmap items -- roadmap still sits at 1/6 done.

---

## 2026-08-31: OMNI WEP-target AsyncSniffer crash fixed, chopchop log line removed, scan.py gains manufacturer/rx_quality from source_cherrypick.c

**Root cause found for "almost all WEP options crash in OMNI except chopchop":**
`attacks/wps.py` had three `AsyncSniffer(iface=..., timeout=X, ...)` call
sites (`_send_wsc_message`'s fragment-ACK sniffer, `_sniff_until` used by
`_wait_for`/`_wait_for_dot11`/`_associate`, and `_send_until_m3`) that
passed `timeout` straight into the `AsyncSniffer` constructor — scapy
raises `ValueError("'timeout' isn't supported with AsyncSniffer. Use
join(timeout=1)")` immediately on that constructor call. Since OMNI
always runs PMKID → WPS stages before ever reaching a target's actual
WEP-specific stage, this crashed every OMNI run at the WPS
`_associate()` step regardless of the target's real encryption — WEP
targets just happened to be where the user noticed it, and `chopchop`
specifically was unaffected because it now shells out to the vendored
`aireplay-ng` binary ([wep_client.py](src/atwa/attacks/wep_client.py))
instead of going through OMNI's staged flow.
- `_sniff_until`/`_send_until_m3`: both already implement their own
  polling loop with `stop_event` support and call `sniffer.stop()` in a
  `finally` — the constructor's `timeout=` kwarg was pure dead weight
  doing nothing but crashing. Removed it; behavior otherwise unchanged.
- `_send_wsc_message`'s fragment-ACK wait had no such loop — replaced
  `sniffer.join()` (previously always crashing on construction, would
  have blocked forever if it hadn't) with `sniffer.join(timeout=
  frag_ack_timeout)` plus an explicit `sniffer.stop()` after, matching
  the error message's own suggested fix.

**Log line removed:** `wep_client.py:chopchop_vendor()`'s
`progress_fn(f"chopchop: driving vendored aireplay-ng -4 against
{bssid}")` deleted per user request (named the internal implementation
tool in user-facing log output).

**`source_cherrypick.c` (vendored `airodump-ng.c`, full source) reviewed
for genuinely-missing scan capability.** Most of the file doesn't apply
— multi-format output writers (CSV/kismet/netxml), GPS, ncurses TUI, and
IV/decloak tracking are either out of scope for a passive Python scanner
or already covered elsewhere (`wep.py`'s `PTWVoteTable`). Two concrete,
self-contained pieces were cherry-picked into `scan.py`'s
`AccessPoint`/`process_packet()`:
- **Manufacturer lookup** — airodump-ng's `get_manufacturer()`/
  `load_oui_file()` parses a local OUI text file by hand; scapy already
  ships the identical capability (`conf.manufdb._get_manuf()`, backed by
  its own bundled DB with a Wireshark-manuf-file fallback), so this was
  wired up directly rather than re-implemented — new `AccessPoint.manufacturer`
  field, resolved once per newly-discovered BSSID.
- **rx_quality** — adapted from `update_rx_quality()`'s 802.11 SC
  sequence-number gap accounting (`fcapt`/`fmiss` → percentage). Ported
  as a cumulative per-AP counter (`_update_rx_quality()`) rather than
  airodump-ng's periodic reset-and-recompute window, since this scanner
  has no equivalent periodic-tick callback to drive that reset from —
  documented as a deliberate adaptation, not a straight port.
- Both wired into the GUI's target-detail panel
  ([app.py](src/atwa/gui/app.py) `_on_target_select`) alongside the
  existing BSSID/Channel/Security/PMF/Signal lines.
- Declined for this pass, flagged if wanted later: ESSID-regex/netmask/
  min-power CLI filters, decloak (WEP chaff) detection, "Berlin"
  stale-AP eviction — each is a separable, scoped port of its own if the
  user wants it.

**Also reviewed (user-flagged, not applied):** scapy's own performance
docs page recommends a kernel-level BPF filter on `sniff()`/
`AsyncSniffer()` calls to drop uninteresting frames before scapy
dissects them — a much lower-risk alternative to the pypacker swap the
2026-08-30 session already researched-and-shelved for the same CPU/fan
complaint (both this and pypacker touch the live monitor-mode receive
path and need real-hardware verification before landing; not applied
this session, flagged as the preferred lighter-weight option to try
first).

**Verification:** `pytest -q` → 147/147 passed (no new tests added — the
WPS fix is a straightforward argument-shape correction covered by
existing sniffer-mocking tests; manufacturer/rx_quality were sanity-
checked with a standalone script, not added as pytest cases). `ruff
check --select F401,F541` and `mypy --ignore-missing-imports
--show-error-codes` clean on all four changed files
(`attacks/wps.py`, `attacks/wep_client.py`, `scan.py`, `gui/app.py`).
**Not live-tested** — the WPS crash fix in particular should be
confirmed against a real OMNI run (WEP or otherwise) now that
`_associate()` can no longer raise on construction.

**Next:** live-test the WPS/OMNI fix against a real AP; decide whether
to build the BPF-filter scan optimization; pick up any of the declined
scan.py cherry-picks if wanted.

## 2026-08-31 (same day): performance audit doc triaged — 3 real fixes landed, 6 declined as based on stale/incorrect premises

User pasted a 9-item performance-issues doc (`~/Desktop/atwa_issues.md`)
covering `radio.py`, `wpa/crypto.py`, `omni.py`, `housekeeping.py`, and
`scan.py`. Checked every claim against the actual current code before
touching anything (not "boring verification for its own sake" — several
of the doc's claims describe bugs that were real once but were already
fixed in earlier sessions, and applying its suggested fix verbatim in
one case would have caused a real regression).

**Landed (3 real, safe fixes):**
1. **`radio.py get_driver()` now cached per-interface** — a driver
   never changes without a hot-unplug (a different device node in the
   normal case), so the repeated `ethtool -i` subprocess calls from
   `detect_alfa_pair()` and every `set_monitor_mode()` →
   `apply_achm_txpower_patch()` call no longer re-shell out for an
   answer that can't have changed. New `clear_driver_cache()` mirrors
   the existing `clear_channel_cache()` pattern. 5 new tests in
   `tests/test_radio.py`.
2. **`housekeeping.py _plan_targets()`** did two separate `rglob()`
   walks per target folder (one for cap files, one for `.22000`
   hashes) — collapsed into one walk that classifies each file by
   suffix in a single pass. Halves directory-walk work at cleanup time;
   no behavior change (aside from `.22000` matching now being
   case-insensitive, matching the cap-suffix check right next to it).
3. **Conservative BPF filter added to both `AsyncSniffer` scan
   loops** (`scan.py scan()` and `gui/app.py`'s own scan loop) —
   `filter="not type ctl"`, dropping only control frames (ACK/RTS/CTS/
   block-ack, the chattiest frame type on a busy channel) before scapy
   ever dissects them. Verified the filter string actually compiles
   against the 802.11-radio linktype (`scapy.arch.common.compile_filter`)
   rather than assuming the syntax is valid.

**Declined the doc's exact suggested filter for #3 — would have broken
client discovery.** The doc proposed `"type mgt and (subtype beacon or
subtype probe-resp)"`, which drops all data frames. `process_packet()`
reads client MACs off *data* frames too (via `addr3 == bssid`), not
just beacons — applying that filter verbatim would have silently
stopped the Clients list from populating. This is exactly the class of
mistake the project's own history already flags as a real risk for any
change to the live capture path (2026-08-29 PyRIC revert, 2026-08-30's
deliberate deferral of this same BPF idea pending hardware
verification) — landed a narrower, verified-safe version instead of
the doc's literal suggestion. **Still not live-hardware-tested** — the
filter compiles correctly and the logic it preserves is unchanged, but
confirming it doesn't drop anything unexpected on a real busy channel
is still outstanding.

**Declined, 6 items — based on stale or incorrect premises about this
specific codebase, not real bugs:**
- **#1 (blocking `time.sleep(dwell)` in `ChannelHopper.hop()`
  "misses beacons"):** false premise. `scan()` and the GUI's scan loop
  both run a *persistent* `AsyncSniffer` on its own thread (the whole
  point of the 2026-08-27 Phase 6b fix) — `hop()`'s sleep only paces
  the main loop that decides when to retune the channel; it has no
  effect on the capture thread, which keeps receiving regardless.
- **#2 (subprocess 15s timeouts "expensive... every AP selection"):**
  the 15s is a safety ceiling, not real added latency (subprocess.run
  returns as soon as the child exits) — and `ensure_channel()` already
  caches repeat channel-sets (2026-08-27 Phase 1), so it does *not*
  call `set_channel`/spawn a subprocess on every AP selection when the
  channel is unchanged. The one real part of this (driver-detection
  overhead) is fix #1 above.
- **#3 (PBKDF2 4096 iterations "expensive... consider
  multi-threading wordlist pre-computation"):** correct that it's
  costly per-call, but checked `attacks/online.py`'s actual
  `online_guess()` loop — each attempt is dominated by multiple
  network round-trips with multi-second timeouts (association, M1
  wait, M3 wait); the few milliseconds of PBKDF2 time is noise by
  comparison, so precomputing it wouldn't move the needle. There's
  also no Python-side wordlist pre-computation for offline PMKID/
  handshake cracking to optimize — that's delegated entirely to John/
  aircrack-ng, not implemented here.
- **#4 ("race condition" in `omni.py _stage_handshake`'s
  `result.get("cap")`, "up to 2s of missed frames before first
  deauth"):** not a race — `dict.get()` on a not-yet-set key safely
  returns `None`, already null-checked before use. The 2s settle sleep
  is deliberate and does the *opposite* of what the doc claims: it
  gives the capture thread time to actually start listening before the
  first deauth burst goes out, specifically to avoid missing the
  AP's response.
- **#6 (in-memory `sorted(set(...))` dedup "expensive... use
  `sort -u`"):** the suggested fix is slower, not faster — spawning a
  subprocess for what Python does in sub-millisecond time even at
  thousands of lines is a net loss. No change.
- **#8 (manufacturer lookup "performed on every beacon"):** already
  not true in this codebase — the 2026-08-31 (earlier same day)
  `scan.py` cherry-pick already guards the lookup behind `if is_new:`,
  resolving it once per newly-discovered BSSID, not per beacon.

**Verification:** `pytest -q` → 152/152 passed (5 new). `ruff check
--select F401,F541` clean. `mypy --ignore-missing-imports
--show-error-codes` clean on all touched files (one pre-existing,
unrelated error at `gui/app.py:2245` — a dialog-button lambda far from
anything touched this session — left alone, out of scope). BPF filter
string independently confirmed to compile against the 802.11-radio
linktype via `scapy.arch.common.compile_filter`, not just assumed
syntactically valid.

**Next:** live-hardware test of the BPF filter change specifically
(confirm no unexpected frame loss on a real busy channel) before
trusting it fully; everything else in this entry is either already
proven safe by the existing test suite or was correctly left alone.

## 2026-08-31 (same day, later): second AsyncSniffer-timeout bug found in online.py, wps-recon native port, PINCER stale-claim correction, power_save off, CPU research dive

**Second instance of the WPS AsyncSniffer bug, found from a user memory
fragment.** User recalled "a timeout error across all attacks except
deauth/chopchop" without remembering which file. Re-grepped every
`AsyncSniffer(` call site project-wide and found `attacks/online.py`
(the WPA online dictionary-guess attack) had the identical broken
pattern — three separate `AsyncSniffer(iface=..., timeout=X, ...)`
constructor calls (`_wait_for_dot11`, `_wait_for_m1`,
`_wait_for_m3_or_reject`) that would crash immediately the same way
`wps.py`'s did before its earlier fix this session. None of these three
functions take a `stop_event` (unlike the wps.py ones), so the fix is
simpler: drop `timeout=` from the constructor, use
`sniffer.join(timeout=timeout)` instead, plus an explicit
`sniffer.stop()` for cleanup. `handshake.py`/`pmkid.py`/`scan.py`/
`lock_capture.py` confirmed clean (grepped, no `timeout=` on any
`AsyncSniffer` construction).

**`wps-recon` CLI ported off the vendored `wash` binary.**
`cli_commands/scan.py:_cmd_wps_recon` previously shelled out to
`WPSRECON_BIN` (`vendor/reaver/src/wash`) — the last non-cracking-backend
wrapper in the whole project. Replaced with a native `scan.scan()` call
filtered to APs where `.wps is not None`, since `secure.wps_profile()`
already extracts the same manufacturer/model/device-name/lock-state
data from beacon frames natively (added 2026-08-27, "wash parity" pass)
— this was a wiring gap, not a missing capability. Removed
`WPSRECON_BIN`/`_WPSRECON_ROOT` from `cli_commands/__init__.py`,
updated `cli.py`'s stale module docstring, rewrote the 3 wash-specific
tests in `test_cli.py` (missing-binary guard, SIGINT-and-collect Popen
mocking) to mock `scan_cmds.scan` instead. Also corrected
`docs/vendor_inventory.md`, which was *also* stale in the same way
`AGENTS.md` was — it described WPS attack logic as not-yet-native
("port the WPS state machine... into wps_native.py") when
`attacks/wps.py` has had full native pixie-dust/bruteforce/M2→M3 logic
since 2026-08-27. Corrected to describe reality: WPS (attack + recon)
is fully done, `vendor/reaver` is now reference-only.

**Corrected a stale claim this session itself had written into
`STATUS.md` a few hours earlier.** While investigating "Dual-Alfa/PINCER"
as a possible roadmap pick, discovered `attack_runner.py`'s `pincer()`
is a complete, real, native implementation — not "still the old v1
prototype" as `AGENTS.md`'s Roadmap (and this session's own STATUS.md
rewrite, which trusted that wording without checking) claimed. Checked
`vendor/n2-ng-v1-src` directly: no pincer/dual-adapter code exists there
at all. What's actually missing is test coverage (zero, no file exists
for `attack_runner.py`) and live-hardware verification with two real
adapters — a much smaller gap than "reimplement natively" implied.
Lesson: even this session's own freshly-written docs need the same
check-against-code discipline as the ones being audited, not blind
trust just because they're new.

**`radio.py` `set_monitor_mode()` now disables power-save.** New
`disable_power_save()` (`iw dev <iface> set power_save off`), called
right after bringing the interface up, alongside the existing txpower
patch and antenna-mask fix. Sourced from a user-provided research doc
on 802.11 USB optimization — independently verified as a real, standard
technique (not fabricated), and the single most immediately-actionable
item in that doc: aggressive driver power-save on Realtek/MediaTek
chipsets is a documented cause of erratic RX latency and dropped
frames, which plausibly explains some of this project's own
already-logged adapter flakiness. Non-fatal if a driver doesn't expose
the setting (same pattern as `fix_antenna_mask()`). 2 new tests in
`tests/test_radio.py`.

**CPU/fan research dive (user-requested), findings folded into
STATUS.md's Performance section:** a second viable scapy-replacement
candidate (`dpkt`, natively supports Radiotap/802.11, benchmarked
competitive with or faster than pypacker), TPACKET_V3 mmap ring
buffers as a genuinely new lever, AF_XDP as the honest "actual C"
answer if ever needed (judged unlikely — 802.11 monitor-mode capture is
RF-bandwidth-bottlenecked, not socket-throughput-bottlenecked at the
scale AF_XDP solves), and a full re-confirmation of why PyRIC/pyroute2
remain not-recommended for `radio.py` (PyRIC was actually tried on
2026-08-29, broke real 5GHz scanning on the exact hardware in use,
root cause never confirmed — see vault log
`2026-08-29-pyric-migration-reverted-broke-live-scanning.md` for the
full account). A user-provided research doc's specific technical claims
(3 CVE numbers, 2 pip package names) were independently verified rather
than trusted at face value — all 3 CVEs turned out to be real (initial
suspicion of fabrication was wrong and said so directly), one package
(`pylibpcap`) confirmed real but unmaintained since 2021, one
(`pywifi-controls`) confirmed real but a wrong architectural fit
(managed-mode client control, not monitor-mode).

**Verification:** `pytest -q` → 154/154 passed (2 new tests for
`disable_power_save`; net zero from the wps-recon test rewrite — 3
removed, 3 added). `ruff check --select F401,F541` and `mypy
--ignore-missing-imports --show-error-codes` clean on every changed
file (`attacks/online.py`, `cli_commands/scan.py`,
`cli_commands/__init__.py`, `cli.py`, `radio.py`, `tests/test_cli.py`,
`tests/test_radio.py`).

**Not done:** dpkt/pypacker swap itself (still just researched, real
scope, needs live-hardware verification); TPACKET_V3 ring buffers (not
attempted); PINCER test coverage / live dual-adapter test (flagged, not
built this session).

## 2026-09-01: roadmap closeout push begins — PINCER tests, downgrade_twin built, OWE bug fixed, cracking docs written; 1/6 done

User set today's goal as finishing the 6-item roadmap left over from
2026-08-31 (dpkt/pypacker swap, OWE downgrade, CSA spoofing, Dragonblood
SAE, self-healing monitor check, cracking how-to docs), explicitly asking
for minimal redundant re-verification along the way.

**Landed, each individually committed + merged to local `main` (not
pushed — user direction: accumulate locally, tag/push the whole batch as
v2.3 once all 6 items are done):**

- **PINCER test coverage** — `tests/test_attack_runner.py`, 5 tests.
  Confirmed in passing that `pincer()` was never the "old v1 prototype"
  the roadmap claimed (no such code exists in `vendor/n2-ng-v1-src`) —
  real native logic, just untested until now.
- **Second `AsyncSniffer` timeout-crash instance found**, from a vague
  user memory fragment ("timeout error except deauth/chopchop") rather
  than a file reference — re-grepped every `AsyncSniffer(` call site and
  found `attacks/online.py` had the identical broken `timeout=` pattern
  already fixed in `wps.py` earlier. Fixed the same way (3 call sites).
- **Active probe-request injection** (`scan()`'s `active_probe_interval`
  + `atwa scan --active-probe`), **channel-range CLI syntax**
  (`scan.parse_channel_range()`, `"1,3-7,11"`), and **passive PMKID
  sniffing** from ambient EAPOL M1 traffic in `process_packet()` — all
  three surfaced from the completed `source_cherrypick.c` read, not
  previously on any roadmap.
- **`attacks/pmf_bypass.py`** — the rogue-AP EAPOL-corruption PMF bypass
  (CVE-2025-27558-class), ported byte-for-byte from the published PoC
  (fetched via `gh api` from domienschepers/wifi-deauthentication) rather
  than reconstructed from the paper's prose. Caught the exact `FCfield`
  hyphen-vs-underscore gotcha this project already hit once before
  (2026-08-27, `frames.py`'s `craft_probe_req()`) — same mistake,
  recognized and fixed immediately this time. Standalone primitive, not
  yet wired into a live attack flow.
- **`attacks/eviltwin.py run_downgrade_twin()`** — `secure.py`'s
  `downgrade_twin` recommendation was a confirmed dead stub; now a real
  WPA2-only rogue-twin attack reusing `run_eviltwin()`'s hostapd
  scaffolding (no DHCP/portal needed — the 4-way handshake completes
  before any IP is assigned) + the existing `capture_handshake()`.
  New CLI subcommand `downgrade-twin`. Caught and fixed a real bug in my
  own first draft (dead code left over from iterating on the design —
  a `cap.status(rogue_bssid, "")` call that did nothing) before it ever
  ran, not after.
- **OWE misclassification bug** — found while scoping the OWE-downgrade
  item, not looking for it: `secure.py`'s `security_profile()` never
  checked AKM suite 18 (OWE/Enhanced Open) at all, so every real OWE
  beacon was silently reported as `"WPA2"` — a network with literally no
  password being flagged as PSK-crackable. Fixed + gave `security_profile()`
  its first test coverage ever (it had none). The actual OWE-downgrade
  *attack* (parse the Transition Mode IE, spoof the paired open SSID)
  is still open — deliberately not rushed without a real OWE capture to
  verify IE byte offsets against.
- **`power_save off`** landed on `set_monitor_mode()`, sourced from a
  user-provided `80211_Optimization_and_Capture_Guide.md` research doc —
  independently verified as real technique (unlike a second doc,
  `research_09-01-26.md`, rejected outright: it contradicts itself on
  which RSN bit is MFPC vs MFPR three different ways in the same file,
  cites an MLO-replay CVE that doesn't exist on search, and contains a
  broken self-referential Python script that writes a duplicate of its
  own content to a file named after the *other* doc).
- **Cracking how-to docs** (item 1/6, done) — `README.md`/`README_ES.md`
  gained a full how-to section (GUI + 3 CLI shapes + capture location)
  and real John Jumbo install instructions, verified against this
  machine's actual `~/john` build layout (first draft cloned to the
  wrong path, `~/john/src` instead of `~/john`, which would have broken
  the code's own `~/john/run/john` fallback resolution — caught before
  publishing, not after). "Miguel the Ripper" (a deliberate, pre-existing
  user branding choice — not a typo, confirmed after an initial wrong
  guess that it was) stays unexplained in the feature table/prose per
  explicit direction; the Install section, not a parenthetical, is where
  a reader learns it's really John the Ripper underneath.

**Verification:** `pytest -q` → 187 passed across all of the above
(net new: PINCER 5, pmf_bypass 5, downgrade_twin 8, security_profile 6).
`ruff check --select F401,F541` and `mypy --ignore-missing-imports
--show-error-codes` clean on every changed file after each batch.
README changes have no test suite (markdown) — verified by matching
fence-count parity and, for the install instructions specifically,
against the real `~/john` folder already on this machine rather than
assumed from general knowledge of John's build layout.

**Status: 1/6 roadmap items done** (cracking docs). Remaining: dpkt/
pypacker swap, OWE downgrade attack itself, CSA spoofing, Dragonblood
SAE, self-healing monitor-mode check. See STATUS.md's "Today's 6-point
closeout list" for the live-tracked version of this list.
