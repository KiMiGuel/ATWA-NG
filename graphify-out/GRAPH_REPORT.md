# Graph Report - ATWA-NG  (2026-09-26)

## Corpus Check
- 448 files · ~504,364 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 472 nodes · 884 edges · 18 communities (16 shown, 2 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 44 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `536779be`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_chaos.py
- test_dissect_radiotap_channel.py
- test_live_findings_2026_09_25.py
- README_ES.md
- cli.py
- App
- test_injection_test.py
- AttackRunner
- ._run_capture_task
- test_attack_runner.py
- ._sync_iface_display
- AccessPoint
- ._build_body
- ._log
- ._on_tree_heading_release
- ._lock_channel
- .__init__
- ._auto_deauth_run

## God Nodes (most connected - your core abstractions)
1. `App` - 128 edges
2. `AttackRunner` - 36 edges
3. `build_parser()` - 20 edges
4. `ChaosResult` - 12 edges
5. `Frame` - 12 edges
6. `injection_test()` - 12 edges
7. `chaos()` - 11 edges
8. `VectorResult` - 10 edges
9. `InjectionTestResult` - 10 edges
10. `_args()` - 10 edges

## Surprising Connections (you probably didn't know these)
- `_make_runner()` --uses--> `AttackRunner`  [INFERRED]
  tests/test_attack_runner.py → src/atwa/gui/attack_runner.py
- `_beacon_with_ies()` --uses--> `Frame`  [INFERRED]
  tests/test_live_findings_2026_09_25.py → src/atwa/dissect.py
- `test_injection_test_percent_zero_when_nothing_sent()` --uses--> `InjectionTestResult`  [INFERRED]
  tests/test_injection_test.py → src/atwa/injection_test.py
- `test_txpower_note_is_calm_when_healthy()` --uses--> `InjectionTestResult`  [INFERRED]
  tests/test_injection_test.py → src/atwa/injection_test.py
- `test_txpower_note_reports_headroom_against_the_domain()` --uses--> `InjectionTestResult`  [INFERRED]
  tests/test_injection_test.py → src/atwa/injection_test.py

## Import Cycles
- None detected.

## Communities (18 total, 2 thin omitted)

### Community 0 - "test_chaos.py"
Cohesion: 0.08
Nodes (38): Event, fixture, chaos(), ChaosResult, CHAOS: coordinated multi-vector flood against a single target. Every other…, Run one vector, returning (frames_sent, human effect note)., Run every vector against ``bssid`` at every tier, reporting each.…, Outcome of one (vector, tier) cell. ``frames`` is what was handed to the OS and… (+30 more)

### Community 1 - "test_dissect_radiotap_channel.py"
Cohesion: 0.06
Nodes (56): beacon_capability(), _channel_from_hz(), channel_of(), dissect(), eapol_key_info(), _eapol_payload(), _fast_radiotap_header(), Frame (+48 more)

### Community 2 - "test_live_findings_2026_09_25.py"
Cohesion: 0.09
Nodes (30): _args(), _beacon_with_ies(), Regression tests for the four defects found by live hardware testing on…, CHALLENGE is M1+M2 and is genuinely crackable offline, so it is a success --…, Synthesize a minimal beacon Frame carrying the given IEs. Mirrors the real…, Build a minimal RSN element body with the given pairwise selector., WPS/P2P reserves the 01:80:c2 OUI, not just the all-zero tail., CCMP is selector 4. This used to fall through to 'unknown'. (+22 more)

### Community 3 - "README_ES.md"
Cohesion: 0.08
Nodes (24): Attacks, Cracking, Cómo usarlo, 🚩 Insignia: PINCER — Ataque Dual-WiFi, Instalación, La última herramienta de pentesting WiFi que vas a necesitar, Lanzamientos y comprobación de actualizaciones, N2-NG acaba de ser REVAMPEADO. 🔥 (+16 more)

### Community 4 - "cli.py"
Cohesion: 0.20
Nodes (21): ArgumentParser, build_parser(), _cmd_deauth(), _cmd_downgrade_twin(), _cmd_dragonblood(), _cmd_handshake(), _cmd_omni(), _cmd_owe_downgrade() (+13 more)

### Community 5 - "App"
Cohesion: 0.07
Nodes (17): App, Build an AttackRunner from current App state., Run a background task and report its lifecycle to the GUI. ``result_kind`` is…, Right-click a column header to show/hide it (deferred earlier since it wanted…, Modal countdown confirm before firing an attack. Attacks are native calls, not…, The native from-scratch chopchop (ICV-correction math) was confirmed broken by…, Auto-deauth uses the selected client station, or the strongest observed client…, Live per-password 4-way handshake attempt against the AP itself… (+9 more)

### Community 6 - "test_injection_test.py"
Cohesion: 0.05
Nodes (44): _cmd_injection_test(), _cmd_scan(), _cmd_wps_recon(), Scan and reconnaissance subcommands., Native scapy channel-hopping scan (scan.py) — no external engine., Native injection self-test — confirms the adapter can actually inject frames…, WPS-enabled AP reconnaissance — native passive scan filtered to WPS-advertising…, _current_txpower() (+36 more)

### Community 7 - "AttackRunner"
Cohesion: 0.06
Nodes (6): AttackRunner, Event, Run the coordinated multi-vector flood and return its summary. 2026-09-26: the…, Thin orchestration layer between the Tkinter App and the attack implementations…, SAE (WPA3) timing side-channel wordlist pruning (CVE-2019-9494) -- see…, None if deauth is worth attempting against ap, else the reason it isn't -- same…

### Community 8 - "._run_capture_task"
Cohesion: 0.11
Nodes (7): Run a Captures-tab operation without attack/monitor semantics., Real per-machine John speed (candidates/sec) via John's own --test self-…, Crack the selected file(s): .22000 -> John, .cap/.pcap/.pcapng -> aircrack-ng…, cap_paths (optional): raw .cap/.pcap/.pcapng files to convert to 22000 first,…, Quick button: force John on the current selection regardless of file type (caps…, Quick button: force aircrack-ng on the current selection., Preview then run housekeeping.cleanup_handshakes — merges each target's…

### Community 9 - "test_attack_runner.py"
Cohesion: 0.24
Nodes (14): main(), ATWA-NG GUI — Tkinter, wired to this project's own native attack functions…, Attack orchestration logic extracted from gui/app.py. AttackRunner holds the…, FakeAP, _make_runner(), _patch_radio(), Tests for gui/attack_runner.py -- specifically pincer(), which had zero…, The GUI CHAOS wrapper must surface the summary, which names observed effects --… (+6 more)

### Community 10 - "._sync_iface_display"
Cohesion: 0.18
Nodes (4): Point display_var at name_var's current bare iface name's SHORT display string…, Rough driver-name -> vendor label, purely so wlan0/wlan1 in the toolbar are…, Refresh adapter_mac_var from the currently-selected adapter's MAC. Kept out of…, StringVar

### Community 11 - "AccessPoint"
Cohesion: 0.20
Nodes (5): AccessPoint, Render an SSID for the tree. Real, non-UTF8 SSIDs decode fine (frames.py falls…, Column width = actual longest rendered value (header or any current row), not a…, Fires on both a real user click AND _render_targets()'s own…, Live KB readout of any existing capture data for the selected target. Reads…

### Community 12 - "._build_body"
Cohesion: 0.20
Nodes (4): Frame, displaycolumns, not width=0 — a zero-width column is still a clickable sliver…, Canvas+Scrollbar wrapper — the Target tab's content (signal graph + 10 attack…, skip: widgets whose own subtree gets a dedicated scroller instead (e.g. the…

### Community 13 - "._log"
Cohesion: 0.22
Nodes (3): Resume hopping the full channel range., Auto-unlock if the locked target hasn't been seen for CHANNEL_LOCK_TIMEOUT., Dedicated Stop button for the Captures panel -- the generic 'Stop Attack'…

### Community 14 - "._on_tree_heading_release"
Cohesion: 0.29
Nodes (4): Same column released as pressed -> plain click -> sort (what ttk's own heading…, identify_column() returns '#N' (1-indexed position among currently VISIBLE…, Swap two columns' positions (drag one heading onto another). Persisted the same…, Click a column heading to sort by it; click again to reverse.

### Community 15 - "._lock_channel"
Cohesion: 0.25
Nodes (3): Redundant with single-click since 2026-08-26 (select now locks too, see…, Stop hopping and park the adapter on ap's channel. Also starts a native packet…, Native AsyncSniffer-backed capture (lock_capture.LockCapture), restricted to…

## Knowledge Gaps
- **22 isolated node(s):** `Attacks`, `Cracking`, `Cómo usarlo`, `🚩 Insignia: PINCER — Ataque Dual-WiFi`, `Instalación` (+17 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `App` connect `App` to `test_dissect_radiotap_channel.py`, `AttackRunner`, `._run_capture_task`, `test_attack_runner.py`, `._sync_iface_display`, `AccessPoint`, `._build_body`, `._log`, `._on_tree_heading_release`, `._lock_channel`, `.__init__`, `._auto_deauth_run`?**
  _High betweenness centrality (0.645) - this node is a cross-community bridge._
- **Why does `Frame` connect `test_dissect_radiotap_channel.py` to `test_live_findings_2026_09_25.py`?**
  _High betweenness centrality (0.427) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `AttackRunner` (e.g. with `App` and `_make_runner()`) actually correct?**
  _`AttackRunner` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 16 inferred relationships involving `build_parser()` (e.g. with `_cmd_chaos()` and `_cmd_deauth()`) actually correct?**
  _`build_parser()` has 16 INFERRED edges - model-reasoned connections that need verification._
- **Are the 7 inferred relationships involving `ChaosResult` (e.g. with `test_cli_exits_zero_when_nothing_bit_but_ran()` and `test_cli_passes_vectors_and_tiers_through()`) actually correct?**
  _`ChaosResult` has 7 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `Frame` (e.g. with `test_frame_still_parses_ies_correctly()` and `_beacon_with_ies()`) actually correct?**
  _`Frame` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Attacks`, `Cracking`, `Cómo usarlo` to the rest of the system?**
  _22 weakly-connected nodes found - possible documentation gaps or missing edges._