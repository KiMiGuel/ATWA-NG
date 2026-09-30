# Changelog

## [2.6.1] - 2026-09-29

### Fixed
- `deauth()` recovers from the USB-dongle socket reset (ENETDOWN/ENODEV right
  after a transmitted frame) by closing, reopening and retrying the frame
  instead of aborting the whole burst after the first send.
- `deauth()` no longer toggles active monitor off when the burst ends. The
  toggle is an interface down/up cycle that tore down every other socket on
  the interface (e.g. the GUI's live capture), and PINCER-style per-round
  deauth calls flapped it twice per round. It is still requested once up
  front; leaving it on is harmless.
- Directed deauth counts a round's AP->client frame even when the client->AP
  send dies mid-round (the returned frame total no longer undercounts).
- GUI sudo relaunch uses cached sudo credentials when present (no password
  dialog) and passes the editable-install path through to the root re-exec
  inline, so root actually finds the `atwa` package.
- `atwa crack` works for the unprivileged user again: the hcxhashtool
  `--john=` conversion now writes to the system temp dir instead of next
  to the hashfile (captures under `~/atwa-hs` are root-owned after any
  sudo run, and hcxhashtool exits 0 even when it cannot open its output
  file there, so the failure surfaced as a misleading "no valid
  handshake" error), and John's `--session` .rec/.log files moved from
  the root-owned `~/atwa-hs/.john-sessions` to the user cache dir
  (`$XDG_CACHE_HOME/atwa/john-sessions`). A conversion that still
  produces no output now reports what hcxhashtool actually said.
- `verify-handshake` and `eapol-hunt` fail with a clear error when the
  vendored helper script is missing instead of crashing with a raw
  FileNotFoundError traceback.
- `mypy src/` is clean again (theme style annotation, scapy override); plain
  `pytest` from the repo root no longer descends into `vendor/`.

## [2.6.0] - 2026-09-29

### Fixed
- PMKID hashes now use the real `WPA*01*` 22000 format. The previous
  16800-style lines were rejected by hcxhashtool ("no hashes loaded"),
  john, the GUI hash inspector and the housekeeping merge — captured
  PMKIDs never reached a cracker at all.
- John cracking reports the exact password: results now come from the
  pot file instead of `john --show`, which glued hash metadata
  (IV/MAC/ESSID/"converted by hcxhashtool") onto every reported password.
- aircrack parsing keeps `]` inside the password (`KEY FOUND! [ a]b ]`).
- Handshake capture no longer deletes a previous run's pcap when a re-run
  sees no EAPOL, and no longer mistakes a group-key (GTK rekey) message
  for a 4-way M3 (false AUTHORIZED / early sniff stop).
- PMKID capture only accepts M1 frames addressed to the target client —
  a foreign station's M1 used to produce an uncrackable phantom success.
- Scanner attributes clients correctly on bridged networks (DS-bit BSSID
  selection) and ignores multicast group addresses.
- WEP-104 recovery works again: PTW votes come only from real keystream
  bytes (zero-padding drowned the true counts), and the known ARP
  plaintext is extended to 15 bytes to cover all 13 key positions.
- Converters start from a clean output file — hcxtools append, so a stale
  file from an earlier run used to pass the "wrote nothing" guard and
  hand john the previous capture's hashes.
- `atwa update` runs `git pull`/`pip install -e .` inside the ATWA-NG
  checkout, never whatever directory the command was launched from;
  version comparison no longer ranks `3.0.1` below `3.0.0`.
- GUI: no more cross-thread Tk variable reads; "Inspect All" previews
  deletions instead of unlinking before the report opens; Stop Attack and
  window-close genuinely stop auto-deauth and terminate crack subprocesses;
  Stop during OMNI no longer launches the crack stage; false
  "AUTHORIZED captured" dialog on networks whose SSID contains the word.
- WPS: the M2 resend-timer chain can no longer outlive a timeout as an
  unstoppable zombie; pixie-dust tries the zero-ES case unconditionally
  and sweeps bad-checksum PINs like pixiewps does.
- Clean CLI errors instead of tracebacks: missing john, headless
  `atwa gui` (no $DISPLAY), radio errors, WPS timeouts.
- Dragonblood timing capture works with uppercase MACs; radio helpers
  degrade gracefully when a system binary is missing.

### Changed
- CLI startup: `atwa --help` 523ms → 114ms (-78%) via lazy subcommand
  dispatch (handlers imported only when invoked), plus dpkt deferred to
  the parse fallback (-40ms). Regression-guarded by tests.
- Dead code removed from `wps/oneshot.py` (write-only fields).

## [2.5.7] - 2026-09-26

### Fixed
- GUI stalled during long floods at `interval=0`, most visibly in CHAOS at
  high tiers.
- Update check crashed when comparing a zero-padded pre-release tag against
  an unpadded one (`2.5.0-beta` vs `2.5-alpha`).

## [2.5.6] - 2026-09-26

### Added
- CHAOS, a coordinated multi-vector flood, from `atwa chaos` and the GUI.
- Code knowledge graph committed to the repo (`graphify-out/`).

### Changed
- README and README_ES rewritten as a feature tour.
- Internal docs consolidated into AGENTS.md.

[2.6.0]: https://github.com/KiMiGuel/ATWA-NG/releases/tag/v2.6.0
[2.5.7]: https://github.com/KiMiGuel/ATWA-NG/releases/tag/v2.5.7
[2.5.6]: https://github.com/KiMiGuel/ATWA-NG/releases/tag/v2.5.6
