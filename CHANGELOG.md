# Changelog

All notable changes to ATWA-NG are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`update-check` reads the latest *published* GitHub Release, so a change is only
visible to users checking for updates once its release is published — not when
the commit lands.

## [2.5.7] - 2026-09-26

### Fixed

- **Flood attacks no longer freeze the interface at `interval=0`.** Every
  send loop in `deauth`, `auth_flood`, `beacon_flood`, `csa_spoof`,
  `eapol_flood` and `tkip_mic_flood` guarded its inter-frame sleep with
  `if interval`, so a zero interval skipped the sleep entirely. That removed
  the only point where the thread released the GIL, and a maximum-speed flood
  starved every other thread — the GUI stopped repainting and `Ctrl-C` went
  unresponsive for the duration of the run. The sleep is now unconditional:
  `time.sleep(0.0)` is still a real syscall, so it yields the GIL every frame
  while adding no delay. Affects anyone running a flood with no inter-frame
  delay, which is the common case for a speed test.
- **Update check no longer crashes on non-numeric or zero-padded tags.** In
  `update_check._version_parts`, a tag with no leading number (`release-candidate`,
  a stray `latest`) raised `TypeError` by comparing a bare string against every
  normal version, taking down the whole check. Separately, a tag with an
  explicit trailing zero (`2.5.0-beta`) produced one more numeric component
  than its equivalent without it (`2.5-alpha`), which shifted the suffix
  marker's position until it collided with a numeric `(0, 0)` and raised the
  same `TypeError`. Both branches now trim trailing zeros before appending
  their marker, so equivalent versions compare equal. The `cast` that papered
  over the mixed-shape return type is gone; the annotation is now honest.

### Changed

- Added `tools/anti_slop`, a linter that fails on type-safety escape hatches
  (`Any` parameters and returns, chained casts, `type: ignore`) and reports
  architectural smells such as module mocking and `getattr` dispatch. Runs
  alongside `ruff` and `mypy`. Configured under `[tool.anti-slop]` in
  `pyproject.toml`; the `recommended` preset keeps escape-hatch rules at
  `error` and architectural rules at `warn`.

## [2.5.6] - 2026-09-26

### Added

- CHAOS, a coordinated multi-vector flood, runnable from both `atwa chaos` and
  the GUI.
- `graphify-out/` is now committed, so the code knowledge graph travels with
  the repository. Scope is code only (`src/` + `vendor/`); its regenerable
  caches and dated backups stay ignored.

### Changed

- `README.md` and `README_ES.md` rewritten as a scanning and attacking feature
  tour, with no internal process detail.
- Consolidated internal documentation into `AGENTS.md`; retired `READFIRST.md`,
  `RELEASING.md`, `docs/vendor_inventory.md` and the issues list.

[2.5.7]: https://github.com/KiMiGuel/ATWA-NG/releases/tag/v2.5.7
[2.5.6]: https://github.com/KiMiGuel/ATWA-NG/releases/tag/v2.5.6
