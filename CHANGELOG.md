# Changelog

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

[2.5.7]: https://github.com/KiMiGuel/ATWA-NG/releases/tag/v2.5.7
[2.5.6]: https://github.com/KiMiGuel/ATWA-NG/releases/tag/v2.5.6
