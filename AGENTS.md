# ATWA-NG — Agent Instructions

Standalone WiFi security auditing tool, package `atwa`. Renamed and
relocated 2026-08-25 from `~/N2-NG_v2/.simulation/N2-NGv2` (was
`n2ngv2`) into its own dedicated home. Read by both Claude Code (as
`CLAUDE.md`, symlinked to this file) and Kimi Code (as `AGENTS.md`).

## Vault connection
Dedicated, isolated vault: `~/CCM2` (read `~/CCM2/CLAUDE.md` for full
rules — `/resume`, `/save`, Zettelkasten conventions). **Not** `~/CCM` —
that vault covers other, less sensitive projects and this one stays out
of it. Vault section: `~/CCM2/ATWA-NG/` — logs: `~/CCM2/ATWA-NG/logs/`,
decisions: `~/CCM2/ATWA-NG/architecture/decisions.md`. Knowledge graph:
`~/CCM2/graphify/ATWA-NG/` — regenerate with `/graphify <path>
--obsidian --obsidian-dir ~/CCM2/graphify/ATWA-NG` after structural
changes.

## Context Navigation (3-Layer Query Rule)
1. Query `~/CCM2/graphify/ATWA-NG/` for code structure (if present)
2. Query `~/CCM2/ATWA-NG/` vault notes for decisions/progress
3. Read raw code files only when editing, or when layers 1-2 don't have
   the answer

## Objective
Native Python implementations of WiFi attack concepts (scan, monitor,
deauth, handshake capture, PMKID, WPS, WEP, evil twin, online guess,
cracking). Scanning and injection are **fully native, zero
vendored-engine fallback** — `airodump-ng`/`aireplay-ng` code paths were
deliberately, completely removed (Phase 6b/6c, 2026-08-27), not flagged
off. The only permanent vendored/wrapped components are cracking
backends (John the Ripper jumbo, `aircrack-ng` as an optional alternate)
and cap/pcap-format tools (`hcxpcapngtool`, `wpapcap2john`) — never
scanning, injection, WPS, or monitor control. Keep OMNI/Smart/
PMKID-less attack logic intact.

## Decisions
- Cracking engine: **John the Ripper (jumbo)** — NOT hashcat. Supports
  22000 via `--format=wpapsk`; `.cap`/`.pcap` via
  hcxpcapngtool/wpapcap2john.
- Package/launch name: `atwa`. Display name "ATWA-NG" — never spell out
  what "NG" stands for in user-facing text.

## Rules
- **Worktree/main sync**: multiple worktrees/branches can merge into
  `main` independently (2026-09-04: a worktree fell behind `main` by 5
  commits — OWE fix, pmf_bypass, downgrade_twin, cracking docs — landed
  via a different branch with nobody syncing it back). At the START of
  every session, before any new work, run `git merge main --ff-only` in
  the current worktree (falls back to `git merge main` if that fails,
  i.e. main has actually diverged) — worktrees share one `.git`, so this
  needs no fetch. After merging a worktree branch into `main`, do NOT
  assume other worktrees picked it up automatically; they didn't.
- `github.com/KiMiGuel/ATWA-NG` is live (has been since ~2026-08-28) —
  pushes/tags are fine. The old "TOP SECRET, no GitHub push" note is
  retired; the still-active boundary is just no mixing into `~/CCM`
  (the other vault) — `~/CCM2` stays the only vault this project uses.
- Do NOT touch `~/CCM` (the other vault), `~/n2-ng` (original v1 repo),
  or `~/N2-NG_v2` (now just the older, unrelated `n2ng2` codebase — not
  part of this project)
- Session state: append to `CHECKPOINT.md` locally when an objective
  completes, AND log to `~/CCM2/ATWA-NG/logs/` per the vault's `/save`
  format — both, not one instead of the other
- Work only inside this repo (code) / `~/CCM2` (vault notes)
- **Never read, cat, or grep-without-redaction `~/.graphify.env` or any
  API key file — it is not `KEY=value` format, it's a bare key with no
  `=`, so naive redaction patterns fail open and print it raw. Source it
  only via command substitution so the value stays in a subprocess
  environment and never appears in tool output.**
- The fixed capture directory is `~/atwa-hs` — see `storage.py`'s
  `capture_root()` (its own "do not change it" comment applies to this
  path). A `~/hs/n2-ng` directory may still exist on machines used
  before the 2026-08-25 rename — that's leftover pre-rename data, not
  a path any current atwa code writes to.
- No image/logo/color-theme work without being explicitly asked — see
  Roadmap below for current branding status.

## Roadmap
- [x] Rename sweep (n2ngv2 → atwa/ATWA-NG), relocate to own home
- [x] Publish decision — resolved: dedicated new repo (not a
      replacement of `n2-ng`), live at `github.com/KiMiGuel/ATWA-NG`
      since 2026-08-28. Pushes/tags/releases are routine now.
- [ ] Dual-Alfa mode (two Alfa adapters in parallel; was prototyped in
      the old v1 repo, buggy — reimplement natively)
- [x] Color-theme/logo integration — substantially complete as of
      2026-08-27 (see vault `decisions.md`'s Branding section): palette,
      icons, toolbar logo, About dialog all done. Re-open only if new
      brand-asset work is explicitly requested.
