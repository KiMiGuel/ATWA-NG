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
deauth, handshake capture, PMKID, cracking) plus the vendored v1
scanning engine (aircrack-ng/reaver source), unified. Keep OMNI/Smart/
PMKID-less attack logic intact.

## Decisions
- Cracking engine: **John the Ripper (jumbo)** — NOT hashcat. Supports
  22000 via `--format=wpapsk`; `.cap`/`.pcap` via
  hcxpcapngtool/wpapcap2john.
- Package/launch name: `atwa`. Display name "ATWA-NG" — never spell out
  what "NG" stands for in user-facing text.

## Rules
- TOP SECRET for now: no GitHub push, no mixing into `~/CCM`. Local +
  `~/CCM2` only.
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
- The `~/hs/n2-ng` capture directory path is intentionally unchanged by
  the rename — see `storage.py`'s own "do not change it" comment.
- No image/logo/color-theme work without being explicitly asked — brand
  assets are still in draft (see vault decisions.md).

## Roadmap
- [x] Rename sweep (n2ngv2 → atwa/ATWA-NG), relocate to own home
- [ ] Publish decision (new repo vs. replacing `n2-ng` on GitHub) —
      explicitly deferred, not to be decided autonomously
- [ ] Dual-Alfa mode (two Alfa adapters in parallel; was prototyped in
      the old v1 repo, buggy — reimplement natively)
- [ ] Color-theme/logo integration, once real brand assets are ready
