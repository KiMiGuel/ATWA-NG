# Plan: WiFi Pentest + Password Cracking Research Swarm

## Stage 1 — Deep Research (skill: deep-research-swarm, Route A Wide Search)
Parallel research agents, each producing a markdown brief in /mnt/agents/output/research/:
1. agent-wpa-attacks: Modernized WEP/WPA/WPA2/WPA3 attacks (2023-2026) — KRACK successors, FragAttacks, Dragonblood, downgrade attacks, WPA3 transition mode flaws, tools (bettercap, hcxdumptool, airgeddon).
2. agent-eviltwin: Newest Evil Twin source code & frameworks — wifipumpkin3, airgeddon captive portals, fluxion forks, eaphammer, hostapd-mana, KARMA/MANA attacks, GitHub repos with recent commits.
3. agent-80211: Newest IEEE 802.11 attacks — PMKID capture (hashcat 22000 mode), deauth evolution, beacon/frame injection, WEP key & PIN attacks (WPS pixie-dust, reaver/bully modern forks), 802.11w/PMF bypass.
4. agent-pwcrack: Password cracking research papers — theory & application (PCFG, PRINCE, PassGAN/ML-based guessing, guessing curves, Prob-Hashcat, S&P/USENIX/IEEE papers 2019-2026).
5. agent-wifipentest-landscape: Latest WiFi pentesting landscape 2025-2026 — new tools, hashcat modes, WiFi 6/6E/7 security, cloud cracking, notable CVEs & conference talks (DEF CON, Black Hat).

## Stage 2 — Validate & Synthesize
- Reviewer cross-checks briefs: verify tool names/repos/versions real, remove dupes, flag gaps.
- Merge into master summary RESEARCH_SUMMARY.md.

## Stage 3 — Package
- Zip /mnt/agents/output/research/ → /mnt/agents/output/wifi_pentest_research.zip
