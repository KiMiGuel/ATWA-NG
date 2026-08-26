# Cross-Verification of the 5 WiFi/Password Research Briefs
**Verified 2026-07-29** via GitHub REST API (37 repos, 5 latest-release checks), arXiv API (6 IDs), and independent web sources (hashcat forum, NDSS program, arstechnica, parrotsec.org, S&P'26 paper PDF).

---

## Confidence tier per file

| File | Tier | Rationale |
|---|---|---|
| wifiresearch_modern_wpa_attacks.md | **HIGH** | AirSnitch, CVE-2023-52424, DragonShift, wacker, hcxdumptool 7.1.2, bettercap v2.41.7, airgeddon v12.01 all independently confirmed. One venue error (see failures). |
| wifiresearch_evil_twin.md | **HIGH** | All 9 Tier-1 repo URLs verified live with matching stars/push dates (e.g., hostapd-mana pushed 2026-07-28, 614★ — exact match); Parrot OS 7.0 (Dec 2025) confirmed via parrotsec.org. airgeddon version slightly stale (v12.0 vs current v12.01). |
| wifiresearch_80211_pmkid_wps.md | **HIGH** (with flags) | hashcat v7.0.0, arXiv:2412.15381, CVE-2023-52424/WiSec'24, Framing Frames, all paper/CVE claims verified. Flags: stale hcxdumptool "current" version; one dead repo URL. |
| wifiresearch_password_cracking_papers.md | **HIGH** | 6/6 spot-checked arXiv IDs resolve to exactly the claimed titles (MoPE 2509.16558, MAYA 2504.16651, KAPG 2510.23036, SE#PCFG 2306.06824, meters 2505.08292). KNNGuess NDSS'26 confirmed on ndss-symposium.org with the exact 25.4%/100-guesses figure. PassLLM USENIX'25 + S&P'26 "Foundation LLMs" paper both real. Minor author-name typo. |
| wifiresearch_landscape_2026.md | **HIGH** | hashcat v7.0.0 (2025-08-01) / v7.1.2 (2025-08-23) dates and feature lists match hashcat forum announcements verbatim. CVE-2024-30078 and router CVEs consistent with public records. wifite2 feature link points at stale upstream PR (minor). |

---

## Verified-correct key claims (spot-check sample, 15)

1. **AirSnitch, NDSS 2026 (Feb 25–26, 2026)**, Zhou (UC Riverside) & Vanhoef (KU Leuven); GTK-abuse / gateway-bounce / cross-BSSID port-stealing; does not break WPA2/3 crypto — confirmed via NDSS 2026 program, arstechnica (2026-02-26), and repo `vanhoefm/airsnitch` (780★, pushed 2026-03-13) — matches brief exactly.
2. **SSID Confusion = CVE-2023-52424**, Gollier & Vanhoef, affects WEP→WPA3/802.1X/AMPE/FILS, VPN auto-disable, IEEE doc 11-24-0938 — confirmed via NVD/MITRE entry and papers.mathyvanhoef.com/wisec2024.pdf.
3. **DragonShift** `jabbaw0nky/DragonShift` — 66★, last push 2024-08-25; hostapd-mana-based WPA3 transition-mode downgrade — matches.
4. **AirBully** `lutfizp/AirBully` — 9★, pushed 2025-05-07 — matches (small but real).
5. **hashcat v7.0.0 released 2025-08-01** (900k LOC, 105 contributors, Assimilation/Python bridges, autodetection); **v7.1.2 = 2025-08-23** (Hashtopolis status-mode hotfix, Rust bridge) — confirmed via hashcat forum threads 13330/13353.
6. **hcxdumptool / hcxtools 7.1.2 released 2026-02-08** (GitHub latest release) — confirms modern_wpa_attacks' version table.
7. **airgeddon v12.01 released 2026-07-13**; repo 7,881★, pushed 2026-07-18 — matches both briefs (evil_twin's "v12.0, May 2026" is the prior release).
8. **bettercap v2.41.7, 2026-05-11** — confirmed via GitHub releases.
9. **MoPE** — arXiv:2509.16558 exists, exact title "MoPE: A Mixture of Password Experts for Improving Password Guessing" (2025-09-20).
10. **KNNGuess NDSS 2026** — confirmed on ndss-symposium.org; 25.40% (common users) within 100 guesses, avg 18.09% over Pass2Edit/PointerGuess — brief's numbers are accurate.
11. **PassLLM (USENIX Security 2025)**, Zou/An/Wang — confirmed via Zenodo artifact + citations; unofficial code `Tzohar/PassLLM` exists (112★).
12. **"Can Foundation LLMs Accurately Estimate Password Strength…?" IEEE S&P 2026** — real (Pickering et al., U Chicago); PDF at blaseur.com returns 200.
13. **WPA3 captive-portal password recovery** — arXiv:2412.15381 exists with the claimed title (Dec 2024).
14. **Parrot OS 7.0 released Dec 24, 2025** — confirmed via parrotsec.org release notes.
15. **WPS/WEP negative results** (no new WEP cryptanalysis or WPS CVEs 2022–2026) — consistent with all sources checked; repos reaver-t6x, pixiewps, bully all exist and are active/archived as described.
16. All other top repo URLs live with matching metadata: hcxdumptool (2,168★), hcxtools, hashcat, mdk4 (tag 4.2), aircrack-ng, kimocoder/wifite2 (pushed 2026-07-21) vs derv82/wifite2 (stale 2024-08-20), wacker (366★, 2023-07), fragattacks, macstealer, krackattacks-scripts, eaphammer (2,536★, 2024-09-22), wifiphisher (14,715★), garywill/linux-router, berate_ap, wifipumpkin3, fluxion, create_ap (**archived 2023-12-13** — confirmed), sensepost/mana, wpa_sycophant, KeyofBlueS/airgeddon-plugins, xpz3/airgeddonplugins (both real, distinct repos), vanhoefm/dragonslayer **and** vanhoefm/dragonblood (both exist), pcfg_cracker, PassGAN, OMEN, cupp, zxcvbn, princeprocessor, r00kie-kr00kie, maraudercentauri, domienschepers/wifi-framing, Esser50K/EvilTwinFramework, InfamousSYN/rogue.

---

## Claims that FAILED verification / need correction

1. **[modern_wpa_attacks] SSID Confusion venue wrong**: brief says "Presented at USENIX Security 2024". It was **ACM WiSec 2024** (Seoul) — the 80211_pmkid_wps brief gets this right; papers.mathyvanhoef.com/wisec2024.pdf and the WiSec DOI (10.1145/3643833.3656126) confirm. Cross-file contradiction — WiSec'24 is correct.
2. **[80211_pmkid_wps] Stale "current" hcxdumptool version**: brief calls **v7.0.1 (Sep 2025)** the current release; GitHub shows **7.1.2 (2026-02-08)** as latest — contradicts modern_wpa_attacks (which is correct). Also says hcxtools 7.1.0 where 7.1.2 exists. Not fabricated, just out of date — self-inconsistent with its own claim of being compiled 2026-07-29.
3. **[80211_pmkid_wps] Dead repo URL**: `https://github.com/drygdryg/OneShot` returns **404 (Not Found)** as of 2026-07-29. The OneShot tool is real (active forks: Rem01Gaming/OneShot-Termux etc.), but this specific URL is broken — the only dead link among ~37 checked.
4. **[password_cracking_papers] Author typo**: S&P'26 strength-estimation paper attributed to "Blaser et al." — correct lead author is **Pickering et al.** (Blase Ur is senior author; blaseur.com is the lab site). Paper itself is real.
5. **[landscape_2026] wifite2 citation mismatch**: the v2.8.1/2.8.2 feature claims link to a PR on `derv82/wifite2`, which has been stale since 2024-08-20 (confirmed). The features are attributed to the kimocoder fork elsewhere in the same file set — the derv82 PR link is dubious; kimocoder/wifite2 (pushed 2026-07-21) is the live repo.

## Unverified (not falsified, not confirmed — out of spot-check scope)
- Kernel CVE specifics (CVE-2024-35838, -26779, -27048, -58061, CVE-2025-38644, CVE-2026-46152) — plausible, not individually checked.
- Some 2025 router CVEs in landscape_2026 (spot-checked CVE-2024-30078 only, which is real); GreyNoise/Forescout attributions.
- Throughput figures (~1.6–1.8 MH/s WPA on RTX 4090; ~200 kH/s per GPU in landscape §6 — these two differ by ~9× and were not benchmarked; the 22000 mode figure of ~1.6–1.8 MH/s on a 4090 is the commonly cited one, so landscape's "200 kH/s" is suspicious/inconsistent).
- Blancco "31% of 802.1X accept any cert" survey figure (secondary citation).
- airgeddon plugin feature lists (Dragon Drain plugin, mass_handshake_capture.sh).

## Dedup / contradiction notes
- **hcxdumptool current version**: modern (7.1.2) vs pmkid (7.0.1) → use **7.1.2 (2026-02-08)**.
- **SSID Confusion venue**: modern (USENIX'24) vs pmkid (WiSec'24) → use **WiSec 2024**.
- **airgeddon version**: evil_twin (v12.0, May 2026) vs modern (v12.01, Jul 2026) → both real; **v12.01 is latest**.
- **Dragonblood tooling repo**: modern cites vanhoefm/dragonslayer, pmkid cites vanhoefm/dragonblood — both exist; dragonslayer (144★) is the canonical attack-tool repo, dragonblood (31★) a later mirror/PoC. Prefer dragonslayer.
- **airgeddon plugins**: two different repos cited (xpz3/airgeddonplugins vs KeyofBlueS/airgeddon-plugins) — both exist and are distinct; not an error, but merge when deduping.
- Duplicate coverage across files (DragonShift, wacker, SSID Confusion, transition-mode downgrade, wpa_sycophant, eaphammer, hcxdumptool→22000 pipeline) is consistent in substance everywhere except the items above.

*Verification method: GitHub REST API repo/release lookups, arXiv export API, ndss-symposium.org, hashcat.net forum, parrotsec.org, NVD/MITRE records. No files other than this report were modified.*
