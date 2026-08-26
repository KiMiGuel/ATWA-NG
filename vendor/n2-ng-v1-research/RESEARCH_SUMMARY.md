# WiFi Pentesting & Password Cracking Research — Master Summary
Compiled 2026-07-29 by a 5-agent research swarm + independent cross-verifier.
All briefs passed verification (high confidence). Corrections from the verifier are folded in below and annotated in `wifiresearch_cross_verification.md`.

## Files in this bundle
| File | Scope |
|---|---|
| `wifiresearch_modern_wpa_attacks.md` | WPA3/Dragonblood, FragAttacks, SSID Confusion, AirSnitch, PMF bypass, tooling |
| `wifiresearch_evil_twin.md` | Evil Twin / rogue AP frameworks, newest source code, WPA-Enterprise harvesting |
| `wifiresearch_80211_pmkid_wps.md` | PMKID capture, WEP attacks, WPS PIN, 802.11 protocol & WiFi 7 research |
| `wifiresearch_password_cracking_papers.md` | ~45 verified papers: PCFG/PRINCE/Markov, ML cracking, targeted/OSINT attacks |
| `wifiresearch_landscape_2026.md` | 2025–2026 tooling state, CVEs, conference talks, 6 GHz / WiFi 7, defense shifts |
| `wifiresearch_cross_verification.md` | Confidence tiers, spot-check results, corrected claims |

## Top headlines (newest first)
1. **AirSnitch (Zhou & Vanhoef, NDSS Feb 2026)** — bypasses client isolation on every router tested via GTK group-key abuse, gateway bouncing, cross-BSSID port stealing. Tool: github.com/vanhoefm/airsnitch. Group-key hygiene is the renewed audit theme.
2. **SSID Confusion (CVE-2023-52424, WiSec 2024** — verifier corrected venue from USENIX) — SSID unauthenticated in the 4-way handshake → downgrade + VPN-disable on all clients.
3. **WPA3 transition-mode downgrade** is the realistic WPA3 vector: DragonShift (2024) and AirBully (2025), both hostapd-mana-based; wacker does online SAE brute force.
4. **PMKID**: clientless capture via hcxdumptool remains best practice — current version **7.1.2** (2026-02-08; one brief said 7.0.1 — corrected). hashcat v7.0.0/v7.1.2, mode 22000 standard, 16800/16801 legacy. PMF does not block PMKID.
5. **WEP**: zero new research since the PTW/aireplay era — aircrack-ng 1.7 chopchop/fragmentation/ARP-replay remain fully practical; WEP now only appears as a FragAttacks/SSID-Confusion victim protocol.
6. **WPS**: no new CVEs; pixie-dust (reaver-t6x fork, pixiewps) still works on pre-2018 Ralink/Realtek/Broadcom. OneShot upstream URL is dead (tool lives on via forks). Online PIN brute is mostly dead via lockouts.
7. **Router-side RCE is displacing radio attacks**: Windows WiFi driver RCE CVE-2024-30078, TP-Link CVE-2024-21833 & 2025-7850/7851/6542/15568, NETGEAR RAXE300 (6E) firmware-MiTM CVE-2025-12943.
8. **6 GHz changes the game**: WPA3/OWE/PMF-only, no WPA2 fallback — classic capture-and-crack is dead there; AWUS1900/ACHM can't do 6 GHz (AWUS036AXML / MT7921AUN is the community 6E pick). WiFi 7 MLO removes single-band deauth; **no peer-reviewed MLO attack paper exists yet** — open research gap. Beacon Protection unsupported on nearly all WiFi 7 clients except iPhones.

## Evil Twin landscape (verified repos, activity as of 2026-07-29)
- **Actively maintained**: airgeddon v12.01, sensepost/hostapd-mana (pushed 2026-07-28 — the live engine behind berate_ap & enterprise twins), eaphammer v1.14.0, wifiphisher, garywill/linux-router.
- **Stale/deprecated**: wifipumpkin3 (v1.1.7, 2023 — but richest MFA/QR captive-portal phishing code), fluxion upstream, create_ap (archived → use linux-router), mana-toolkit (→ hostapd-mana + berate_ap).
- **Enterprise harvesting**: PEAP/MSCHAPv2→NetNTLMv1, eaphammer GTC downgrade, wpa_sycophant PEAP relay; ~31% of 802.1X deployments lack server-cert validation.
- **Your 2-adapter setup (AWUS1900 + ACHM)** fits the rogue-AP+deauth workflow all these frameworks use; AWUS1900 5GHz AP mode enables dual-band twins.

## Password cracking research (45 verified papers, newest first)
- **Newest**: MoPE (S&P'26), KNNGuess (NDSS'26, 25.4% targeted-crack figure), PassLLM (USENIX'25), RankGuess (S&P'25), SE#PCFG/SEPCA, TDSC'25 parallel-PCFG — all directly relevant to your pipeline's PCFG/PRINCE stages.
- **Targeted-attack lineage mapped**: TarGuess → Pal'19 (S&P) → Pass2Edit → PointerGuess → PassLLM-I/II/III → KNNGuess, plus Araña (USENIX'23) and the Nisenoff 20-year reuse study.
- **Tools**: lakiw/pcfg_cracker v4.4/4.6, PassGAN, princeprocessor, OMEN, CUPP.
- **Academically orphaned** (your opportunity): PRINCE has zero peer-reviewed treatment; mask/hybrid attacks likewise; no theory for ensembling guesses across models in probability order.

## Implications for n2-ng v1.6 roadmap
- PMKID (scapy EAPOL_KEY) is the right next feature — hcxdumptool 7.1.2 methodology, hashcat 22000 output.
- Evil twin: build on hostapd-mana concepts rather than deprecated fluxion/mana-toolkit; consider WPA3-transition downgrade (DragonShift approach) as a differentiator.
- Add PMF-aware attack routing (skip deauth when PMF enforced; pivot to PMKID/clientless).
- Watch RTX 4090 throughput claims: sources conflict (~200 kH/s vs ~1.6–1.8 MH/s for 22000) — calibrate on your own hardware.
