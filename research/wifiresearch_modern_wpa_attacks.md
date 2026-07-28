# Modern WEP/WPA/WPA2/WPA3 Attack Landscape (2022–2026)
**Research brief for WiFi pentest tooling developers — compiled 2026-07-29**

---

## Key Findings

1. **AirSnitch (NDSS 2026, Feb 2026) is the newest major WiFi attack class.** Xin'an Zhou (UC Riverside) & Mathy Vanhoef (KU Leuven) showed that WiFi *client isolation* (guest networks / AP isolation) can be bypassed on every device tested (Netgear, D-Link, TP-Link, Asus, Ubiquiti, Cisco Catalyst 9130, DD-WRT, OpenWrt 24.10). It does **not** break WPA2/WPA3 crypto — it bypasses it via three primitives: (1) **GTK group-key abuse** (shared GTK lets any insider inject broadcast frames carrying unicast IP payloads to a victim), (2) **gateway bouncing** (isolation enforced only at L2 — bounce IP packets off the gateway), (3) **cross-BSSID port stealing** (spoof MAC bindings across bands → full bidirectional MitM). Reference tool: https://github.com/vanhoefm/airsnitch. Sources: [arstechnica.com/security/2026/02/new-airsnitch-attack-breaks-wi-fi-encryption-in-homes-offices-and-enterprises/](https://arstechnica.com/security/2026/02/new-airsnitch-attack-breaks-wi-fi-encryption-in-homes-offices-and-enterprises/), [kaspersky.com/blog/airsnitch...](https://www.kaspersky.com/blog/airsnitch-wi-fi-client-isolation-guest-network-vulnerability-and-mitigation/55597/).

2. **SSID Confusion (CVE-2023-52424, May 2024)** is the most important KRACK-successor / KRACK-amplifier of the period: the 802.11 standard never authenticates the SSID inside the 4-way handshake, so an attacker can downgrade a victim to a *different* network sharing credentials ("TrustedNet" → "WrongNet"), defeating VPN auto-disable-on-trusted-SSID. Affects WEP→WPA3, 802.1X/EAP, AMPE, all OSes. Presented at USENIX Security 2024 (Héloïse Gollier & Vanhoef). IEEE fix in progress (11-24-0938 "Protect SSID in 4-way handshake"). Sources: [thehackernews.com/2024/05/new-wi-fi-vulnerability-enabling.html](https://thehackernews.com/2024/05/new-wi-fi-vulnerability-enabling.html), [ubuntu.com/security/CVE-2023-52424](https://ubuntu.com/security/CVE-2023-52424), [top10vpn.com research PDF](https://www.top10vpn.com/assets/2024/05/Top10VPN-x-Vanhoef-SSID-Confusion.pdf).

3. **WPA3 transition-mode downgrade remains the most *practical* WPA3 attack.** Rogue WPA2-only AP with same SSID → WPA3 clients fall back → capture standard WPA2 handshake → offline crack. Tooling matured: **DragonShift** (https://github.com/jabbaw0nky/DragonShift, Aug 2024) automates it; airgeddon v11.x/12.x has a dedicated "WPA3 downgrade / transition mode" path. Also: captive-portal WPA3 password recovery (arXiv:2412.15381, Dec 2024) works **only when PMF is absent**.

4. **WPA3-SAE online brute force** is the other live WPA3 surface: **wacker** (https://github.com/blunderbuss-wctf/wacker — "A WPA3 dictionary cracker"; runs in *managed* mode via wpa_supplicant, ~1–3 guesses/s, AP-rate-limited). SAE kills offline cracking but not weak passwords. Ref: [az0th.it wifi pentest guide](https://az0th.it/wifi/wifi-pentest-guide/).

5. **PMF (802.11w) is the pivot of modern deauth.** Pure WPA3 mandates PMF → classic deauth fails. Modern bypasses: **CSA (Channel Switch Announcement) injection** (pre-auth action frames honored even with PMF), rogue AP without MFP against MFPC ("optional") networks, auth-flood association-table exhaustion, beacon-flood confusion, 802.11v BSS-TM "roaming" abuse. mdk4 `d -w 1` enables PMF-aware testing. Ref: [hackersmanifest.com/wireless-pentesting/06-deauth/](https://hackersmanifest.com/wireless-pentesting/06-deauth/), [airgeddon FAQ](https://github.com/v1s1t0r1sh3r3/airgeddon/wiki/FAQ-&-Troubleshooting).

6. **FragAttacks (2021) and KRACK (2017) are patched on modern stacks but alive in the IoT/embedded long tail** — industrial clients, old Android, cameras, POS. Both test frameworks remain the canonical client-side audit tools (vanhoefm/fragattacks, vanhoefm/krackattacks-scripts).

7. **Tooling landscape is healthy and hcxdumptool-centric**: hcxdumptool/hcxtools 7.1.2 (Feb 2026) + hashcat mode 22000 is the standard capture→crack pipeline; bettercap v2.41.7 (May 2026) for integrated wifi/MitM; airgeddon v12.01 (Jul 2026) as the orchestrator (now with WPA3 plugin menus + MFP status analysis); wifite2 maintained by kimocoder fork (original derv82 repo stale since Aug 2024); mdk4 4.2 still the deauth/DoS workhorse.

---

## Tools & Repos (verified via GitHub API 2026-07-29)

| Tool | Repo | Version / Last Activity | Notes |
|---|---|---|---|
| hcxdumptool | https://github.com/ZerBea/hcxdumptool | **7.1.2** (2026-02-08); pushed 2026-07-08; 2.1k★ | PMKID + handshake capture, active; not for pure WPA3-SAE |
| hcxtools | https://github.com/ZerBea/hcxtools | **7.1.2** (2026-02-08); pushed 2026-07-18 | hcxpcapngtool → hashcat 22000; recommended by hashcat |
| bettercap | https://github.com/bettercap/bettercap | **v2.41.7** (2026-05-11); 19.5k★ | wifi.recon/deauth/PMKID assoc, Evil Twin, BLE, caplets; loud (WIDS-visible) |
| airgeddon | https://github.com/v1s1t0r1sh3r3/airgeddon | **v12.01** (2026-07-13); 7.9k★ | v12: WPA3 plugin menus, WPA3 MFP analysis, WEP besside-ng, decloaking, enterprise identity capture |
| mdk4 | https://github.com/aircrack-ng/mdk4 | **4.2**; pushed 2026-05-29 | modes b/a/p/d/m/e/s/w/f/x; PMF-aware `-w`; IDS evasion `--ghost`/`--frag` |
| aircrack-ng | https://github.com/aircrack-ng/aircrack-ng | 1.7+; pushed 2026-06-12 | base suite; aireplay-ng deauth still default vs non-PMF |
| wifite2 (active fork) | https://github.com/kimocoder/wifite2 | pushed 2026-07-21; 1.6k★ | original https://github.com/derv82/wifite2 stale since 2024-08-20 (8k★) |
| wacker | https://github.com/blunderbuss-wctf/wacker | last push 2023-07-10; 366★ | WPA3-SAE **online** dictionary attack via wpa_supplicant; managed mode |
| DragonShift | https://github.com/jabbaw0nky/DragonShift | 2024-08-25; 66★ | Automates WPA3 transition-mode downgrade (rogue WPA2 AP + handshake capture) |
| AirSnitch | https://github.com/vanhoefm/airsnitch | pushed 2026-03-13; 780★ | Client-isolation bypass test tool: `--check-gtk-shared`, `--c2c-ip`, `--c2c-broadcast` |
| FragAttacks scripts | https://github.com/vanhoefm/fragattacks | pushed 2025-04-29 | 45-variant fragmentation/aggregation client+AP tester |
| KRACK scripts | https://github.com/vanhoefm/krackattacks-scripts | pushed 2024-12-25 | `krack-test-client.py` KRACK variant tester |
| Dragonblood tools | https://github.com/vanhoefm/dragonslayer (+ wpa3.mathyvanhoef.com) | 2019 | dragondrain (SAE DoS), dragontime (timing), dragonforce (partitioning) |
| Kr00k PoC | https://github.com/hexway/r00kie-kr00kie | 2020 | CVE-2019-15126 decryption PoC (all-zero TK after disassoc) |
| eaphammer | https://github.com/s0lst1c3/eaphammer | active | WPA2-Enterprise Evil Twin, hostile portal, RADIUS cred capture |
| hostapd-mana | https://github.com/sensepost/hostapd-mana | legacy but used | KARMA/Mana rogue AP; used by DragonShift |
| hashcat | https://github.com/hashcat/hashcat | 6.2.6+ | mode 22000 (WPA-PBKDF2-PMKID+EAPOL); ~1.6–1.8 MH/s on RTX 4090 |
| airgeddon plugins | https://github.com/xpz3/airgeddonplugins | active | mass_handshake_capture.sh (mass PMKID/handshake sweeps, needs airgeddon ≥12.0) |

---

## CVEs & Papers

### WPA3 / SAE
- **Dragonblood** — Vanhoef & Ronen, IEEE S&P 2020 (disclosed Apr 2019): https://papers.mathyvanhoef.com/dragonblood.pdf, site https://wpa3.mathyvanhoef.com
  - CVE-2019-9494 SAE cache side-channel (FLUSH+RELOAD on PWE derivation)
  - CVE-2019-9495 EAP-pwd cache side-channel
  - CVE-2019-9496 SAE confirm missing state validation (DoS)
  - CVE-2019-9497/9498/9499 EAP-pwd missing commit validation → reflection/impersonation
  - CVE-2019-13377 timing side-channel on Brainpool curves (follow-up fix bypass)
  - "Dragonblood is Still Leaking: Practical Cache-based Side-Channel in the Wild" — https://arxiv.org/pdf/2012.0579... (arXiv:2012.02745)
- **SSID Confusion** — CVE-2023-52424 (CVSS 7.4), Gollier & Vanhoef, USENIX Security 2024 / Top10VPN, May 2024: https://www.top10vpn.com/research/wifi-vulnerability-ssid/
- WPA3 captive-portal password recovery via transition mode — Khan, arXiv:2412.15381 (Dec 2024): https://arxiv.org/abs/2412.15381

### WPA2 / standard-level
- **KRACK** — Vanhoef & Piessens, ACM CCS 2017: https://papers.mathyvanhoef.com/ccs2017.pdf; CVE-2017-13077/78/79/80/81/82/84/86/87/88 (incl. **GTK/IGTK group-key reinstallations** 13078/13079/13080/13081 — the "group key attacks" lineage)
- **FragAttacks** — Vanhoef, May 2021: https://www.fragattacks.com; CVE-2020-24586 (fragment cache not cleared), -24587 (mixed-key fragment reassembly), -24588 (A-MSDU/EAPOL injection) + CVE-2020-26139–26147 (implementation bugs: EAPOL forwarding pre-auth, plaintext injection, etc.)
- **Kr00k** — CVE-2019-15126 (ESET, RSA 2020): Broadcom/Cypress FullMAC chips encrypt residual buffer with all-zero TK after disassociation; >1B devices; PoC hexway/r00kie-kr00kie. Whitepaper: https://web-assets.esetstatic.com/wls/2020/02/ESET_Kr00k.pdf
- **AirSnitch** — Zhou & Vanhoef, NDSS 2026 (Feb 2026): "AirSnitch: Demystifying and Breaking Client Isolation in Wi-Fi Networks"; GTK-abuse / gateway-bounce / port-stealing; vendor advisories incl. Extreme Networks SA-2026-030, OpenWrt/DD-WRT affected.

### Kernel/driver layer (mac80211 / MLO era, 2024–2026)
- CVE-2024-35838 mac80211 sta-link leak (MLO/MLD connection path)
- CVE-2024-26779 mac80211 fast-xmit race; CVE-2024-27048 brcm80211 pmk_op alloc failure
- CVE-2024-58061 mac80211 "prohibit deactivating all links" (MLO)
- CVE-2025-38644 mac80211 TDLS ops while unassociated
- CVE-2026-46152 mac80211 `ieee80211_invoke_fast_rx()` static-variable race (May 2026)
- Theme: Wi-Fi 7 (802.11be, ratified Jul 2025) MLO code paths are the fresh kernel attack surface.

---

## Trends

1. **Attack surface shifted from crypto → state management & layering.** KRACK (2017) → FragAttacks (2021) → SSID Confusion (2024) → AirSnitch (2026): the 802.11 *standard's* cross-layer assumptions (SSID not authenticated, isolation not standardized, group keys shared) are the target, not ciphers.
2. **WPA3's practical weaknesses are deployment weaknesses**: transition mode + missing PMF enforcement + weak passwords (wacker). Direct SAE crypto breaks remain academic (side channels need code exec or many samples).
3. **Deauth evolved into "PMF-aware disconnection engineering"**: CSA injection, beacon/auth floods, 802.11v BSS-TM steering, and evil-twin-without-MFP rather than raw deauth frames.
4. **Capture pipeline standardized**: hcxdumptool (PMKID/handshake) → hcxpcapngtool → hashcat -m 22000 is the industry workflow; aircrack-ng suite is now mostly recon + deauth; wrapper orchestration (airgeddon 12.x, kimocoder/wifite2) handles multi-attack sequencing.
5. **Group-key abuse is a renewed theme** (KRACK GTK reinstall → AirSnitch GTK injection); per-client randomized GTK + `drop_unicast_in_l2_multicast=1` are the mitigations to test for.
6. **Wi-Fi 7/MLO (802.11be)** is the next frontier: mandatory WPA3/PMF on 6 GHz but brand-new multi-link state machines already yielding kernel CVEs.

---

## Recommended Deep-Dive Areas

1. **AirSnitch tooling integration** — port GTK-abuse/gateway-bounce/port-stealing tests into your toolkit; add `--check-gtk-shared` equivalent and per-VLAN GTK detection. Read the NDSS'26 paper + github.com/vanhoefm/airsnitch.
2. **SSID Confusion exploitation chains** — downgrade + VPN-auto-disable + KRACK amplification; build detection for beacon-probe SSID/auth mismatches.
3. **PMF bypass module** — CSA frame injection, MFPC-vs-MFPR fingerprinting (airgeddon 12.x already does MFP analysis — study its approach), 802.11v BTM abuse.
4. **WPA3 transition-mode automation** — DragonShift-style rogue WPA2 AP + wacker online SAE guessing as fallback; add PMKID capture on the WPA2 leg (quiet, no deauth).
5. **Wi-Fi 7 / MLO state-machine fuzzing** — mac80211 MLD link management, per-link GTK handling; track kernel CVE-2024/2025/2026 wifi:* series.
6. **Group-key hygiene auditing** — GTK sharing across BSSIDs/VLANs, broadcast-to-unicast conversion presence, client acceptance of unicast IP in broadcast frames.
7. **IoT/embedded long-tail** — KRACK/FragAttacks/Kr00k testers against unpatched embedded clients (highest real-world hit rate in 2026 engagements).

*All repo URLs verified live via GitHub API on 2026-07-29. For authorized testing only.*
