# IEEE 802.11 Protocol Attack Research Brief (2022–2026 focus, newest first)
**Audience:** WiFi pentester | **Compiled:** 2026-07-29

Scope: attacks on the 802.11 protocol itself — PMKID capture, WEP, WPS PIN, frame injection/management-frame attacks, and WiFi 6/6E/7 research. Author's own (authorized) testing only.

---

## 1. PMKID Attacks

**Status (2026):** PMKID capture remains the most efficient clientless WPA/WPA2-PSK attack. Tooling matured significantly in 2025: hcxdumptool v7.0.x and hashcat v7.0.0 are the current releases.

### Background
- The PMKID attack (disclosed Aug 2018 by Jens "atom" Steube / hashcat team) extracts `PMKID = HMAC-SHA1(PMK, "PMK Name" || MAC_AP || MAC_STA)` from the RSN IE in EAPOL M1, letting the attacker target the AP directly — no client, no full 4-way handshake, no retransmission/nonce-repair problems. Advantages enumerated in the original hashcat writeup: client-less, no waiting for handshakes, no invalid PSKs from real users, single hex-encoded hash string. (https://hashcat.net/forum/thread-7717.html ; summary: https://www.hackingarticles.in/wireless-penetration-testing-pmkid-attack/)
- Only APs with roaming/PMKID caching enabled are vulnerable; WPA3-SAE-only networks are NOT (SAE has no RSN-PMKID in M1).

### hcxdumptool methodology (current, v7.x)
- hcxdumptool (ZerBea) is a self-contained monitor-mode capture tool that actively sends authentication/association requests to APs to elicit PMKIDs ("client-less PMKID"), captures M1M2 rogue handshakes, and is fully controllable via Berkeley Packet Filters (BPF). It manages interface mode, MAC, and channel itself — the author explicitly warns *not* to set monitor mode with third-party tools, not to use virtual interfaces/VMs/macchanger, and not to merge pcapng files (destroys assigned hash values). (https://github.com/ZerBea/hcxdumptool ; changelog: https://raw.githubusercontent.com/ZerBea/hcxdumptool/master/changelog)
- Key versions: **v7.0.0 (2025-08-02)** released in tandem with hashcat v7.0.0, including an OpenWRT kernel-bug workaround; **v7.0.1 (2025-09-09)** fixed a proberesponsetx error. Later 2025/2026 additions: `--daemonize`, `--watchdogmax`, waterfall real-time display (`--rds=4`), expanded `--rds` rcascan attack modes showing `[FOUND PMKID]` / `[FOUND PMKID CLIENT-LESS]`, PROBEREQUEST counters. (https://github.com/ZerBea/hcxdumptool/discussions/522)
- Typical modern workflow:
  ```
  hcxdumptool -i wlan0 -w dump.pcapng -F            # all freqs incl. 6 GHz (channel+band, e.g. 36b)
  hcxpcapngtool -o hash.22000 -E elist dump.pcapng  # convert; also harvest ESSID list
  hcxeiutool -i elist -d digits -x xdigits -c chars # build targeted wordlists from ESSIDs
  hashcat -m 22000 hash.22000 wordlist
  ```
  (Kali hcxtools 7.1.0 docs, 2026: https://www.kali.org/tools/hcxtools/)
- Note: some 2025 users report weaker capture performance in v7 vs 6.3.x depending on BPF tuning (GitHub discussion #522); v6.3.4/6.3.5 remain widely deployed (OpenWRT packages pin 6.3.4).

### hashcat mode evolution
- **-m 16800** (WPA-PMKID-PBKDF2, 2018) and **-m 16801** (WPA-PMKID-PMK) are *deprecated/legacy*; hcxpcapngtool now emits the unified **-m 22000 (WPA-PBKDF2-PMKID+EAPOL)** format, which hashcat enforces (attempting 16800 against a 22000 hashline errors out). WPA-PMK-PMKID+EAPOL is mode 22001. (https://hashcat.net/forum/archive/index.php?thread-12510.html)
- **hashcat v7.0.0 (2025-08-01)**: major rewrite — Assimilation/Python Bridge, hash-mode autodetection, HIP (AMD) and Metal (Apple Silicon) backends, autotune refactor, removal of 4GB allocation caps. WPA-relevant notes: mode autodetection is explicitly *disabled* for 16800/16801/22001 (still use 22000), and "WPA: allow users to override nonce_error_corrections even if message_pair suggests otherwise" — useful for noisy PMKID/handshake captures. (https://hashcat.net/forum/thread-13330.html ; https://github.com/hashcat/hashcat/blob/master/docs/releases_notes_v7.0.0.md)
- Throughput reference: WPA-PBKDF2 mode 22000 runs ~0.9–1.0 MH/s on RTX 3090, ~1.6–1.8 MH/s on RTX 4090 (rockyou+best64 ≈ minutes). (https://codeby.net/threads/93030/)
- Alternative online verification: wpa-sec.stanev.org accepts "uncleaned" caps to check whether the AP/client leaks PMK or is crackable with common wordlists. (hcxtools OpenWRT discussion: https://github.com/ZerBea/hcxdumptool/discussions/424)

### Latest improvements / operational notes
- hcxdumptool now works in 6 GHz (band c) and 5 GHz (band b) — channel notation requires band suffix (e.g., `-c 36b`), relevant for WiFi 6E/7 engagements.
- PMF (802.11w) does not block PMKID attacks (PMKID comes from unprotected EAPOL M1), but PMF blocks deauth-based handshake capture; pentest guidance is: if PMF enforced → fall back to PMKID or passive capture. wifite2 automates this strategy selection. (https://github.com/kimocoder/wifite2)
- Known mitigation: disable roaming/802.11r PMKID caching on APs where not needed; use WPA3-SAE.

---

## 2. WEP Key Attacks

**Status (2026):** No genuinely new WEP cryptanalysis since the classic era (FMS 2001, PTW/Tews 2007–2009). WEP persists only in industrial/legacy IoT; the attacks remain fully practical and are still shipped in aircrack-ng 1.7. No 2022–2026 academic paper advances WEP cracking; modern references are field guides.

### Current toolbox (aircrack-ng 1.7, stable since 2022)
- **PTW attack** in `aircrack-ng`: recovers 104-bit WEP keys from as few as ~40k–85k IVs (in lab demos: cracks after only ~146–5000 IVs gathered; "Tested 177409 keys (got 146 IVs)"). (Synacktiv "Wireless-(in)Fidelity: Pentesting Wi-Fi in 2025": https://www.synacktiv.com/en/publications/wireless-infidelity-pentesting-wi-fi-in-2025)
- **ARP-request replay** (`aireplay-ng -3`): retransmits captured ARP, forces AP to emit fresh IVs — primary IV generator; still the standard acceleration.
- **Chopchop** (`aireplay-ng -4`): decrypts a WEP packet byte-by-byte without the key; fails on APs dropping short frames (<60/<42 bytes). **Fragmentation** (`aireplay-ng -5`): obtains up to 1500 bytes of PRGA keystream for `packetforge-ng` injection — faster than chopchop but driver- and proximity-sensitive. (aireplay-ng(8) man page: https://manpages.opensuse.org/Tumbleweed/aircrack-ng/aireplay-ng.8.en.html)
- **Caffe-Latte** (`-6`): harvest IVs from a client without any AP in range; **cfrag** (`-7`) against clients/ad-hoc/softAP; **migmode** (`-8`) against Cisco WPA Migration Mode (WEP+WPA on one SSID). All still present in aircrack-ng 1.7. (https://www.kali.org/tools/aircrack-ng/)
- Supporting tools unchanged: wesside-ng (automated WEP), easside-ng (no AP association), tkiptun-ng (TKIP — see §4).
- Note: WEP reappears in 2024-era research as a *victim protocol*: the SSID Confusion attack (CVE-2023-52424) explicitly covers "Home WEP" networks, and Framing Frames (USENIX Sec'23) showed FreeBSD leaking queued frames as "WEP with all-zero key" (§4).

### Practical notes
- Modern driver caveat: Atheros needs the card MAC set to the spoofed MAC for fragmentation attacks; injection-capable chipsets (AR9271, MT7612U) remain the recommended hardware. (https://codeby.net/threads/93030/)
- WEP is essentially an automatic win on engagement; remaining risk is operational (deauth noise in industrial settings — prefer ARP-replay only, per Synacktiv).

---

## 3. WPS PIN Attacks

**Status (2026):** No new WPS protocol flaw disclosed since pixie-dust (2014/15). The attack surface is legacy-but-alive: online brute force is largely defeated by lockouts; pixie-dust still hits old Ralink/Realtek/Broadcom chipsets. Tooling is community-maintained forks.

### Attacks
- **Online PIN brute force** (Viehböck 2011, CVE-2011-5053 lineage): PIN verified in two halves (first 4 digits → 10^4, last 3 + checksum → 10^3) ⇒ ~11,000 attempts. Mostly impractical vs modern APs (WPS lock after 3–5 failures; some permanently brick WPS).
- **Pixie-dust (offline)** — Dominique Bongard 2014: weak/non-random E-S1/E-S2 nonces let `pixiewps` recover the PIN from a single WPS exchange in ~1–5 s. Patched/unaffected: modern Intel, Qualcomm Atheros post-2018, most WPA3-capable APs with WPS 2.0.4+. (https://tessl.io/registry/skills/github/PurpleAILAB/Decepticon/wps-pixie-dust ; https://www.pentesting.org/wps-attack-guide/)
- **Null/known-PIN attacks**: empty-PIN (`-p ''`) and default-PIN lists (12345670, 00000000, 56562562, vendor algorithmic PINs) still tried by wifite-style automation ("WPS NULL PIN" attack step). (https://www.securitronlinux.com/kali/...)
- **2025 tooling note:** ZerBea removed WPS info from hcxtools' hcxnmealog in March 2025, observing "all tested APs use WPS 2.0!" — i.e., field reality is WPS 2.0 everywhere, and vendor WPS analysis moved out of the hcxtools pipeline. (hcxdumptool changelog, op. cit.)

### Tools & forks (current)
- **reaver-wps-fork-t6x** — the maintained community fork of reaver (wash scanner included; `-K 1` = pixie-dust via pixiewps, `-N` no-NACK, `-p` known PIN): https://github.com/t6x/reaver-wps-fork-t6x
- **pixiewps** — offline pixie-dust cracker: https://github.com/wiire-a/pixiewps (v1.4.x)
- **bully** — alternative WPS brute forcer (`-d` pixie mode, better lockout handling; last community updates via Kali package): https://github.com/aanarchyy/bully (original; Kali-maintained builds)
- **OneShot** (drygdryg) — Python pixie-dust/null-PIN automation, actively used: https://github.com/drygdryg/OneShot
- **wifite2** (kimocoder) — orchestrates pixie-dust → null-PIN → PIN brute → PMKID → handshake chain: https://github.com/kimocoder/wifite2
- No new WPS CVEs in 2022–2026; the "new" WPS flaw landscape is deployment-side (WPS still enabled on SOHO gear, weak RNG chipsets still shipping in embedded/IoT).

---

## 4. 802.11 Protocol & WiFi 6/6E/7 Research (2022–2026, newest first)

### 2024–2026
- **SSID Confusion attack — CVE-2023-52424 (WiSec'24, Gollier & Vanhoef, KU Leuven).** Design flaw: the SSID is not always authenticated / not bound into PMK derivation or the protected 4-way handshake. Attacker tricks a client into connecting to WrongNet while the UI shows TrustedNet; downgrades clients to a less-secure band/SSID sharing the same credentials, and can auto-disable VPNs that trust networks by SSID (Cloudflare WARP, Windscribe demonstrated). All tested clients (Windows 11, iOS 17, Android 10, macOS 14) vulnerable; affects Home WEP, WPA3 SAE-loop, 802.1X/EAP, Mesh AMPE, FILS (FT not vulnerable). CVSS 7.4 (AV:A/AC:L/PR:L/UI:R). Mitigations: unique credentials per SSID, modified beacon protection, IEEE 802.11 amendment to protect SSID in the 4-way handshake (IEEE doc 11-24-0938). Paper: https://papers.mathyvanhoef.com/wisec2024.pdf ; NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-52424 ; writeup: https://www.top10vpn.com/research/wifi-vulnerability-ssid/
- **WiFi 7 (802.11be) security posture (2024–2026 deployment research).** No peer-reviewed MLO attack paper found at USENIX/S&P/CCS/NDSS through mid-2026 — the published WiFi 7 security work is industry-side:
  - 802.11be *mandates* WPA3 (SAE-EXT-KEY AKMs 24/25 for per-MLD authentication), GCMP-256 pairwise cipher, PMF (single-link and MLO), and Beacon Protection (BIGTK + MIC IE on beacons). Clients on weaker security are restricted to 11ax rates with no MLO. (Cisco: https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/223061-migrate-to-wi-fi-7-and-6ghz.pdf ; Arista: https://www.arista.com/assets/data/pdf/Whitepapers/Unlocking-Wi-Fi-7-The-Real-World-State-of-Client-Security.pdf)
  - Arista's 2026 client testing (S25, iPhone 16/17, Pixel 8/9, Intel BE200, etc.): all WiFi 7 clients support AKM 24/25 + GCMP-256 + PMF, but **Beacon Protection is unsupported on most clients except iPhones** — a live gap: beacon-forgery attacks (channel-switch DoS, rate reduction, SSID-confusion enabler) remain viable against most WiFi 7 clients.
  - MLO attack surface is recognized but under-protected: MLO control-plane signaling (link sync/switching) is not covered by WPA3 data-plane security; only theoretical countermeasure work exists so far ("Securing Wi-Fi 7 MLO: SMCP-MLO" whitepaper, Dec 2025: https://www.academia.edu/145535778/). Watch this space — first offensive MLO/MLD papers are expected; per-link MAC addresses differing from the MLD MAC are a tracking/spoofing consideration.
  - WPA3 adoption ~10% per WLPC 2026 data; cross-AKM roaming and GCMP-256 enforcement gaps mean downgrade-prone mixed deployments. (https://mrncciew.com/wp-content/uploads/2026/02/wpa3-deployment-challenges_wlpc2026.pdf)
- **WPA3 attack ecosystem matured (2022–2025):** Vanhoef's HITB 2022 "Attacking WPA3: New Vulnerabilities & Exploit Framework" and wifite2's 2025 WPA3 module automate: transition-mode downgrade (80–90% success on mixed APs), SAE handshake capture → hashcat 22000, Dragonblood timing checks, SAE commit flooding (AP CPU DoS). (https://github.com/kimocoder/wifite2 ; https://sgu.ac.id/wpa3-is-broken-your-next-gen-wifi-is-not-safe/)

### 2023
- **Framing Frames: Bypassing Wi-Fi Encryption by Manipulating Transmit Queues (USENIX Security'23, Schepers/Ranganathan/Vanhoef).** Abuses the unprotected power-save bit to trick APs into leaking queued frames in plaintext, or encrypted with group/all-zero keys (FreeBSD variants leak "WEP with all-zero key"); bypasses client isolation in hotspot networks by forcing the AP to encrypt with an adversary-chosen key. Affects Linux, FreeBSD, iOS, Android; CVE-2022-47522 lineage. PoC ("MacStealer"): https://github.com/vanhoefm/macstealer ; paper: https://papers.mathyvanhoef.com/usenix2023-wifi.pdf ; Cisco advisory: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-ffeb-22epcEWu

### 2022
- **On the Robustness of Wi-Fi Deauthentication Countermeasures (WiSec'22, Schepers/Ranganathan/Vanhoef).** Shows PMF/802.11w is bypassable in practice: contradictory rules require accepting unprotected disconnect frames pre-encryption; forged beacons and channel-switch announcements still disconnect/downgrade clients across Windows/macOS/Linux/iOS/Android. Directly relevant to beacon-flood/deauth engagements. (https://dl.acm.org/doi/10.1145/3507657.3528556 ; referenced in https://dl.acm.org/doi/abs/10.1007/s10207-024-00958-1)
- **Multi-Channel MitM (MC-MitM) state-of-the-art review (2022, arXiv:2203.0579)** — systematizes channel-based MitM enabling KRACK/FragAttacks even with PMF. (https://arxiv.org/pdf/2203.0579)

### Foundation still on engagements (2021, referenced constantly)
- **FragAttacks (USENIX Security'21, Vanhoef)** — 12 CVEs; 3 design flaws affecting everything from WEP to WPA3: CVE-2020-24588 (aggregation/A-MSDU injection), CVE-2020-24587 (mixed-key fragment reassembly), CVE-2020-24586 (fragment cache poisoning); plus 9 implementation CVEs (CVE-2020-26139…26147) incl. **CVE-2020-26141 "not verifying TKIP MIC of fragmented frames"** — the modern TKIP-relevant issue. Mostly patched on mainstream OSes; embedded/IoT long tail remains in scope. Test suite: https://github.com/vanhoefm/fragattacks ; paper: https://papers.mathyvanhoef.com/usenix2021.pdf
- **TKIP MIC (Michael) attacks:** no new research 2022–2026. Beck–Tews (2008) and tkiptun-ng remain the state of the art; TKIP's practical role today is as a FragAttacks amplifier (26141) and as a downgrade target on WPA/WPA2-mixed IoT networks. TKIP is banned on 6 GHz/WiFi 6E+.
- **Frame injection / beacon flood:** aireplay-ng (injection, deauth with configurable reason codes `--deauth-rc`), **mdk4** (beacon flood mode `b`, deauth `d`, auth DoS `a`, EAPOL logoff/Michael countermeasure-exploitation modes) remain the standard tools; no protocol-level successor. mdk4 maintained fork: https://github.com/aircrack-ng/mdk4
- **WiFi 6E/6 GHz:** WPA3-only, PMF mandatory, no transition mode, OWE for open networks. Attack consequence: PMKID/handshake dictionary attacks don't apply in pure 6 GHz; pivot points are OWE's lack of authentication (evil twin), Dragonblood-class SAE issues on unpatched gear, and cross-band downgrade when the same credentials exist on 2.4/5 GHz (SSID Confusion). (https://www.csoonline.com/article/571147/what-cisos-need-to-know-about-wi-fi-6e.html)

---

## 5. Tools & Repos

| Tool | Repo | Version / status (2026) |
|---|---|---|
| hcxdumptool | https://github.com/ZerBea/hcxdumptool | v7.0.1 (Sep 2025); active, Jan 2026 commits; BPF-controlled, 6 GHz aware |
| hcxtools (hcxpcapngtool, hcxeiutool) | https://github.com/ZerBea/hcxtools | 7.1.0 (Kali 2026); hashcat-recommended converter |
| hashcat | https://github.com/hashcat/hashcat | v7.0.0 (Aug 2025); mode 22000 standard, 16800/16801 legacy |
| aircrack-ng suite | https://github.com/aircrack-ng/aircrack-ng | 1.7 (2022, current); PTW WEP crack, aireplay-ng -0..-9 |
| mdk4 | https://github.com/aircrack-ng/mdk4 | v4.2; beacon flood/auth DoS/deauth/EAPOL modes |
| reaver (t6x fork) | https://github.com/t6x/reaver-wps-fork-t6x | v1.6.6; maintained; pixie-dust `-K 1`, wash |
| pixiewps | https://github.com/wiire-a/pixiewps | v1.4.x; offline pixie-dust |
| bully | https://github.com/aanarchyy/bully | v1.4-00 (archived; Kali-maintained builds) |
| OneShot | https://github.com/drygdryg/OneShot | active; Python pixie-dust/null-PIN |
| wifite2 | https://github.com/kimocoder/wifite2 | active 2025; automated WPA3/PMKID/WPS chains |
| FragAttacks PoC | https://github.com/vanhoefm/fragattacks | 2021 test suite (12 CVE variants) |
| MacStealer (Framing Frames) | https://github.com/vanhoefm/macstealer | 2023 PoC (Cisco-confirmed) |
| Dragonblood PoC | https://github.com/vanhoefm/dragonblood | dragontime.py / dragondrain.py |
| Wi-Fi Framing (research) | https://github.com/domienschepers/wifi-framing | USENIX'23 artifacts |
| eaphammer | https://github.com/s0lst1c3/eaphammer | active; WPA2-Enterprise evil twin |
| wpa_sycophant (MANA relay) | https://github.com/sensepost/wpa_sycophant | PEAP/MSCHAPv2 relay (Synacktiv 2025 demo) |

## 6. Papers & CVEs

### Papers (newest first)
1. Gollier & Vanhoef, **SSID Confusion**, ACM WiSec 2024 — https://papers.mathyvanhoef.com/wisec2024.pdf (DOI 10.1145/3643833.3656126)
2. Arista, **Unlocking Wi-Fi 7: The Real-World State of Client Security** (whitepaper, 2026) — https://www.arista.com/assets/data/pdf/Whitepapers/Unlocking-Wi-Fi-7-The-Real-World-State-of-Client-Security.pdf
3. Schepers, Ranganathan, Vanhoef, **Framing Frames: Bypassing Wi-Fi Encryption by Manipulating Transmit Queues**, USENIX Security 2023 — https://papers.mathyvanhoef.com/usenix2023-wifi.pdf ; https://www.usenix.org/conference/usenixsecurity23/presentation/schepers
4. Schepers, Ranganathan, Vanhoef, **On the Robustness of Wi-Fi Deauthentication Countermeasures**, ACM WiSec 2022
5. **Multi-Channel Man-in-the-Middle Attacks Against Protected Wi-Fi Networks: A State of the Art Review**, 2022 — https://arxiv.org/pdf/2203.0579
6. Vanhoef, **Fragment and Forge (FragAttacks)**, USENIX Security 2021 — https://papers.mathyvanhoef.com/usenix2021.pdf
7. Vanhoef, **Attacking WPA3: New Vulnerabilities & Exploit Framework**, HITB Singapore 2022 (talk)
8. Synacktiv, **Wireless-(in)Fidelity: Pentesting Wi-Fi in 2025** (field methodology) — https://www.synacktiv.com/en/publications/wireless-infidelity-pentesting-wi-fi-in-2025
9. **Securing Wi-Fi 7 MLO: SMCP-MLO** (theoretical framework, Dec 2025) — https://www.academia.edu/145535778/ (non-peer-reviewed; only MLO-security work found to date)

### CVEs
| CVE | Name / impact |
|---|---|
| CVE-2023-52424 | SSID Confusion — 802.11 design flaw; all clients; downgrade + VPN-disable |
| CVE-2020-24586 / 24587 / 24588 | FragAttacks design flaws: fragment cache, mixed key, A-MSDU aggregation |
| CVE-2020-26139–26147 | FragAttacks implementation flaws (incl. 26141: no TKIP MIC check on fragments) |
| CVE-2022-47522 (family) | Framing Frames transmit-queue security-context leaks |
| CVE-2019-9494/9496/13377 (+13456) | Dragonblood SAE cache/timing side channels & validation |
| CVE-2019-15126 | Kr00k — all-zero-key re-encryption after disassociation (background for Framing Frames) |
| CVE-2017-13077–13082 | KRACK key reinstallation (baseline reference) |

### Notable gaps / honest negatives
- No new WEP cryptanalysis 2022–2026 (PTW + aireplay attacks remain state of the art).
- No new WPS protocol CVEs 2022–2026; WPS attacks are a legacy/IoT play now (all tested APs ship WPS 2.0).
- No peer-reviewed WiFi 7 MLO/MLD attack paper located at USENIX Sec/S&P/CCS/NDSS through 2026-07 — WiFi 7 security findings are currently industry-side (beacon-protection client gap, GCMP-256/AKM-24/25 enforcement gaps). Highest-watch research area.
- TKIP Michael/MIC attacks: nothing new; TKIP persists only as downgrade/FragAttacks (CVE-2020-26141) surface.
