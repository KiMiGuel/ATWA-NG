# WiFi Pentesting Landscape 2025–2026
**Brief date: 2026-07-29.** Audience: pentester who builds their own aircrack-ng-style automation tooling, uses Alfa AWUS1900 (RTL8814AU) / AWUS036ACHM-class adapters, and cracks with hashcat on Kali.

---

## 1. Tooling State of the Art

### 1.1 Hashcat: v7.x era
- **hashcat v7.0.0 (released 2025-08-01)** — the first major release after v6.2.x, "over two years of development," ~900k lines changed, 105 contributors. Key features for tool builders:
  - **Assimilation Bridge**: integrate external resources (CPUs, FPGAs, embedded interpreters) into the cracking pipeline.
  - **Python Bridge plugin** (and later **Rust bridge**) to write custom hash-matching logic without C/recompilation.
  - **Hash-mode autodetection** (omit `-m`, or `--identify`).
  - Virtual backend devices, Docker build support.
  - [hashcat forum v7.0.0 announcement](https://hashcat.net/forum/thread-13330.html), [GitHub releases](https://github.com/hashcat/hashcat/releases)
- **v7.1.0 (2025-08-16)** — new algorithms (LUKS2 Argon2i, KeePass KDBX4, AS/400, Cisco-ISE, etc.). **v7.1.2** hotfix restored machine-readable status compatibility used by Hashtopolis agents and fixed Argon2 multi-hash issues. [hashkiller forum mirror of announcements](https://forum.hashkiller.io/index.php?threads/welcome-to-hashcat-v7-0-0-update-hashcat-v7-1-2-release.74892/)
- **WiFi modes unchanged in name but still the core**: `-m 22000` (WPA-PBKDF2-PMKID+EAPOL) and `-m 22001` (WPA-PMK-PMKID+EAPOL, for verifying pre-computed PMKs). Mode 22000 remains the single unified text format replacing hccapx/PMKID (2500/16800 deprecated). Benefits: PMKID + EAPOL in one file, PBKDF2 reuse across salts, plain text. [hashcat wiki: cracking_wpawpa2](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)
- Official online converter still available: https://hashcat.net/cap2hashcat/ (strip data frames with tshark first if file too large).

### 1.2 hcxtools / hcxdumptool
- **hcxtools v7.0.0 (2025-08-02)** — hcxpcapngtool added support for **relayed EAPOL messages**; **v7.0.1 (2025-08-17)** fixed MxMxE3 MESSAGEPAIR handling on `--all`.
- 2025 additions: NMEA 0183 GPS ingest (`--nmea-in`, `--nmea-offset`) to correlate captures with GPS tracks (via GPSBabel GPX→NMEA conversion); Jan 2026: EPPKE authentication-protocol detection.
- hcxhashtool v6.3.5 (Nov 2024) added `--essid-regex` ESSID filtering.
- [hcxtools changelog](https://raw.githubusercontent.com/ZerBea/hcxtools/master/changelog)
- Recommended capture workflow (per hashcat wiki): stop NetworkManager/wpa_supplicant, run `hcxdumptool -i IFACE -w dump.pcapng --rds=1 -F` directly (no third-party monitor-mode scripts, no virtual interfaces, no pcapng merging/cleaning), then `hcxpcapngtool -o hash.hc22000 -E wordlist dump.pcapng`. hcxlabtool (wifi_laboratory repo) is the headless/expert alternative.
- Note: hcxdumptool now supports **SAE (WPA3) handshake captures**, and community tools parse them — but offline cracking still effectively targets WPA2/transition-mode material (see §5). [securiumacademy WPA3 2025 writeup](https://securiumacademy.com/blog/wi-fi-hacking-in-2025-cracking-wpa3/)

### 1.3 Automation wrappers
- **wifite2** remains actively maintained (kimocoder fork commits Oct 2025): v2.8.1/2.8.2 added a new TUI (`--tui`), session/resume/clean, **DragonBlood (WPA3 SAE) detection**, OWE detection, adaptive deauth, EvilTwin improvements, PMKID re-use fix, hashcat `cracked.json` output. [wifite2 PR/commit log](https://github.com/derv82/wifite2/pull/249/files)

### 1.4 GPU/OpenCL runtime developments
- hashcat v7 backend guidance: NVIDIA = driver 440.64+ plus CUDA toolkit 9.0+ (CUDA preferred, OpenCL fallback); AMD = AMDGPU 21.50+/ROCm 5.0+ or HIP SDK (note: AMD Adrenalin 22.7.1+ dropped HIPRTC, breaking hashcat HIP compile — install HIP SDK); Intel CPUs/iGPUs = Intel OpenCL runtime / **NEO Compute Runtime**. [hashcat error guidance, e.g. issue #4156](https://github.com/hashcat/hashcat/issues/4156)
- **Intel NEO (compute-runtime)** is open-source (MIT) OpenCL 3.0/Level Zero for Gen12+ through Panther Lake/Nova Lake; Fedora 42 (2025) adopted the new compute runtime with legacy hardware cut-off. CPU-OpenCL cracking remains viable but ~<10% of a mid-range GPU's WPA throughput — useful for rules/odd kernels, not for raw mask attacks. [intel/compute-runtime](https://github.com/intel/compute-runtime), [Fedora change proposal](https://discussion.fedoraproject.org/t/f42-change-proposal-intel-compute-runtime-upgrade-with-hw-cut-off-self-contained/139842)
- Hashcat's v7 Assimilation Bridge is the intended path to fold CPUs/FPGAs into the pipeline more formally.

### 1.5 Cloud / online cracking services
- Established WPA services still active: **wpa-sec (stanev.org)** (free community service; hashcat wiki recommends its `cracked.txt.gz` wordlist: `wget https://wpa-sec.stanev.org/dict/cracked.txt.gz`), **OnlineHashCrack** (online hashcat service incl. WPA), **GPUHASH.me**, banthex.de/wpa, hashes.pw — all have pwnagotchi upload plugins. [hashcat wiki](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2), [pwnagotchi plugins](https://pwnagotchi.org/3rd-party-plugins/plugins.html), [OnlineHashCrack hashcat service](https://www.onlinehashcrack.com/online-hashcat-service.php)
- 2025 trend: PAYG/subscription "cloud cracking" GPU clusters (~$10–13/GPU-hour; NTLM ~350 GH/s class on clusters in 2025 marketing claims — treat vendor benchmarks skeptically). [onlinehashcrack cloud-cracking 2025 guide](https://www.onlinehashcrack.com/guides/password-recovery/cloud-cracking-services-2025-costs-speeds.php)
- **OPSEC warning for engagements**: uploading client handshakes to third-party services leaks ESSIDs/passwords — get explicit authorization.

---

## 2. New CVEs (2024–2026) Affecting Routers/APs and WiFi Clients

### 2.1 WiFi protocol/driver layer
- **CVE-2024-30078 — Windows Wi-Fi Driver RCE (nwifi.sys)**, June 2024 Patch Tuesday. Unauthenticated, adjacent-network RCE via malformed 802.11 frames; no association or user interaction required. Root cause: missing length check in `Dot11Translate80211ToEthernetNdisPacket()` (802.1Q/vlanid path). Public analysis by Crowdfense (Sept 2024) shows exploitation via fake AP. [SentinelOne vuln DB](https://www.sentinelone.com/vulnerability-database/cve-2024-30078/), [Crowdfense analysis](https://www.crowdfense.com/windows-wi-fi-driver-rce-vulnerability-cve-2024-30078/)

### 2.2 Consumer/SOHO routers & APs (selected, verified)
- **CVE-2024-21833** — TP-Link Archer AX3000/AX5400/AXE75, Deco X50/XE200: unauthenticated **LAN/WiFi-adjacent OS command injection**. [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2024-21833/)
- **CVE-2024-20287** — Cisco WAP371 AP: authenticated command injection as root via web UI. [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2024-20287/)
- **CVE-2024-24329** — TOTOLINK A3300R: unauthenticated RCE in `setPortForwardRules`. [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2024-24329/)
- **CVE-2024-12856** — Four-Faith F3x24/F3x36 routers: OS command injection via `apply.cgi`; trivial with default creds. [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2024-12856/)
- **CVE-2024-39962** — D-Link DIR-823X AX3000: RCE. [Red Hat CVE page](https://access.redhat.com/security/cve/cve-2024-39962)
- **CVE-2025-25246** — NETGEAR XR1000/XR1000v2/XR500: unauthenticated network RCE (CWE-94 code injection). [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25246/)
- **CVE-2025-4121** — Netgear JWNR2000v2: authenticated command injection in `cmd_wireless` (`host` arg). [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-4121/)
- **CVE-2025-6542** — TP-Link Omada ER8411/ER7206 etc.: **unauthenticated network OS command injection** (CWE-78) on business routers/gateways. [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-6542/)
- **CVE-2025-7850 / CVE-2025-7851** (Forescout Vedere Labs, Oct 2025) — TP-Link Omada/Festa VPN routers: command injection via WireGuard private key sanitization (remotely exploitable **without credentials** in some deployments) + hidden `cli_server` root SSH path. More critical TP-Link issues in coordinated disclosure, patches expected Q1 2026. [Forescout blog](https://www.forescout.com/blog/new-tp-link-router-vulnerabilities-a-primer-on-rooting-routers/)
- **CVE-2025-15568** — TP-Link Archer AXE75 (WiFi 6E): authenticated adjacent-network command injection → root, CVSSv4 8.5, when `sysmode=ap`. [TP-Link advisory](https://www.tp-link.com/us/support/faq/5005/)
- **CVE-2025-12941/12942/12943/12945/12946** (NETGEAR Dec 2025 advisory) — incl. R6260/R6850 DNS-MiTM command execution; **RAX30/RAXE300 (WiFi 6E) firmware-update improper cert validation → MiTM malicious firmware** (CVE-2025-12943); R7000P admin command injection; Nighthawk speedtest MiTM command execution across many models. [NETGEAR Dec 2025 advisory](https://kb.netgear.com/000070416/December-2025-NETGEAR-Security-Advisory), [SentinelOne CVE-2025-12943](https://www.sentinelone.com/vulnerability-database/cve-2025-12943/)
- Actively-scanned in 2025 (GreyNoise tags): **CVE-2025-52688/52689** (Alcatel AP1361D WiFi AP command injection + auth bypass), **CVE-2025-52376/52378** (Nexxt mesh router auth bypass/XSS). [GreyNoise NoiseLetter July 2025](https://www.greynoise.io/resources/noiseletter-july-2025)

**Pattern for pentesters**: WiFi-adjacent command injection in web modules and MiTM-of-firmware/DNS paths dominate; many devices are EOL/unpatched — router compromise is often a faster path than handshake cracking once you're on (or near) the LAN.

---

## 3. Conference Talks & Research (DEF CON 31–33, Black Hat 2024–2026)

- **RF/Wireless Village evolution**: the former WiFi Village/Wireless Village (RF Hackers Sanctuary) rebranded as the **Radio Frequency Village at DEF CON 32** (2024) and continued at DC33 — scope now spans WiFi, BT, Zigbee, SDR, RFID; still runs the original WiFi/Wireless/RF CTF. Schedules: rfhackers.com/calendar. [DEF CON 32 villages page](https://defcon.org/html/defcon-32/dc-32-villages.html), [DEF CON 33 villages](https://defcon.org/html/defcon-33/dc-33-villages.html)
- **DEF CON 32 (Aug 2024)** wireless-relevant: "Warflying in a Cessna" (wardriving from aircraft — RF village/Aerospace). [Aerospace Village DC32 schedule](https://www.aerospacevillage.org/defcon-32-talk-schedule)
- **DEF CON 33 (Aug 2025)** relevant items: "Recording PCAPs from Stingrays With a $20 Hotspot" (EFF, main track); "What is Dead May Never Die: The Immortality of SDK Bugs" (Creator Stage 2 — includes vehicular-router/WiFi bug chains by Lawshae/Wang/Yu); Car Hacking Village talk chaining bus free-WiFi → vehicular router RCE. [DEF CON 33 schedule](https://defcon.org/html/defcon-33/dc-33-schedule.html), [Car Hacking Village DC33](https://www.carhackingvillage.com/defcon-33-talks)
- **Black Hat USA 2024–2025**: no headline-grabbing pure-WiFi briefing surfaced in this research window; wireless content has largely migrated to DEF CON RF Village and academic venues. (Negative result — verified across searches; do not cite invented talks.)
- **Academic research 2024–2026**:
  - SAE anti-clogging DoS: spoofed commit exchanges defeat cookie mechanism, push AP CPU to 100% (Raspberry Pi-class attacker). [OST integrative review PDF](https://eprints.ost.ch/id/eprint/1241/1/HS%202024%202025-SA-EP-Glaus-Burger-Wi-Fi%20Security%20Threats%20-%20an%20Integrative%20Review.pdf)
  - Deauth-vs-PMF studies: open/WPA1/WPA2-without-PMF fully vulnerable to deauth; WPA2+PMF and WPA3 resisted in controlled 2026 testbed measurements — PMF works when actually enforced. [arXiv deauth-resilience testbed](https://arxiv.org/html/2602.23513v1)
  - WPA3 transition-mode **downgrade-to-WPA2 evil twin** remains the standard practical attack; eaphammer automates rogue APs accepting WPA2-PSK against WPA3-transition SSIDs. [RedLegg WPA3 evil twin writeup](https://www.redlegg.com/blog/wpa3-evil-twin-attack)

---

## 4. WiFi 6E/7 & 6GHz Pentest Considerations

- **6 GHz is WPA3-only by regulation/certification**: WiFi 6E certification mandates WPA3 and Enhanced Open (OWE); **no WPA2 backward compatibility, no open SSIDs, PMF/MFP required** in 6 GHz. No transition modes → no downgrade path on pure-6GHz BSSIDs. [Extreme Networks 6GHz security blog](https://www.extremenetworks.com/resources/blogs/wireless-security-in-a-6-ghz-wi-fi-6e-world), [Cisco WPA3 blog](https://blogs.cisco.com/networking/wpa3-bringing-robust-security-for-wi-fi-networks)
- **Practical implication**: classic PMKID/handshake capture + hashcat workflow does **not** work against 6 GHz-only networks. Deauth (for handshake forcing) also fails with PMF. Attack surface shifts to: legacy-band twins of the same SSID (2.4/5 GHz transition-mode BSSIDs), evil twin/downgrade, enterprise 802.1X credential attacks (eaphammer/hostapd-wpe), router-side CVEs, and AFC/config weaknesses.
- **Hardware for 6 GHz monitoring/injection is the bottleneck**: Alfa AWUS1900/ACHM-class adapters are 2.4/5 GHz only. The community-recommended 6E adapter is the **AWUS036AXML (MediaTek MT7921AUN, in-kernel mt7921u since 5.18)**; 6 GHz injection is still not fully stable. Realtek RTL8832BU-based adapters (AWUS036AX/AXER) have poor monitor support below kernel 6.14 — avoid. Intel AX200/AX210 do **no injection** on Linux. [Yupitek Kali adapter guide 2026](https://yupitek.com/en/blog/best-wifi-adapter-kali-linux-2026/)
- **WiFi 7 (802.11be) specifics**: WPA3 mandatory, MLO (Multi-Link Operation) adds per-link encryption — deauth/jamming one band no longer disconnects an MLO client; rogue-AP mirroring of a single link remains a risk where policy parity across links is inconsistent. Vendor claims (Positive Technologies test of Huawei WiFi 7 at Muscat Airport, 2025) say KRACK/Dragonblood/FragAttacks were fully repelled vs ~72% max on WiFi 6 — directional, not independent. [Bitdefender MLO risk analysis](https://www.bitdefender.com/en-us/blog/hotforsecurity/wi-fi-7-multi-link), [joindigital WiFi 7 security](https://joindigital.com/news-insights/security-features-of-wifi-7), [Oman Airports WiFi 7 deployment](https://dokanway.com/tech-startups/oman-airports-worlds-first-wi-fi-7/)
- Regulatory note: 6 GHz availability varies (EU/UK only 480 MHz; China none as of early 2025) — check target geography for which bands are actually in use. [plusclouds WiFi 6E regulatory table](https://plusclouds.com/us/blogs/what-is-wifi-6e)

---

## 5. Defense Trends & Attack Surface Shifts

- **WPA3 adoption**: WPA3 mandatory for WiFi certification since July 2020 and required for 6E/7; Cisco reported ~60% of its enterprise AP deployments using WPA3 (2021 data point; enterprise transition mode remains common). PMF mandatory under WPA3 → classic deauth largely dead against well-configured modern networks (confirmed by 2026 testbed study).
- **Enhanced Open (OWE)**: mandatory in 6 GHz, so no truly open SSIDs there; passive sniffing of guest networks dies in 6 GHz. OWE gives encryption without authentication — evil twin/captive-portal credential phishing still works.
- **Transition mode is the soft underbelly**: WPA2/WPA3 transition SSIDs allow downgrade to crackable WPA2 handshakes (evil twin + eaphammer). Expect transition mode on 2.4/5 GHz for years.
- **SAE-specific attacks persist**: Dragonblood-class side channels mostly patched but linger in unpatched routers; SAE anti-clogging DoS (cookie replay/spoofed commits) demonstrated effective in 2024–2025 research.
- **MLO** widens the misconfiguration surface (per-link policy parity, link steering) but removes single-band deauth as a disconnection primitive.
- **Attack surface is migrating off the radio**: with PMF+SAE+OWE closing the classic capture-and-crack path, 2024–2026 impact concentrates on (a) router/AP web & firmware-update RCEs (§2), (b) client-side driver RCEs (CVE-2024-30078), (c) enterprise credential attacks (802.1X), (d) social-engineering captive portals, (e) WPS on legacy/ISP CPE (still live in the field).

---

## 6. Recommendations for Tool Builders

1. **Target hashcat v7.x API**: adopt the Assimilation/Python/Rust bridges for custom logic instead of forked kernels; use hash-mode autodetection (`--identify`) in your pipeline; if you drive hashcat from an agent/overlay (Hashtopolis-style), pin ≥ v7.1.2 for fixed machine-readable status output. Keep emitting/consuming **22000** — it remains the canonical WiFi format in v7.
2. **Track hcxtools v7.x**: relayed-EAPOL support (v7.0.0) and MESSAGEPAIR fixes (v7.0.1) change edge-case yields — re-run your regression pcaps after upgrading. Leverage NMEA ingest if your tool does wardriving correlation. Don't clean/merge pcapng files; hcxtools extracts value from "junk" frames.
3. **Borrow from wifite2's 2025 additions**: DragonBlood/OWE detection flags, adaptive deauth that **checks PMF status before wasting attempts**, and session/resume — all directly applicable to an aircrack-style automation tool. Add a PMF probe (SAE/RSN capabilities) and auto-route targets: WPA2-no-PMF → classic capture; transition mode → downgrade evil twin; pure WPA3/6 GHz → skip radio attacks, suggest client-side or router-side vectors.
4. **Plan a 6 GHz hardware path**: AWUS1900/ACHM stay your 2.4/5 GHz workhorses (RTL8814AU/MT7612U), but add an MT7921AUN adapter (AWUS036AXML) for 6E recon; treat 6 GHz injection as experimental (kernel ≥ 6.14 preferred). Architect your tool for tri-band channel lists and per-band capability flags now.
5. **Detection engineering for MLO/WiFi 7**: fingerprint MLDs (multi-link elements in beacons/probes); note that deauth tests must target per-link and that policy-parity gaps across links are the reportable finding.
6. **Cracking strategy**: PBKDF2-HMAC-SHA1 (4096 iters) is unchanged, so WPA2 cracking economics are stable — ~200 kH/s per RTX-4090-class GPU for 22000. Use wpa-sec `cracked.txt.gz` as a base list, keep CPU-OpenCL (Intel NEO) as a rules/preprocessing device, and treat cloud cracking services as an authorization-gated option (data-leak risk).
7. **Broaden beyond PSK**: with PMF/SAE/OWE rising, the highest-value modules to build next are (a) router CVE fingerprinting/exploitation after network access, (b) 802.1X credential capture (hostapd-wpe/eaphammer integration), (c) OWE evil-twin captive portal flows, (d) SAE anti-clogging DoS (authorized resilience testing only).
8. **Stay legal/scoped**: several capabilities above (DoS, downgrade, CVE exploitation) are strictly in-scope-only activities; log authorization in your tooling.

---
*Sources: all URLs inline above. Key primary sources: hashcat forum/wiki & GitHub releases, ZerBea hcxtools changelog, wifite2 commits, intel/compute-runtime, NETGEAR/TP-Link advisories, Forescout Vedere Labs, Crowdfense, SentinelOne vuln DB, DEF CON official schedules, Extreme Networks/Cisco/Bitdefender blogs, arXiv/OST research papers.*
