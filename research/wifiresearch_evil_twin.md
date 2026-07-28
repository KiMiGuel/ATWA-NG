# Evil Twin Attack Frameworks & Source Code — Research Brief
**Date:** 2026-07-29 · **Audience:** WiFi pentester building tooling (Alfa AWUS1900 / AWUS036ACHM-class adapters)
**Method:** 25 web searches; every repo URL below verified live via the GitHub REST API (`pushed_at`, stars, archived flag) on 2026-07-29.

---

## Key Findings

1. **The actively maintained core stack (2024–2026) is airgeddon, hostapd-mana, eaphammer, wifiphisher, and garywill/linux-router.** Everything else in the classic Evil Twin canon (create_ap, mana-toolkit, fluxion upstream, wifipumpkin3) is stale or slow-moving, though most still work.
2. **hostapd-mana (SensePost) is quietly the most-alive offensive WiFi codebase** — pushed 2026-07-28, and Parrot OS 7.0 (Dec 2025) explicitly shipped a *fixed hostapd-mana dependency* alongside airgeddon 11.60. It is the upstream engine behind berate_ap, airgeddon's enterprise attacks, and WPA3-downgrade tools.
3. **The hot research frontier is WPA3-transition-mode (Dragonblood) downgrade via rogue AP.** Two dedicated 2024–2025 tools exist: **DragonShift** (2024, hostapd-mana-based) and **AirBully** (2025). RedLegg published a full field write-up doing this with eaphammer.
4. **airgeddon is the de-facto maintained captive-portal Evil Twin framework** — v12.0 released May 2026, repo pushed 2026-07-18, ~7.9k stars, with an active plugin ecosystem (KeyofBlueS/airgeddon-plugins, incl. a Dragon Drain plugin updated Jun 2026).
5. **fluxion is effectively unmaintained upstream**, but the community "FluxionNetwork/fluxion" repo shows pushes into 2026 (mostly issue/translation churn); serious users have moved to airgeddon or wifiphisher.
6. **create_ap is archived (Dec 2023).** Its maintained spiritual successor is **garywill/linux-router** (pushed Jul 2026); for MANA-style APs the successor is **sensepost/berate_ap**.
7. For your adapters: AWUS1900 (RTL8814AU) and AWUS036ACHM (MT7610U) both support AP+monitor+injection on Kali with community drivers; all frameworks below drive them through hostapd/dnsmasq via nl80211, so adapter choice matters less than driver build. Two-adapter workflows (rogue AP + deauth) are the norm — exactly what your Alfa pair enables.

---

## Frameworks & Repos

### Tier 1 — Actively maintained (commits in 2024–2026)

| Tool | Repo URL | Version / Last activity | Capabilities & hostapd/dnsmasq handling |
|---|---|---|---|
| **airgeddon** | https://github.com/v1s1t0r1sh3r3/airgeddon | v12.0 (2026-05-18); pushed 2026-07-18; ~7,881★; not archived | All-in-one bash framework. Evil Twin menu: captive-portal Evil Twin (built-in multi-language portal templates that verify captured PSK against a real handshake), Enterprise Evil Twin (via **hostapd-mana**), DoS-pursuit mode. Spawns **hostapd/hostapd-mana + dnsmasq** itself; handles iptables/NAT. Plugin system (airgeddon-plugins). Supports 5 GHz (relevant for AWUS1900/ACHM). Source: https://gitlab.com/kalilinux/packages/airgeddon/-/tags |
| **hostapd-mana** | https://github.com/sensepost/hostapd-mana | pushed **2026-07-28** (most active of all); ~614★ | SensePost's patched hostapd implementing KARMA (respond to all probe requests), MANA (respond with probed SSIDs), loud mode, WPA/WPA2 handshake capture to hccapx/hashcat format, WPE-style EAP credential interception (PEAP/MSCHAPv2 → NetNTLMv1), `enable_sycophant` relay hook. Requires external dnsmasq for DHCP/DNS (orchestrated by berate_ap or scripts). Latest commit verified at https://github.com/sensepost/hostapd-mana |
| **eaphammer** | https://github.com/s0lst1c3/eaphammer | v1.14.0 (ESSID-stripping attacks); pushed 2024-09-22; ~2,536★ | Targeted Evil Twins vs WPA2-Enterprise: RADIUS cred theft (PEAP/MSCHAPv2, GTC downgrade for plaintext), hostile portal attacks (AD creds + indirect wireless pivots via timed PowerShell payloads), captive portal w/ keylogging + payload delivery + integrated website cloner (v1.13.5), PMKID attacks, password spraying, OWE/OWE-transition rogue APs, 802.11w PMF support, SSID cloaking, karma + loud karma + known-beacons. Bundles its **own hostapd (2.8-based) fork**; drives **dnsmasq** for DHCP/DNS; integrates Responder. Kali package: https://www.kali.org/tools/eaphammer/ |
| **wifiphisher** | https://github.com/wifiphisher/wifiphisher | v1.4 codebase; pushed 2026-05-22 (repo active, code stable); ~14,715★ | Rogue AP framework: Evil Twin + KARMA + Known Beacons auto-association, victim-customized phishing (firmware-upgrade, OAuth-login, browser-plugin-update, web-based network manager scenarios), handshake-verified PSK capture, community scenario repo. Prefers its **roguehostapd** fork (https://github.com/wifiphisher/roguehostapd, stale since 2021 — Python-2-era build issues on modern distros); `--force-hostapd` falls back to system hostapd at feature cost. Sets up its own DHCP (no dnsmasq) + iptables NAT. Docs: https://wifiphisher.readthedocs.io/ |
| **garywill/linux-router** | https://github.com/garywill/linux-router | pushed 2026-07-08; ~2,036★ | Modern create_ap replacement. One command: hostapd + dnsmasq + NAT/bridge/redsocks, IPv6, VM/container routing. No offensive features, but the cleanest maintained hostapd/dnsmasq orchestration code to crib for custom tooling. |
| **DragonShift** | https://github.com/jabbaw0nky/DragonShift | v1, 2024-08-25; ~66★ | Automates WPA3-transition (Dragonblood) downgrade: airodump recon → detects SAE+PSK/MFP-inactive APs → generates hostapd-mana configs → rogue WPA2 AP captures handshake → hccapx for hashcat. Tested on WiFiChallengeLab. Uses **hostapd-mana directly**; no captive portal (pure handshake capture). Blog: https://jabba.sensorack.com/posts/2024/08/wpa3-downgrade-attack/ |
| **AirBully** | https://github.com/lutfizp/AirBully | pushed 2025-05-07; ~9★ | Semi-automated bash toolkit for targeted WPA3 Transition Mode downgrade attacks (found via GitHub wpa3 topic; small but recent). |
| **berate_ap** | https://github.com/sensepost/berate_ap | pushed 2025-02-03; ~249★ | create_ap-style wrapper that orchestrates **hostapd-mana** (default) + dnsmasq: `--mana`, `--mana-loud`, `--mana-wpe` (EAP cred interception), `--mana-eapsuccess`, `--mana-eaptls`, `--mana-wpa` (handshake capture to hccapx), `--wpa-sycophant` relay mode, EAP with built-in RADIUS or external FreeRADIUS, WPA3/OWE flags, 802.11w. Full option dump: https://www.kali.org/tools/berate-ap/ |
| **airgeddon-plugins (KeyofBlueS)** | https://github.com/KeyofBlueS/airgeddon-plugins | pushed 2026-03-01; ~125★ | Extensions incl. 5 GHz improvements, BeEF integration, and a **Dragon Drain (SAE DoS) plugin** updated Jun 2026 — shows where community Evil Twin/DoS innovation is happening. |

### Tier 2 — Stalled but still widely used / reference-grade

| Tool | Repo URL | Last activity | Notes |
|---|---|---|---|
| **wifipumpkin3** | https://github.com/P0cL4bs/wifipumpkin3 | v1.1.7 "Gao" (2023-11-16); repo pushed 2024-01-09; ~2,484★ | Python rogue-AP framework: captiveflask captive-portal phishing (templates + custom), **Phishkin3 (MFA-aware phishing via captive portal)**, EvilQR3 (QR phishing), dns2proxy DNS spoofing, PumpkinProxy (intercept/modify web traffic), BeEF hooking, deauth module, REST API. Uses **hostapd + dnsmasq** (dhcpd module) or its own DHCP; supports hostapd-wpe w/ karma since v1.1.4. Installable via Kali `apt install wifipumpkin3`. Docs: https://docs.wifipumpkin3.com/ — still the richest captive-portal/MFA-phishing codebase to study. |
| **fluxion** | https://github.com/FluxionNetwork/fluxion | pushed 2026-07-21 (mostly maintenance churn; core attack logic ~2019–2021); ~5,858★ | Linset remake: handshake-snooper + captive portal with PSK verification via aircrack against captured handshake, multi-language portals, hostapd + dnsmasq + lighttpd stack. Functional but code is old; prefer airgeddon for the same workflow. |
| **Esser50K/EvilTwinFramework** | https://github.com/Esser50K/EvilTwinFramework | pushed 2024-08-01; ~357★ | Python framework for Evil Twins + other WiFi exploits (presented with DEF CON talk lineage); modular, good reference architecture for custom tooling. |
| **InfamousSYN/rogue** | https://github.com/InfamousSYN/rogue | pushed 2024-10-30; ~302★ | Extensible toolkit to deploy rogue APs in red-team engagements; hostapd-based, modular payload/cert handling. |
| **wpa_sycophant** | https://github.com/sensepost/wpa_sycophant | v1.0; pushed 2023-07-05; ~219★ | Patched wpa_supplicant relaying PEAP/MSCHAPv2 phase-2 auth from rogue AP (hostapd-mana `enable_sycophant`) to the real AP — MSCHAP relay without cracking. Requires `crypto_binding=0`; ~3 adapters. Packaged in Kali since 2021.3 (`apt install wpa-sycophant`). |

### Tier 3 — Deprecated / archived (do not build on)

| Tool | Repo URL | Status |
|---|---|---|
| **create_ap** | https://github.com/oblique/create_ap | **ARCHIVED** 2023-12-13; ~4,516★. Superseded by garywill/linux-router; its MANA fork lineage lives on in berate_ap. |
| **mana-toolkit** | https://github.com/sensepost/mana | DEPRECATED (DEF CON 26 announcement); pushed 2018-08-21; ~1,101★. Core lives on in hostapd-mana + berate_ap; toolkit itself (run-mana, crackapd, sslstrip-hsts) is historical reference. |
| **MarauderCentauri** | https://github.com/justcallmekoko/maraudercentauri | Stale (2021); ESP32/ESP8266 Evil Twin suite. Active successors are community ESP32 Marauder builds and ESP32 captive-portal Evil Twin repos (2025–2026, e.g. the ESP32 deauther+evil-twin firmwares trending on the `evil-twin` topic) — microcontroller-class, orthogonal to your Alfa tooling. |

---

## Techniques

### Captive portal phishing (state of the art, 2022–2026)
- **Handshake-verified portals:** airgeddon & fluxion capture the 4-way handshake first, then validate portal-submitted PSKs against it (aircrack-ng) before releasing the victim — kills false submissions. wifiphisher does the same via `--handshake-capture`.
- **Victim-customized pages:** wifiphisher parses beacons + HTTP User-Agent to render OS-matching fake network managers and vendor-matching router pages. airgeddon ships multi-language router-login templates ("re-enter WiFi password to reconnect").
- **MFA-aware phishing:** wifipumpkin3's **Phishkin3** proxy performs MFA phishing via captive portal; **EvilQR3** does QR-code phishing from the portal.
- **Keylogging/payload portals:** eaphammer's modular portal (v1.13.5+) has JS keylogging, payload delivery, and an integrated **website cloner** (pywebcopy-based) for cloning any login page into a portal module.
- **HSTS reality check:** pure HTTP captive portals still work because the portal *is* the interception point; sslstrip-style post-connect MITM is largely dead vs HSTS preload. Modern value is in credential capture at the portal, not traffic stripping.
- **Detection trigger:** modern captive-portal detection (CNA on iOS/macOS, Android captive portal check) is abused by all portal frameworks — they answer the OS probe endpoints to force the login popup.

### WPA-Enterprise credential harvesting (EAP)
- **PEAP/MSCHAPv2 → NetNTLMv1:** rogue RADIUS in hostapd-mana/eaphammer captures MSCHAPv2 challenge-response; crack with hashcat mode 5500 (or asleap). Root cause: clients not validating server certs — a 2024 Blancco survey found **31% of 802.1X deployments accept any server cert / no CA pinning** (https://nohack.net/wi-fi-security-wpa3-and-beyond/).
- **GTC downgrade:** eaphammer auto-attempts EAP-GTC downgrade → plaintext creds (from PAP-token exchange).
- **EAP relay (no cracking):** wpa_sycophant + hostapd-mana relays the live PEAP session to the real AP; works only with `crypto_binding=0`, PEAP (not TTLS), 3 adapters. Defense: enforce crypto binding / EAP-TLS. Detailed walkthrough: https://www.kayssel.com/newsletter/issue-39/
- **EAP-TLS:** immune to credential theft; `mana-eaptls` accepts any client cert for auth-success-only tricks.

### KARMA / MANA
- Classic KARMA (respond "yes" to any probe) still works against legacy clients; modern OSes mostly use directed probes with saved-network SSIDs, hence **MANA** (respond with the SSID being probed) and **loud MANA** (broadcast all seen SSIDs). Implementation reference: hostapd-mana source + SensePost DEF CON 22/26 talks; hub: https://w1f1.net/.
- **ESSID stripping** (eaphammer 1.14.0, 2024): strip non-printable/leading chars to defeat SSID cloaking.

### WPA3 transition-mode downgrade (Dragonblood lineage)
- Rogue WPA2-only AP with same SSID → client in transition mode falls back → capture WPA2 4-way handshake → offline crack. Preconditions: AP advertises SAE+PSK, MFP not enforced (check `airodump-ng` AUTH column and beacon RSN capabilities). Tools: DragonShift (automated), AirBully, eaphammer/hostapd-mana manually. Field report: https://www.redlegg.com/blog/wpa3-evil-twin-attack · Explainer: https://cavementech.com/2026/04/wpa3-hacking.html
- Pure-SAE networks: only online attacks (Wacker) or SAE DoS (Dragon Drain — available as airgeddon plugin).

---

## Papers & Talks

- **SensePost, "Improvements in Rogue AP Attacks – MANA"** — DEF CON 22 (2014). Foundational KARMA→MANA improvements. https://youtu.be/i2-jReLBSVk · https://sensepost.com/blog/2015/improvements-in-rogue-ap-attacks-mana-1%2F2/
- **Michael Kruger & Dominic White, "Practical attacks against WPA-EAP-PEAP"** — DEF CON 26 (2018); PEAP relay (wpa_sycophant) + mana-toolkit deprecation in favor of bettercap/berate_ap. https://github.com/sensepost/wpa_sycophant
- **Vanhoef & Ronen, "Dragonblood"** (2019) — WPA3 SAE side-channels + downgrade; basis of 2024–2025 transition-mode tooling (DragonShift/AirBully).
- **RedLegg (2025-06), "WPA3 Evil Twin Attack"** — real-engagement write-up of transition-mode downgrade with eaphammer. https://www.redlegg.com/blog/wpa3-evil-twin-attack
- **Akerva / CHAABT Moussa (2024-08), DragonShift release blog.** https://jabba.sensorack.com/posts/2024/08/wpa3-downgrade-attack/
- **Kayssel "WiFi Hacking 101" series, Part 4 (2026)** — modern PEAP relay + crypto-binding defense analysis. https://www.kayssel.com/newsletter/issue-39/
- **eaphammer GTC downgrade talk** (linked from README): https://www.youtube.com/watch?v=-uqTqJwTFyU
- **Blancco 2024 survey** (via nohack.net) — 31% of enterprise 802.1X clients accept any RADIUS cert: https://nohack.net/wi-fi-security-wpa3-and-beyond/
- **w1f1.net** — SensePost-curated hub of wireless hacking research/tools.

---

## Recommended Deep-Dive Areas

1. **hostapd-mana source** (https://github.com/sensepost/hostapd-mana) — the single most valuable codebase: probe-response taxonomy, WPA handshake capture hooks, sycophant relay hook. Pushed yesterday; read the diff vs upstream hostap.
2. **airgeddon's Evil Twin + Enterprise modules** — best-maintained reference for orchestrating hostapd/hostapd-mana + dnsmasq + iptables + portal verification in bash; also its plugin API for extending.
3. **wifipumpkin3 captiveflask/Phishkin3** — study MFA-aware captive portal phishing and QR-phishing proxy design; port ideas forward since core is 2023-era.
4. **eaphammer portal cloner + hostile portal pivots** — keylogging portal modules and indirect-wireless-pivot payload generation (unique to eaphammer).
5. **WPA3 transition-mode toolchain** — combine DragonShift's recon/detection logic (SAE+PSK + MFP check) with berate_ap `--mana-wpa` for a modern, self-contained downgrade tool; this is where new-tool whitespace exists in 2026.
6. **PEAP relay hardening gap** — inventory targets on `crypto_binding`; wpa_sycophant is 2023-stale but the attack is unpatched in most deployments.
7. **Driver layer for your adapters** — AWUS1900 (RTL8814AU: use aircrack-ng/rtl8814au driver) and AWUS036ACHM (MT7610U: upstream mt76 or morrownr driver) — verify AP mode + injection per driver before framework testing; 5 GHz AP mode on the AWUS1900 unlocks dual-band Evil Twins that airgeddon/eaphammer support but ESP32-class tools can't touch.
8. **garywill/linux-router** — cleanest maintained hostapd+dnsmasq+NAT orchestration; ideal scaffolding if building your own Evil Twin tooling rather than forking create_ap.
