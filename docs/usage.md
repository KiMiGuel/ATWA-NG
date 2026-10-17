# ATWA-NG — Usage Guide

Concise reference: [`README.md`](../README.md). This guide covers the GUI and common workflows.

## Table of contents
1. Install
2. Adapters & NetworkManager
3. Launch
4. GUI overview
5. Scan & channel lock
6. Attacks
7. Captures & cracking
8. WPS
9. Stop / cleanup
10. Troubleshooting

## 1. Install
```bash
git clone https://github.com/KiMiGuel/ATWA-NG
cd ATWA-NG
python -m venv .venv && source .venv/bin/activate
pip install -e .
```
Requires root for monitor-mode operations.

## 2. Adapters & NetworkManager
Recommended: two adapters.
- `wlan0` = internet (managed)
- `wlan1` = monitor (ATWA-NG)

Modern NetworkManager (>= 1.0.12) does not need to be killed. Force behavior:
```bash
ATWA_FORCE_NETWORK_MANAGER_KILLING=0 atwa gui   # keep NM
ATWA_FORCE_NETWORK_MANAGER_KILLING=1 atwa gui   # force kill
```

## 3. Launch
```bash
sudo atwa gui
```
CLI equivalents exist for every feature (`atwa --help`).

## 4. GUI overview
![ATWA-NG GUI](brand/gui-screenshot.png)

Panels:
- **Adapters** — select scan/monitor and AP-facing adapters; start/stop monitor mode.
- **Targets** — live scan results, signal, clients, security.
- **Attacks** — per-target and broadcast floods, WPS, WEP, rogue-AP.
- **Captures** — handshake/PMKID capture and cracking.
- **Log** — live status and errors.

## 5. Scan & channel lock
- **Start Scan** hops all channels.
- Single-click a row to select; double-click to **lock** to its channel.
- While locked, only that channel is scanned; capture restricted to the target.
- **Unlock** resumes full-channel hopping.

## 6. Attacks
Common flows:
- **Deauth** — disassociate a client (or broadcast).
- **Auth/Beacon/EAPOL/CSA/TKIP-MIC floods** — DoS/pressure vectors.
- **CHAOS** — runs all vectors at escalating tiers (100/1000/5000).
- **Smart/Omni** — adaptive chains (PMKID → handshake → crack).

Use **Stop Attack** to abort; attacks check between rounds/frames.

## 7. Captures & cracking
- Lock a target with clients to start a capture.
- `handshake`, `pmkid` capture to `~/atwa-hs/<SSID>_<BSSID>/`.
- Crack with `crack` / `crack-cap` or the Captures panel.

## 8. WPS
- `wps-recon` lists WPS-enabled APs.
- `wps-pixie` (Pixie-Dust), `wps-oneshot` (via wpa_supplicant).
- `wps-bruteforce` for PIN brute force.

## 9. Stop / cleanup
- **Stop Attack** aborts the current attack.
- **Stop Monitor** returns the adapter to managed mode and re-enables NM management.
- On close, ATWA restores monitor → managed and restarts NM.
- If NM was killed (old NM), restart manually:
  `sudo systemctl restart NetworkManager`.

## 10. Troubleshooting
- **No targets / few channels:** unlock channel lock; check adapter supports monitor mode.
- **Socket died (ENETDOWN):** interface flap during active-monitor toggle; scan auto-restarts.
- **No internet during run:** NM killed (old NM or forced). Use two adapters or netns; or restart NM after.
- **Adapter stuck unmanaged:** `sudo nmcli device set <iface> managed yes`.
- **Deauth no effect:** raise TX power or move closer; check monitor mode.