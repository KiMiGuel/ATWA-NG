# ATWA-NG — Usage

Short version: [README](../README.md). This page is the practical walkthrough.

## Screenshots
Drop panel captures into `docs/brand/` and they'll render here.

- Overview: `brand/gui-screenshot.png` (included)
- Add: `brand/scan.png`, `brand/attacks.png`, `brand/captures.png`, `brand/wps.png`

![ATWA-NG GUI](brand/gui-screenshot.png)

## Setup
Two adapters is the sane setup:
- `wlan0` → internet (managed)
- `wlan1` → monitor (ATWA-NG)

Modern NetworkManager (>= 1.0.12) doesn't need killing. Force it if you want:
```bash
ATWA_FORCE_NETWORK_MANAGER_KILLING=0 atwa gui
ATWA_FORCE_NETWORK_MANAGER_KILLING=1 atwa gui
```

## Start
```bash
sudo atwa gui
```
CLI mirrors everything (`atwa --help`).

## Scan
- Start Scan hops all channels.
- Single-click selects a target.
- Double-click locks to that channel; click Unlock to resume hopping.

If you only see a few targets, you're probably locked. Unlock.

## Attacks
- **Deauth** — kick a client or broadcast.
- **Floods** — auth, beacon, EAPOL, CSA, TKIP-MIC.
- **CHAOS** — all vectors at 100/1000/5000 frames.
- **Smart/Omni** — automated chains.

Stop Attack aborts between rounds. Some vectors finish their current frame first.

## Captures & cracking
Captures live in `~/atwa-hs/<SSID>_<BSSID>/`.

Handshake:
```bash
sudo atwa handshake --iface wlan1 --bssid AA:BB:CC:DD:EE:FF --channel 6
sudo atwa verify-handshake ~/atwa-hs/NET_AA:BB:CC:DD:EE:FF/handshake-01.cap
```

PMKID:
```bash
sudo atwa pmkid --iface wlan1 --bssid AA:BB:CC:DD:EE:FF --channel 6
```

Crack:
```bash
sudo atwa crack-cap ~/atwa-hs/NET_AA:BB:CC:DD:EE:FF/handshake-01.cap --wordlist rockyou.txt
sudo atwa crack ~/atwa-hs/NET_AA:BB:CC:DD:EE:FF/pmkid_*.22000 --wordlist rockyou.txt
```

GUI: lock a target with clients, capture, then crack from the Captures panel.

## WPS
```bash
sudo atwa wps-recon
sudo atwa wps-pixie --iface wlan1 --bssid AA:BB:CC:DD:EE:FF --channel 6
sudo atwa wps-oneshot --iface wlan0 --bssid AA:BB:CC:DD:EE:FF
```

## Cleanup
- Stop Attack stops the current job.
- Stop Monitor returns the adapter to managed mode and re-enables NM.
- On exit ATWA restores everything. If NM was killed (old NM), run:
  `sudo systemctl restart NetworkManager`.
- Stuck unmanaged adapter: `sudo nmcli device set <iface> managed yes`.

## Troubleshooting
- **Few channels/targets:** unlock channel lock; check monitor-mode support.
- **Socket died (ENETDOWN):** interface flap during active-monitor toggle; scan auto-restarts.
- **No internet during run:** NM killed. Use two adapters or netns, or restart NM after.
- **Deauth does nothing:** raise TX power, move closer, confirm monitor mode.