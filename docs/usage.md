# ATWA-NG — Usage (concise)

## Requirements
- Linux with a monitor-mode-capable Wi-Fi adapter
- Python 3.11+
- `iw`, `ip`, `nmcli` (NetworkManager)

## Install
```bash
git clone https://github.com/KiMiGuel/ATWA-NG.git
cd ATWA-NG
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Two-adapter setup (recommended)
- `wlan0` = internet (managed)
- `wlan1` = monitor (ATWA-NG)
ATWA-NG now keeps NM alive on modern NetworkManager (>= 1.0.12).  
Force behavior with `ATWA_FORCE_NETWORK_MANAGER_KILLING=0|1`.

## Start monitor mode
```bash
atwa gui
# or CLI
atwa scan --iface wlan1
```

## Basic flow
1. Select adapter → **Start Monitor**.
2. **Start Scan** (hops all channels by default).
3. Double-click a target to **lock** its channel; click **Unlock** to resume hopping.
4. Run an attack from the Attacks tab.
5. **Stop Attack** aborts the running attack.

## Notes
- Channel lock restricts scanning to one channel until unlocked.
- On older NetworkManager, ATWA may kill NM; restart it after use:
  `sudo systemctl restart NetworkManager`.
- Stop monitor / quit returns the adapter to managed mode and re-enables NM management.