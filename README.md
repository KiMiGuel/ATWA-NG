# ATWA-NG

WiFi auditing tool — scan, capture and crack WPA/WEP, plus flood, rogue-AP and WPS attacks.

**Requires root.** Authorized testing only.

## Install

```bash
git clone https://github.com/KiMiGuel/ATWA-NG
cd ATWA-NG && pip install -e .
```

## Quick start

```bash
sudo atwa gui
sudo atwa injection-test
sudo atwa scan --iface wlan0
sudo atwa omni --iface wlan0 --bssid AA:BB:CC:DD:EE:FF --ssid NET
sudo atwa crack ~/atwa-hs/NET_AA:BB:CC:DD:EE:FF/handshake-01.cap
```

## Commands

| | |
|---|---|
| `scan` | channel-hopping AP/client scan |
| `injection-test` | injection self-test |
| `wps-recon` | WPS-enabled AP recon |
| `eapol-hunt` | passive EAPOL handshake capture |
| `verify-handshake` | verify a captured handshake |
| `handshake` | 4-way handshake capture |
| `pmkid` | clientless PMKID capture |
| `crack-cap` | crack a capture directly |
| `crack` | crack a 22000/cap file |
| `deauth` | deauth flood |
| `chaos` | coordinated multi-vector flood |
| `omni` | adaptive chain: pmkid → handshake → crack |
| `smart` | pmkid → deauth + handshake |
| `wep` / `wep-hirte` | fake-auth + ARP replay + PTW |
| `wps-pixie` | Pixie-Dust |
| `wps-oneshot` | WPS via `wpa_supplicant` |
| `downgrade-twin` / `owe-downgrade` / `pmf-bypass` | rogue-AP downgrade |
| `dragonblood` | SAE timing side-channel pruning |
| `gui` | desktop GUI |
| `update` | install a newer release |

## Configuration

No config file. Fixed conventions:

- **Captures** → `~/atwa-hs/<SSID>_<BSSID>/`
- **Global flags** → `--help`, `--version`
- **Per-command** → `atwa <command> --help`

## Contribute

`CONTRIBUTING.md` — commit format, branches, PR rules.

Gates: `ruff check src/`, `mypy src/`, `pytest`.

## License

MIT