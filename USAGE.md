# ATWA-NG — Usage Guide

For authorized security testing only — against networks and devices you
own or are explicitly authorized to test.

## 1. Prerequisites

**Required** (nothing works without these):

| Tool | Install | Used for |
|---|---|---|
| `iw` | `sudo apt install -y iw` | monitor mode, channel control |
| `ip` | `sudo apt install -y iproute2` | interface up/down |

**Optional** (each gates exactly one Captures-tab action — missing one
only disables that specific feature, everything else still works):

| Tool | Install | Used for |
|---|---|---|
| `hcxpcapngtool` | `sudo apt install -y hcxtools` | convert captures to 22000 |
| `john` | install John the Ripper **jumbo** (openwall.com/john — not always packaged as plain `john`) | password cracking (22000 hashes) |
| `aircrack-ng` | `sudo apt install -y aircrack-ng` | password cracking (raw .cap, simpler than John) |
| `pcapfix` | `sudo apt install -y pcapfix` | repair a malformed capture |
| `mergecap` | `sudo apt install -y wireshark-common` | merge captures |

Check what's actually present on your system any time via **Help →
Check Dependencies** in the GUI, or `python3 -c "from atwa.deps import check_all; [print(s) for s in check_all()]"`.

**Hardware:** a WiFi adapter capable of monitor mode and packet
injection. Two adapters unlocks PINCER mode (simultaneous scan + attack
on separate radios).

## 2. Install

```bash
cd ~/ATWA-NG
pip install -e .
```

This installs the `atwa` command and its own venv-local console script.
The provided launcher at `~/.local/bin/atwa` wraps it with `sudo`
(everything here needs root for monitor mode/injection):

```bash
#!/bin/bash
exec sudo /home/KaliMa/ATWA-NG/.venv/bin/atwa "$@"
```

## 3. Launch

```bash
atwa gui
```

You'll get a small sudo-password prompt dialog (needed for root), then
the main window opens. First launch has:

- **Adapter** dropdown (top-left) — pick your WiFi card
- **Start Monitor** / **Stop Monitor** — puts the adapter into monitor mode
- **AP iface** dropdown — a *second* adapter for PINCER mode or Evil
  Twin's rogue-AP side, if you have one
- **Start Scanning** — begins hopping channels, building the target list
- Empty **Scanned Access Points** list, **Target** tab, **Captures** tab
- **Log** panel at the bottom — every action gets logged here

Or skip the GUI entirely and use the CLI directly:

```bash
atwa --help       # full subcommand list
atwa --version
```

## 4. The core flow

1. **Pick an adapter**, click **Start Monitor**. The button/label
   updates to show monitor mode is active.
2. Click **Start Scanning**. The target list fills in as beacons/probe
   responses are seen — BSSID, SSID, channel, security, signal.
3. **Click a target row.** This does more than preview it — it:
   - Locks the adapter to that AP's channel (stops the broader
     multi-channel hop)
   - Starts the Signal graph updating (fills in as new readings arrive)
   - Starts a real capture (vendored airodump-ng) restricted to that
     AP, so the **capture size (KB)** readout next to the graph
     actually grows
   - Populates the **Clients** list as stations are seen talking to it

   Double-clicking or hitting **Unlock** both still work — double-click
   is a no-op re-lock (harmless), Unlock resumes full-channel scanning
   and stops that target's capture.
4. **Run an attack** from the button stack or the **Attack** menu —
   Deauth, PMKID, Handshake Capture, Smart/OMNI (multi-stage), WEP, WPS
   variants, Evil Twin. **Stop Attack** (top-right, next to Unlock) ends
   whatever's running, including now correctly stopping a cracking job.
5. Switch to the **Captures** tab to see what's landed on disk. Actions
   there: Inspect, Convert to 22000, Fix (malformed capture), Merge,
   Crack Selected, Copy Path, or the fuller **Crack Handshakes
   (folder)...** dialog (its own Run/Stop, streams live cracker output).
6. Captures live at `~/hs/n2-ng/<SSID>_<BSSID>/` regardless of the
   project's own name — that path is intentionally fixed across
   renames.

## 5. CLI reference

```
atwa scan               v1-engine scan (vendored airodump-ng)
atwa deauth-aireplay     v1-engine deauth (vendored aireplay-ng)
atwa injection-test      test packet injection (vendored aireplay-ng -9)
atwa wash                WPS AP recon (vendored wash, from reaver source)
atwa crack-aircrack      crack via vendored aircrack-ng
atwa deauth              deauth flood (native scapy)
atwa pmkid               clientless PMKID capture
atwa handshake           4-way handshake capture
atwa omni                adaptive chain: profile -> pmkid -> handshake -> crack
atwa smart               quick attack: pmkid -> deauth+handshake
atwa wep                 native WEP: fake-auth + ARP replay + PTW
atwa wps-pixie           WPS pixie-dust (native scapy monitor mode)
atwa wps-oneshot         WPS via wpa_supplicant managed mode
atwa gui                 launch the desktop GUI
atwa crack               crack a 22000/cap file with John
atwa eviltwin            rogue AP + captive portal
```

Run `atwa <command> --help` for that subcommand's arguments.

## 6. Development

```bash
pytest
```

67 hermetic tests as of 2026-08-26. GUI/radio behavior needs live
hardware to verify — not covered by the test suite.
