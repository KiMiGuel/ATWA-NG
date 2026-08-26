# ATWA-NG

Airwave Teardown Wireless Auditing - nextgen. WiFi security auditing
tool: v1's scanning engine (vendored aircrack-ng source) combined with a
native, from-scratch attack/crypto engine (WPS pixie-dust, PMKID, WEP
PTW, handshake capture) and a Tkinter GUI.

For authorized security testing only — against networks and devices you
own or are explicitly authorized to test.

## Install

```bash
pip install -e .
```

## Usage

```bash
atwa --help
atwa --version
atwa gui          # launch the GUI (needs root for monitor mode/injection)
```

See `atwa <command> --help` for CLI subcommands (`scan`, `deauth`,
`handshake`, `pmkid`, `wps`, `wep`, `crack`, `eviltwin`, and others).

## Requirements

- Linux, Python 3.10+
- A WiFi adapter capable of monitor mode and packet injection
- Root privileges for radio operations

## Development

```bash
pytest
```

67 hermetic tests as of 2026-08-25. GUI/radio behavior needs live
hardware to verify — not covered by the test suite.
