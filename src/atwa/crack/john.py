"""John the Ripper (jumbo) cracker backend.

John's wpapsk format does NOT accept a raw hashcat-format 22000 line
directly, confirmed: a real, spec-valid captured line was rejected with
"No password hashes loaded" despite being well-formed. Per hcxtools'
own docs, the required step is converting through hcxhashtool's
`--john=` output first (deprecated-john format) — that's what was
actually missing, not a version-skew mystery. `crack()`/`run_streaming()`
do that conversion internally so callers never need to know about it.
"""

from __future__ import annotations

import shutil
import subprocess

from .base import Cracker
from .convert import hc22000_to_john


class JohnUnavailableError(RuntimeError):
    """Raised when the john binary is not found."""


class JohnParseError(RuntimeError):
    """Raised when john rejects the converted hash file outright (0 hashes
    loaded) — distinct from a wordlist just not containing the password.
    Kept as a safety net after the hcxhashtool conversion step; without
    it JohnCracker would silently return {} (exit 0) either way — a false
    negative indistinguishable from "tried, wrong wordlist"."""


_NO_HASHES_MARKER = "No password hashes loaded"


class JohnCracker(Cracker):
    """Crack WPA hashes via john --format=wpapsk.

    hashfile passed to crack()/run_streaming() is a hashcat-format 22000
    file (what the rest of this project produces) — converted to John's
    own format internally via hcxhashtool before john ever sees it.
    """

    def __init__(self, binary: str = "john", fmt: str = "wpapsk"):
        self.binary = binary
        self.fmt = fmt
        if shutil.which(binary) is None:
            raise JohnUnavailableError(
                f"john not found in PATH; install John the Ripper jumbo"
            )

    def _prepare(self, hashfile: str) -> str:
        """Convert a hashcat 22000 file to John's format; return that path."""
        return hc22000_to_john(hashfile, hashfile + ".john")

    def crack(self, hashfile: str, wordlist: str) -> dict[str, str]:
        """Convert hashfile for John, run it with wordlist, parse `--show`."""
        john_file = self._prepare(hashfile)
        proc = subprocess.run(
            [self.binary, f"--format={self.fmt}", f"--wordlist={wordlist}", john_file],
            capture_output=True,
            text=True,
        )
        if _NO_HASHES_MARKER in proc.stdout:
            raise JohnParseError(
                f"john rejected {john_file} outright (0 hashes loaded) even after "
                f"hcxhashtool conversion — not a wrong wordlist. Try aircrack-ng instead."
            )
        return self.show(john_file)

    def run_streaming(self, hashfile: str, wordlist: str, on_line, proc_holder: dict) -> dict[str, str]:
        """Like crack(), but streams stdout line-by-line to on_line(str) as it
        happens (Popen, not subprocess.run) and stashes the live process on
        proc_holder["proc"] so a caller can proc.terminate() it from another
        thread — a real Stop button that actually terminates the process."""
        john_file = self._prepare(hashfile)
        proc = subprocess.Popen(
            [self.binary, f"--format={self.fmt}", f"--wordlist={wordlist}", john_file],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        proc_holder["proc"] = proc
        rejected = False
        for line in proc.stdout:
            if _NO_HASHES_MARKER in line:
                rejected = True
            on_line(line)
        proc.wait()
        if rejected:
            raise JohnParseError(
                f"john rejected {john_file} outright (0 hashes loaded) even after "
                f"hcxhashtool conversion — not a wrong wordlist. Try aircrack-ng instead."
            )
        return self.show(john_file)

    def show(self, hashfile: str) -> dict[str, str]:
        """Parse `john --show` output into {hash_id: plaintext}."""
        proc = subprocess.run(
            [self.binary, f"--format={self.fmt}", "--show", hashfile],
            capture_output=True,
            text=True,
        )
        results: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and not line.endswith("password hashes cracked"):
                results[parts[0]] = parts[1]
        return results
