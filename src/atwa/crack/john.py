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

import os
import shutil
import signal
import subprocess
import uuid
from pathlib import Path

from .. import storage
from .base import Cracker
from .convert import hc22000_to_john

# Common local clone locations to try when `john` isn't on PATH.
_JOHN_FALLBACK_PATHS = [
    Path.home() / "john" / "run" / "john",
    Path.home() / "John" / "run" / "john",
]


def _resolve_john_binary(binary: str) -> str:
    """Return the first usable John binary: a known local clone location
    (e.g. ~/john/run/john, kept newer/self-built than the distro package)
    takes priority over explicit arg / PATH lookup."""
    for path in _JOHN_FALLBACK_PATHS:
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    if shutil.which(binary):
        return binary
    return binary


class JohnUnavailableError(RuntimeError):
    """Raised when the john binary is not found."""


class JohnParseError(RuntimeError):
    """Raised when john rejects the converted hash file outright (0 hashes
    loaded) — distinct from a wordlist just not containing the password.
    Kept as a safety net after the hcxhashtool conversion step; without
    it JohnCracker would silently return {} (exit 0) either way — a false
    negative indistinguishable from "tried, wrong wordlist"."""


_NO_HASHES_MARKER = "No password hashes loaded"

# John's wpapsk format has no OpenMP support (confirmed live: john warns
# "no OpenMP support for this hash type, consider --fork=N" on every run
# without it), so without --fork it only ever uses one core regardless of
# the machine. Capped at 8 rather than the raw core count -- John forks a
# full separate process per worker, and past ~8 the per-process overhead
# (each with its own .rec/.log) stops paying for itself on a wordlist
# attack, which is I/O-bound on candidate generation more than CPU-bound.
_MAX_FORK = 8


def _fork_count() -> int:
    return max(1, min(os.cpu_count() or 1, _MAX_FORK))


def _rules_args(rules: str) -> list[str]:
    """--rules=<section> if a real ruleset was chosen, else nothing --
    empty string and the literal "None" both mean plain wordlist mode
    (John's own default when --rules is omitted entirely)."""
    if rules and rules.lower() != "none":
        return [f"--rules={rules}"]
    return []


def _session_dir() -> Path:
    """Where John's --session .rec/.log files live: a hidden folder inside
    the fixed capture root, not wherever atwa happened to be launched from.
    John writes <session>.rec/<session>.log relative to the --session value
    itself, so passing a path prefix (not just a bare name) redirects them
    here directly -- previously they landed loose in the launch directory
    (confirmed live: atwa_<hex>.log/.rec appearing directly in ~ after a
    run launched from the home directory), with no cleanup, ever."""
    d = storage.capture_root() / ".john-sessions"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _session_name() -> str:
    """A fresh, unique --session path prefix per run. John's default
    (unnamed) session always writes to the same john.rec regardless of
    hashfile/wordlist -- giving every run its own name means a leftover
    .rec from a stopped run can never be mistaken for -- or interfere
    with -- a later run with different arguments."""
    return str(_session_dir() / f"atwa_{uuid.uuid4().hex[:12]}")


def terminate_tree(proc: subprocess.Popen, grace: float = 5.0) -> None:
    """Terminate john including its --fork=N worker children.

    --fork spawns N-1 child processes; proc.terminate()/kill() only
    signals the leader, orphaning the workers (they keep burning CPU
    after Stop -- confirmed shape of the bug report). The process is
    started with start_new_session=True, so the whole group gets the
    signal: SIGTERM first, SIGKILL on timeout."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        proc.terminate()
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.wait()


class JohnCracker(Cracker):
    """Crack WPA hashes via john --format=wpapsk.

    hashfile passed to crack()/run_streaming() is a hashcat-format 22000
    file (what the rest of this project produces) — converted to John's
    own format internally via hcxhashtool before john ever sees it.
    """

    def __init__(self, binary: str = "john", fmt: str = "wpapsk"):
        self.binary = _resolve_john_binary(binary)
        self.fmt = fmt
        if shutil.which(self.binary) is None:
            raise JohnUnavailableError(
                "john not found in PATH and no local clone built; "
                "install John the Ripper jumbo or build ~/john/run/john"
            )

    def _prepare(self, hashfile: str) -> str:
        """Convert a hashcat 22000 file to John's format; return that path."""
        return hc22000_to_john(hashfile, hashfile + ".john")

    def crack(self, hashfile: str, wordlist: str, rules: str = "", timeout: float = 3600.0) -> dict[str, str]:
        """Convert hashfile for John, run it with wordlist, parse `--show`."""
        john_file = self._prepare(hashfile)
        fork = _fork_count()
        cmd = [self.binary, f"--format={self.fmt}", f"--wordlist={wordlist}",
               "--progress-every=5", f"--session={_session_name()}"]
        if fork > 1:
            cmd.append(f"--fork={fork}")
        cmd.extend(_rules_args(rules))
        cmd.append(john_file)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        # John prints "No password hashes loaded" to STDERR, not stdout --
        # checking stdout alone never fires and silently returns {}.
        if _NO_HASHES_MARKER in proc.stdout + proc.stderr:
            raise JohnParseError(
                f"john rejected {john_file} outright (0 hashes loaded) even after "
                f"hcxhashtool conversion — not a wrong wordlist. Try aircrack-ng instead."
            )
        return self.show(john_file)

    def run_streaming(self, hashfile: str, wordlist: str, on_line, proc_holder: dict, rules: str = "") -> dict[str, str]:
        """Like crack(), but streams stdout line-by-line to on_line(str) as it
        happens (Popen, not subprocess.run) and stashes the live process on
        proc_holder["proc"] so a caller can proc.terminate() it from another
        thread — a real Stop button that actually terminates the process."""
        john_file = self._prepare(hashfile)
        fork = _fork_count()
        cmd = [self.binary, f"--format={self.fmt}", f"--wordlist={wordlist}",
               "--progress-every=5", f"--session={_session_name()}"]
        if fork > 1:
            cmd.append(f"--fork={fork}")
        cmd.extend(_rules_args(rules))
        cmd.append(john_file)
        on_line(f"wordlist: {wordlist}\n")
        on_line(f"rules: {rules or 'None'}\n")
        on_line(f"fork: {fork}\n")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            stdin=subprocess.DEVNULL,
            start_new_session=True,  # own process group so terminate_tree() can kill --fork children
        )
        proc_holder["proc"] = proc
        assert proc.stdout is not None
        rejected = False
        try:
            for line in proc.stdout:
                if _NO_HASHES_MARKER in line:
                    rejected = True
                on_line(line)
        finally:
            terminate_tree(proc)
        if rejected:
            raise JohnParseError(
                f"john rejected {john_file} outright (0 hashes loaded) even after "
                f"hcxhashtool conversion — not a wrong wordlist. Try aircrack-ng instead."
            )
        return self.show(john_file)

    def benchmark(self, seconds: int = 3) -> str:
        """Run John's own --test benchmark for this format and return its
        raw output -- the real, per-machine number, not a guess. Separate
        from an actual crack run: --test needs no hashfile/wordlist at all.

        No --fork here: John rejects --test combined with --fork outright
        ("Invalid options combination: --test=N"), confirmed live -- wpapsk
        already has its own OpenMP threading for --test, so this machine's
        cores are still exercised without it."""
        cmd = [self.binary, f"--format={self.fmt}", f"--test={seconds}"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=seconds + 30)
        return (proc.stdout + proc.stderr).strip()

    def show(self, hashfile: str) -> dict[str, str]:
        """Parse `john --show` output into {hash_id: plaintext}."""
        proc = subprocess.run(
            [self.binary, f"--format={self.fmt}", "--show", hashfile],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        results: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            # Split ONCE: a cracked PSK may itself contain ':' -- taking
            # parts[1] of a full split silently truncates those passwords.
            parts = line.split(":", 1)
            if len(parts) >= 2 and not line.endswith("password hashes cracked"):
                results[parts[0]] = parts[1]
        return results
