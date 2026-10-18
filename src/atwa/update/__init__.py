"""Lightweight GitHub release update checks for ATWA-NG.

The check is deliberately small and dependency-free: it uses only Python's
standard library, has a short timeout, and never runs on the Tk or radio hot
path. The pushed *tags* API is the release signal (since 2.5.9, commit
ca74470): the workflow tags a version before the GitHub Release gets
published, and ``/releases/latest`` only reflects published releases -- so
it lagged the actual push and left users stuck on the old version. Tags
reflect a push immediately; the release URL we hand back becomes live as
soon as the matching GitHub Release is published.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPOSITORY = "KiMiGuel/ATWA-NG"
TAGS_API_URL = f"https://api.github.com/repos/{REPOSITORY}/tags"
USER_AGENT = "ATWA-NG-update-check"


@dataclass(frozen=True)
class UpdateResult:
    """Result of one release lookup.

    Network/API failures are represented in ``error`` rather than raised so a
    GUI startup or CLI check can never fail because GitHub is unavailable.
    """

    current: str
    latest: str | None = None
    release_url: str | None = None
    update_available: bool = False
    error: str | None = None
    checked_at: float = 0.0


def _version_parts(value: str) -> tuple[tuple[int, ...], int, str]:
    """Parse a release version into a totally-ordered comparison key.

    The key is ``(numbers, kind, suffix)``:

    * ``numbers`` -- the numeric components with trailing zeros
      canonicalised away, so ``2.4`` == ``2.4.0`` while ``2.5.3.1`` >
      ``2.5.3``. Canonicalising is what lets variable-length versions
      compare correctly without any marker/terminator machinery: Python's
      own tuple ordering gives ``(2,4) == (2,4,0)``'s canonical form and
      ``(2,5,3) < (2,5,3,1)``.
    * ``kind`` -- 0 for a pre-release, 1 for a final release, so a final
      always sorts above its own pre-releases (``2.4.0-rc1`` < ``2.4.0``)
      and ``suffix`` is only ever compared against another string.
    * ``suffix`` -- the lowercased pre-release label (``rc1``, ``beta``).

    Unparseable tags sort below every well-formed version: their key starts
    with the same empty ``numbers`` tuple a canonical ``0.0.0`` has, so
    ordering falls to ``kind`` -- ``-1`` sits below both final (1) and
    pre-release (0), and two unparseable tags only ever compare
    ``suffix`` vs ``suffix`` -- never int-vs-str, so a malformed tag can
    never raise TypeError mid-check (that regression shipped once
    already, 2026-09-25). (A ``-1`` *number component* would NOT have
    worked: the empty tuple of ``0.0.0`` sorts below every non-empty
    tuple, so ``0.0.0`` would have compared older than garbage.)

    Replaced a flatter ``(marker, value)`` scheme whose terminator shared
    its shape with real numeric components: after the trailing-zero trim,
    ``3.0.1`` compared *older* than ``3.0.0`` because the final-release
    terminator slid ahead of the newer version's zero minor component.
    """
    cleaned = value.strip().lstrip("vV")
    match = re.match(r"^([0-9]+(?:\.[0-9]+)*)(.*)$", cleaned)
    if not match:
        return ((), -1, cleaned)
    numbers = [int(part) for part in match.group(1).split(".")]
    while numbers and numbers[-1] == 0:
        numbers.pop()
    suffix = match.group(2).lstrip("-+").lower()
    if not suffix:
        return (tuple(numbers), 1, "")
    return (tuple(numbers), 0, suffix)


def is_newer(latest: str, current: str) -> bool:
    """Return whether ``latest`` is newer than ``current``.

    Missing/development versions are treated as older than a valid release,
    which ensures source-tree users are notified rather than silently skipped.
    """
    if not latest or not current or current == "0.0.0-dev":
        return bool(latest)
    return _version_parts(latest) > _version_parts(current)


def check_for_update(
    current: str,
    timeout: float = 3.0,
    api_url: str = TAGS_API_URL,
) -> UpdateResult:
    """Query GitHub's latest tag.

    ``timeout`` is intentionally bounded: update checking is advisory and
    must not delay a CLI invocation or hold up the GUI.
    """
    checked_at = time.time()
    request = Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, list) or not payload:
            raise ValueError("GitHub tags response was empty")
        latest = str(payload[0].get("name") or "").strip()
        release_url = f"https://github.com/{REPOSITORY}/releases/tag/{latest}"
        if not latest:
            raise ValueError("GitHub tags response did not contain a tag name")
        return UpdateResult(
            current=current,
            latest=latest,
            release_url=release_url,
            update_available=is_newer(latest, current),
            checked_at=checked_at,
        )
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return UpdateResult(current=current, error=str(exc), checked_at=checked_at)


def _find_checkout() -> Path | None:
    """Locate the ATWA-NG git checkout this module was imported from.

    ``git pull`` and ``pip install -e .`` must run THERE, never in the
    process CWD: launched from any other directory, the old code pulled
    whatever unrelated repo the user happened to be sitting in and then
    installed *that* project into the environment. Walks up from this file
    (editable ``src/`` layout: src/atwa/update_check.py -> repo root) and
    only accepts a directory that is a git repo *and* carries this
    project's pyproject.toml.
    """
    for parent in Path(__file__).resolve().parents:
        if (parent / ".git").exists() and (parent / "pyproject.toml").exists():
            try:
                if 'name = "atwa"' in (parent / "pyproject.toml").read_text():
                    return parent
            except OSError:
                continue
    return None


def _venv_python(checkout: Path) -> Path | None:
    """Return the venv interpreter inside ``checkout`` if present."""
    candidates = (
        checkout / ".venv" / "bin" / "python",
        checkout / ".venv" / "Scripts" / "python.exe",
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def _base_python() -> str:
    """Pick a usable base interpreter for creating a venv."""
    for name in ("python3", "python"):
        found = shutil.which(name)
        if found:
            return found
    return sys.executable


def _run(cmd: list[str], cwd: Path, timeout: float) -> tuple[int, str, str]:
    """subprocess.run wrapper that never raises."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            cwd=str(cwd),
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except OSError as exc:
        return 1, "", str(exc)


def _ensure_venv(checkout: Path, timeout: float) -> tuple[Path | None, str]:
    """Ensure a usable venv exists in ``checkout``, creating it if needed.

    Returns ``(python_path, message)``. ``python_path`` is ``None`` on
    failure. A freshly created venv gets the project + its dependencies
    installed; an existing venv is repaired (deps installed) only if it
    cannot already import ``atwa``.
    """
    existing = _venv_python(checkout)
    if existing is not None:
        # Verify it can import atwa; repair deps if not.
        rc, _out, _err = _run([str(existing), "-c", "import atwa"], checkout, timeout)
        if rc != 0:
            rc2, _out2, err2 = _run(
                [str(existing), "-m", "pip", "install", "-e", "."],
                checkout,
                timeout,
            )
            if rc2 != 0:
                return None, f"existing venv cannot import atwa and repair failed: {err2.strip()}"
        return existing, "existing venv"

    # Create a fresh venv.
    venv_dir = checkout / ".venv"
    base = _base_python()
    rc, _out, err = _run([base, "-m", "venv", str(venv_dir)], checkout, timeout)
    if rc != 0:
        return None, f"could not create venv: {err.strip()}"

    py = _venv_python(checkout)
    if py is None:
        return None, "venv created but interpreter not found"

    # Install project + dependencies into the fresh venv.
    rc, _out, err = _run([str(py), "-m", "pip", "install", "-e", "."], checkout, timeout)
    if rc != 0:
        return None, f"venv created but dependency install failed: {err.strip()}"

    return py, "created venv and installed dependencies"


RELEASES_API_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"


def _fetch_latest_release(timeout: float = 30.0) -> dict | None:
    """Fetch the latest published GitHub release and its assets.

    Returns a dict with keys ``tag``, ``wheel_url``, ``wheel_name`` and
    ``checksum_url`` (the latter may be ``None``), or ``None`` on any
    failure. Used by the release-based update path for packaged installs.
    """
    request = Request(
        RELEASES_API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    tag = str(payload.get("tag_name") or "").strip()
    assets = payload.get("assets")
    if not isinstance(assets, list):
        assets = []
    wheel_url = None
    wheel_name = None
    checksum_url = None
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "")
        if name.endswith(".whl") and wheel_url is None:
            wheel_url = str(asset.get("browser_download_url") or "")
            wheel_name = name
        elif name.endswith((".sha256", ".sha256sum", ".checksum")) and checksum_url is None:
            checksum_url = str(asset.get("browser_download_url") or "")
    return {
        "tag": tag,
        "wheel_url": wheel_url or None,
        "wheel_name": wheel_name,
        "checksum_url": checksum_url,
    }


def _download_file(url: str, dest: Path, timeout: float) -> bool:
    """Download ``url`` to ``dest``. Returns True on success."""
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout) as response:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("wb") as fh:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    fh.write(chunk)
        return dest.is_file() and dest.stat().st_size > 0
    except (HTTPError, URLError, TimeoutError, OSError):
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def _expected_sha256(checksum_url: str, timeout: float) -> str | None:
    """Fetch a checksum file and return the expected hex digest, or None."""
    request = Request(checksum_url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError):
        return None
    for token in text.split():
        token = token.strip().lower()
        if len(token) == 64 and all(c in "0123456789abcdef" for c in token):
            return token
    return None


def _verify_sha256(path: Path, expected: str) -> bool:
    import hashlib

    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return False
    return h.hexdigest().lower() == expected.lower()


def apply_update(timeout: float = 120.0) -> tuple[bool, str]:
    """Update ATWA-NG to the latest release.

    Two paths:

    * Editable/developer install (a git checkout next to the package):
      ``git pull`` + reinstall into the project venv.
    * Packaged install (wheel/pip/binary): download the latest release
      wheel from GitHub Releases, verify its SHA-256 when published, and
      install it into the running interpreter's environment.

    Returns (success, message). Never raises -- update failures are
    reported to the caller, not raised past it.
    """
    checkout = _find_checkout()
    if checkout is None:
        # Packaged install (wheel/pip/binary): no git checkout available.
        # Fall back to downloading the latest release from GitHub.
        try:
            from .. import __version__ as _current_version
        except Exception:  # noqa: BLE001
            _current_version = "0.0.0-dev"

        release = _fetch_latest_release(timeout)
        if release is None:
            return False, ("ATWA-NG source checkout not found and the latest release "
                           "could not be fetched from GitHub; update manually")
        tag = release["tag"]
        if not tag:
            return False, "latest GitHub release has no tag name"
        if not is_newer(tag, _current_version):
            return True, f"already up to date ({_current_version})"

        if not release.get("wheel_url"):
            return False, (f"release {tag} has no wheel asset to install; "
                           f"update manually from {release.get('tag') and 'https://github.com/' + REPOSITORY + '/releases/tag/' + tag}")

        # Download the wheel.
        import tempfile

        tmp_dir = Path(tempfile.mkdtemp(prefix="atwa-update-"))
        wheel_path = tmp_dir / (release["wheel_name"] or f"atwa-{tag}.whl")
        if not _download_file(release["wheel_url"], wheel_path, timeout):
            return False, f"failed to download release {tag} wheel"

        # Verify checksum when a checksum asset is published.
        expected = None
        if release.get("checksum_url"):
            expected = _expected_sha256(release["checksum_url"], timeout)
        if expected is not None and not _verify_sha256(wheel_path, expected):
            try:
                wheel_path.unlink(missing_ok=True)
            except OSError:
                pass
            return False, f"release {tag} wheel failed SHA-256 verification"

        # Install into the running interpreter's environment.
        rc, _out, err = _run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "--no-deps", str(wheel_path)],
            tmp_dir,
            timeout,
        )
        if rc == 124:
            return False, f"downloaded {tag} but pip install timed out after {timeout}s"
        if rc != 0:
            return False, f"downloaded {tag} but pip install failed: {err.strip()}"
        note = "" if expected is not None else " (no checksum published; not verified)"
        return True, f"updated to {tag}{note}; restart ATWA-NG to use the new version"

    # Resolve the branch explicitly: a clone without upstream tracking
    # (common after a fresh clone or a detached HEAD) makes a bare
    # `git pull` fail with "no tracking information". Pinning origin/<branch>
    # avoids that and also repairs the tracking config for next time.
    rc, branch_out, branch_err = _run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"], checkout, timeout
    )
    # _run returns rc from subprocess; but branch determination failure
    # handling: treat non-zero as undetermined.
    if rc != 0:
        return False, f"could not determine current branch: {branch_err.strip() or branch_out.strip()}"
    branch = (branch_out or "").strip()
    if not branch or branch == "HEAD":
        branch = "main"

    rc, pull_stdout, pull_stderr = _run(
        ["git", "pull", "origin", branch], checkout, timeout
    )
    if rc == 124:
        return False, f"git pull timed out after {timeout}s"
    if rc != 0:
        return False, f"git pull failed: {pull_stderr.strip()}"
    pull_msg = pull_stdout.strip() or "already up to date"

    # Repair upstream tracking so future bare `git pull`s work too.
    _run(
        ["git", "branch", "--set-upstream-to", f"origin/{branch}", branch],
        checkout,
        timeout,
    )

    # Resolve (or create) the venv interpreter to reinstall into.
    py, venv_msg = _ensure_venv(checkout, timeout)
    if py is None:
        py = Path(sys.executable)
        venv_msg = f"venv unavailable ({venv_msg}); falling back to {py}"

    # Re-install so the installed package metadata refreshes.
    rc, _out, err = _run(
        [str(py), "-m", "pip", "install", "--no-deps", "-e", "."],
        checkout,
        timeout,
    )
    if rc == 124:
        return False, f"pull succeeded ({pull_msg}) but pip reinstall timed out after {timeout}s"
    if rc != 0:
        return False, f"pull succeeded ({pull_msg}) but pip reinstall failed: {err.strip()}"
    return True, f"{pull_msg}; reinstalled via {venv_msg} ({py})"
