from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

try:
    __version__ = version("atwa")
except PackageNotFoundError:  # not installed (e.g. running straight from source) -- best-effort fallback
    __version__ = "0.0.0-dev"


def _source_checkout_version() -> str | None:
    """When running from a source checkout, read the version from pyproject.toml.

    Installed metadata (especially an older editable install or a non-venv
    launch) can lag behind the tree actually on disk. Preferring the
    checkout's declared version keeps ``--version``, the update check and
    the GUI title honest without requiring a reinstall first.
    """
    for parent in Path(__file__).resolve().parents:
        pyproject = parent / "pyproject.toml"
        if not pyproject.is_file():
            continue
        try:
            text = pyproject.read_text(encoding="utf-8")
        except OSError:
            continue
        if 'name = "atwa"' not in text and "name = 'atwa'" not in text:
            continue
        match = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
        if match:
            return match.group(1)
    return None


_source_version = _source_checkout_version()
if _source_version:
    __version__ = _source_version