"""Lightweight GitHub release update checks for ATWA-NG.

The check is deliberately small and dependency-free: it uses only Python's
standard library, has a short timeout, and never runs on the Tk or radio hot
path. A published GitHub release is the release signal; tags alone are not
queried because they do not carry a user-facing release URL or publication
state. The repository workflow is therefore: bump pyproject.toml, commit,
push, create/publish a GitHub release, and tag the release.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPOSITORY = "KiMiGuel/ATWA-NG"
RELEASES_API_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
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


def _version_parts(value: str) -> tuple[tuple[int, int | str], ...]:
    """Parse a release version for comparison without external dependencies.

    Numeric components compare numerically; a pre-release suffix sorts before
    the corresponding final release. Unknown suffixes are retained as strings
    so malformed-but-readable GitHub tags do not crash the checker.

    The returned keys are deliberately heterogeneous -- every component is a
    ``(marker, value)`` pair whose *marker* is an int, and comparison is
    expected to resolve on the marker before it ever reaches the value. That
    invariant is what makes the comparison total across the mixed int/str
    shapes, so the unparseable-tag fallback below must keep its second
    component's marker strictly below every well-formed version's first
    marker (0), otherwise two different tag shapes can end up comparing an
    ``int`` against a ``str`` and raise TypeError mid-check. 2026-09-25: the
    old fallback returned a bare ``((tag,),)`` string, so any non-numeric tag
    ("release-candidate", a stray "latest") raised TypeError against every
    normal version and took the whole update check down with it.
    """
    cleaned = value.strip().lstrip("vV")
    match = re.match(r"^([0-9]+(?:\.[0-9]+)*)(.*)$", cleaned)
    if not match:
        # Sorts below every parseable version (marker -1 < 0), so an
        # unreadable GitHub tag can never masquerade as a newer release.
        # Marker -1 also means the string component is only ever compared
        # against another unparseable tag, i.e. str-vs-str -- never str-vs-int.
        return ((0, 0), (-1, 0), (0, cleaned))
    numbers = tuple(int(part) for part in match.group(1).split("."))
    suffix = match.group(2).lstrip("-+").lower()
    if not suffix:
        parts = [(number, 0) for number in numbers]
        # GitHub's historical tags include both ``v2.4`` and ``v2.4.0``.
        # Treat omitted trailing zeroes as the same release version.
        while len(parts) > 1 and parts[-1] == (0, 0):
            parts.pop()
        return tuple(parts) + ((1, 0),)
    # The pre-release suffix is a (str, int) pair by design: the int marker
    # makes it sort before the (1, 0) final-release terminator, and the str
    # value orders 'alpha' < 'beta' < 'rc1' within the same marker. The
    # annotation above cannot express that mixed shape, so it is asserted
    # here rather than loosened to `tuple[tuple[int | str, int], ...]`,
    # which would stop describing the numeric and terminator components.
    return cast(
        tuple[tuple[int, int | str], ...],
        tuple((number, 0) for number in numbers) + ((0, 0), (suffix, 0)),
    )


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
    api_url: str = RELEASES_API_URL,
) -> UpdateResult:
    """Query GitHub's latest published release.

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
        latest = str(payload.get("tag_name") or "").strip()
        release_url = str(payload.get("html_url") or "").strip() or None
        if not latest:
            raise ValueError("GitHub release response did not contain tag_name")
        return UpdateResult(
            current=current,
            latest=latest,
            release_url=release_url,
            update_available=is_newer(latest, current),
            checked_at=checked_at,
        )
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return UpdateResult(current=current, error=str(exc), checked_at=checked_at)
