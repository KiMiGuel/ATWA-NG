#!/usr/bin/env python3
"""Sync version/subcommand/test tags across README.md, README_ES.md and
docs/index.html from a single source of truth: pyproject.toml.

Run after bumping the version in pyproject.toml:

    python3 tools/sync_version.py

Counting tests shells out to `pytest --collect-only` and counting
subcommands imports the package's own argparse tree, so run it inside
the project venv from the repo root. Files that are already in sync are
left untouched; whatever changed is printed at the end.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def current_version() -> str:
    data = tomllib.loads((REPO / "pyproject.toml").read_text())
    return str(data["project"]["version"])


def count_tests() -> int:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        capture_output=True, text=True, cwd=REPO, check=False,
    ).stdout
    m = re.search(r"^(\d+) tests? collected", out, re.M)
    if not m:
        sys.exit("sync_version: could not count tests (pytest --collect-only)")
    return int(m.group(1))


def count_subcommands() -> int:
    sys.path.insert(0, str(REPO / "src"))
    from atwa.cli import build_parser  # noqa: PLC0415 -- repo-local, venv required
    subparsers_action = build_parser()._subparsers._group_actions[0]  # noqa: SLF001
    return len(subparsers_action.choices)


def sync_file(path: Path, subs: list[tuple[str, str]]) -> bool:
    text = path.read_text()
    changed = False
    for pattern, repl in subs:
        text, n = re.subn(pattern, repl, text)
        changed = changed or bool(n)
    if changed:
        path.write_text(text)
    return changed


def main() -> int:
    version = current_version()
    tests = count_tests()
    subs = count_subcommands()
    print(f"syncing: version={version} subcommands={subs} tests={tests}")

    jobs = [
        (REPO / "README.md", [
            (r"badge/version-[\d.]+-", f"badge/version-{version}-"),
            (r"badge/subcommands-\d+-", f"badge/subcommands-{subs}-"),
            (r"badge/tests-\d+%20passing", f"badge/tests-{tests}%20passing"),
            (r"alt=\"\d+ tests\"", f"alt=\"{tests} tests\""),
            (r"alt=\"\d+ CLI subcommands\"", f"alt=\"{subs} CLI subcommands\""),
        ]),
        (REPO / "README_ES.md", [
            (r"badge/version-[\d.]+-", f"badge/version-{version}-"),
            (r"badge/subcomandos-\d+-", f"badge/subcomandos-{subs}-"),
            (r"badge/tests-\d+%20passing", f"badge/tests-{tests}%20passing"),
            (r"alt=\"\d+ tests\"", f"alt=\"{tests} tests\""),
            (r"alt=\"\d+ subcomandos CLI\"", f"alt=\"{subs} subcomandos CLI\""),
        ]),
        (REPO / "docs" / "index.html", [
            (r"<span class=\"badge-ver\">v[\d.]+</span>",
             f"<span class=\"badge-ver\">v{version}</span>"),
            (r"Full CLI reference \(\d+ subcommands\)",
             f"Full CLI reference ({subs} subcommands)"),
        ]),
    ]

    touched = []
    for path, subs_list in jobs:
        if sync_file(path, subs_list):
            touched.append(path.relative_to(REPO))

    print("updated: " + (", ".join(map(str, touched)) if touched else "nothing (already in sync)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
