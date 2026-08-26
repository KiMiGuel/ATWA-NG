"""Capture-folder housekeeping: merge scattered per-target handshakes down
to one master file, per the user's own two-stage design — per-target
merge first, then merge all targets together — deleting originals only
after their replacement is verified on disk.

capture_root() (~/atwa-hs) accumulates one folder per target seen, each
holding its own raw captures and/or 22000 hash files from every attack
run against it. That's real, fast-growing clutter (~70 target folders in
normal use) with no cleanup path until now.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .crack.convert import MergeUnavailableError, merge_22000_files, merge_captures
from .storage import capture_root, organized_output_path

# Top-level dirs under capture_root() that are outputs of other actions
# (fix/merge/etc.), not per-target capture folders — never treated as a
# target and never touched by cleanup.
_KIND_DIRS = {"fixed", "merged", "master", "hashcat", "scan", "pcapng", "reconstructed"}

_CAP_SUFFIXES = {".cap", ".pcap", ".pcapng"}


@dataclass
class TargetPlan:
    target_dir: str
    cap_files: list[str] = field(default_factory=list)
    hash_files: list[str] = field(default_factory=list)


@dataclass
class CleanupReport:
    dry_run: bool
    targets: list[TargetPlan] = field(default_factory=list)
    master_cap: str | None = None
    master_hash: str | None = None
    deleted: list[str] = field(default_factory=list)
    removed_dirs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"{'[DRY RUN] ' if self.dry_run else ''}Cleanup report"]
        lines.append(f"  {len(self.targets)} target folder(s) with capture material")
        if self.master_cap:
            lines.append(f"  master capture: {self.master_cap}")
        if self.master_hash:
            lines.append(f"  master hashes:  {self.master_hash}")
        if not self.dry_run:
            lines.append(f"  deleted {len(self.deleted)} original file(s), removed {len(self.removed_dirs)} empty folder(s)")
        if self.errors:
            lines.append(f"  {len(self.errors)} error(s):")
            lines.extend(f"    - {e}" for e in self.errors)
        return "\n".join(lines)


def _plan_targets() -> list[TargetPlan]:
    root = capture_root()
    plans = []
    for d in sorted(root.iterdir()):
        if not d.is_dir() or d.name in _KIND_DIRS:
            continue
        caps = sorted(str(p) for p in d.rglob("*") if p.is_file() and p.suffix.lower() in _CAP_SUFFIXES)
        hashes = sorted(str(p) for p in d.rglob("*.22000"))
        if caps or hashes:
            plans.append(TargetPlan(target_dir=str(d), cap_files=caps, hash_files=hashes))
    return plans


def cleanup_handshakes(dry_run: bool = True) -> CleanupReport:
    """Two-stage merge (per-target, then all-targets) + delete originals.

    dry_run=True (default) only builds and returns the plan — nothing on
    disk is touched. Call with dry_run=False to actually merge and delete.
    """
    targets = _plan_targets()
    report = CleanupReport(dry_run=dry_run, targets=targets)
    if not targets:
        return report

    if dry_run:
        return report

    master_cap_sources: list[str] = []
    master_hash_sources: list[str] = []

    # Stage 1: per-target merge.
    for t in targets:
        try:
            if len(t.cap_files) >= 2:
                merged = merge_captures(t.cap_files)
                master_cap_sources.append(merged)
                for f in t.cap_files:
                    Path(f).unlink()
                    report.deleted.append(f)
            elif len(t.cap_files) == 1:
                master_cap_sources.append(t.cap_files[0])  # deleted later, once folded into master

            if len(t.hash_files) >= 2:
                lines = merge_22000_files(t.hash_files)
                out = organized_output_path("merged", f"{Path(t.target_dir).name}.22000")
                out.write_text("\n".join(lines) + "\n")
                master_hash_sources.append(str(out))
                for f in t.hash_files:
                    Path(f).unlink()
                    report.deleted.append(f)
            elif len(t.hash_files) == 1:
                master_hash_sources.append(t.hash_files[0])
        except (MergeUnavailableError, RuntimeError, OSError) as exc:
            report.errors.append(f"{t.target_dir}: {exc}")

    # Stage 2: merge every target's contribution into one master file.
    try:
        if len(master_cap_sources) >= 2:
            report.master_cap = merge_captures(master_cap_sources)
            for f in master_cap_sources:
                Path(f).unlink()
                report.deleted.append(f)
        elif len(master_cap_sources) == 1:
            src = Path(master_cap_sources[0])
            dest = organized_output_path("master", f"master{src.suffix}")
            dest.write_bytes(src.read_bytes())
            src.unlink()
            report.deleted.append(str(src))
            report.master_cap = str(dest)
    except (MergeUnavailableError, RuntimeError, OSError) as exc:
        report.errors.append(f"master capture merge: {exc}")

    if len(master_hash_sources) >= 2:
        lines = merge_22000_files(master_hash_sources)
        dest = organized_output_path("master", "master.22000")
        dest.write_text("\n".join(lines) + "\n")
        for f in master_hash_sources:
            Path(f).unlink()
            report.deleted.append(f)
        report.master_hash = str(dest)
    elif len(master_hash_sources) == 1:
        src = Path(master_hash_sources[0])
        dest = organized_output_path("master", "master.22000")
        dest.write_text(src.read_text())
        src.unlink()
        report.deleted.append(str(src))
        report.master_hash = str(dest)

    # Remove now-empty per-target folders.
    for t in targets:
        d = Path(t.target_dir)
        try:
            if d.is_dir() and not any(d.rglob("*")):
                d.rmdir()
                report.removed_dirs.append(str(d))
        except OSError as exc:
            report.errors.append(f"{d}: could not remove empty folder ({exc})")

    return report
