"""Bounded, per-target capture housekeeping.

Capture directories are organized by target (``<essid>_<BSSID>``).  The old
cleanup path merged each target into a second output, then merged every
target into ``master.pcap``/``master.22000``.  That final merge is unsafe for
cracking: one file can contain several APs, while aircrack-ng requires one
BSSID.  It is also the source of the old ``master.*`` naming discrepancy.

Housekeeping now has one responsibility: consolidate files *within a target*,
keep the output beside that target's other files, and include the BSSID in
its filename.  It never creates a multi-target crackable capture.  Originals
are removed only after the replacement has been written successfully.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .crack.convert import MergeUnavailableError, merge_22000_files, merge_captures
from .storage import bssid_from_path, capture_root, unique_path

# Top-level output directories produced by other capture actions.  They are
# archives/tools output, not target folders, and are never recursively folded
# into another target by cleanup.
_KIND_DIRS = {"fixed", "merged", "master", "hashcat", "scan", "pcapng", "reconstructed"}

_CAP_SUFFIXES = {".cap", ".pcap", ".pcapng"}


@dataclass
class TargetPlan:
    target_dir: str
    bssid: str | None = None
    cap_files: list[str] = field(default_factory=list)
    hash_files: list[str] = field(default_factory=list)


@dataclass
class CleanupReport:
    dry_run: bool
    targets: list[TargetPlan] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    removed_dirs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"{'[DRY RUN] ' if self.dry_run else ''}Cleanup report"]
        lines.append(f"  {len(self.targets)} target folder(s) with capture material")
        if self.outputs:
            lines.append(f"  per-target outputs: {len(self.outputs)}")
        if not self.dry_run:
            lines.append(
                f"  deleted {len(self.deleted)} original file(s), "
                f"removed {len(self.removed_dirs)} empty folder(s)"
            )
        if self.errors:
            lines.append(f"  {len(self.errors)} error(s):")
            lines.extend(f"    - {e}" for e in self.errors)
        return "\n".join(lines)


def _plan_targets(root: str | Path | None = None) -> list[TargetPlan]:
    root = Path(root) if root is not None else capture_root()
    plans = []
    for d in sorted(root.iterdir()):
        if not d.is_dir() or d.name in _KIND_DIRS:
            continue
        caps = []
        hashes = []
        for p in d.rglob("*"):
            if not p.is_file():
                continue
            suffix = p.suffix.lower()
            if suffix in _CAP_SUFFIXES:
                caps.append(str(p))
            elif suffix == ".22000":
                hashes.append(str(p))
        caps.sort()
        hashes.sort()
        if caps or hashes:
            plans.append(
                TargetPlan(
                    target_dir=str(d),
                    bssid=bssid_from_path(d),
                    cap_files=caps,
                    hash_files=hashes,
                )
            )
    return plans


def _target_filename(prefix: str, bssid: str | None, suffix: str) -> str:
    label = bssid.replace(":", "-") if bssid else "unknown-bssid"
    return f"{prefix}_{label}{suffix}"


def cleanup_handshakes(dry_run: bool = True, root: str | Path | None = None) -> CleanupReport:
    """Merge files within each target, never across targets.

    ``dry_run=True`` (the default) only builds and returns the plan.  With
    ``dry_run=False``, each target with two or more captures is merged beside
    its originals; each target with two or more 22000 files gets a
    deduplicated per-target hash file.  A single file is left alone because
    there is nothing to consolidate.
    """
    targets = _plan_targets(root)
    report = CleanupReport(dry_run=dry_run, targets=targets)
    if not targets or dry_run:
        return report

    for t in targets:
        target_dir = Path(t.target_dir)
        try:
            if len(t.cap_files) >= 2:
                suffix = Path(t.cap_files[0]).suffix
                output = merge_captures(
                    t.cap_files,
                    output_dir=target_dir,
                    output_name=_target_filename("capture", t.bssid, f".merged{suffix}"),
                )
                report.outputs.append(output)
                for f in t.cap_files:
                    Path(f).unlink()
                    report.deleted.append(f)

            if len(t.hash_files) >= 2:
                lines = [
                    line for line in merge_22000_files(t.hash_files)
                    if line.startswith(("WPA*01*", "WPA*02*"))
                ]
                if not lines:
                    raise RuntimeError("no usable WPA*01*/WPA*02* lines in hash files")
                out = unique_path(target_dir / _target_filename("hash", t.bssid, ".22000"))
                out.write_text("\n".join(lines) + "\n")
                report.outputs.append(str(out))
                for f in t.hash_files:
                    Path(f).unlink()
                    report.deleted.append(f)
        except (MergeUnavailableError, RuntimeError, OSError) as exc:
            report.errors.append(f"{t.target_dir}: {exc}")

    # Remove only folders that became empty.  A per-target merged output is
    # intentionally kept, so its target remains a crackable unit.
    for t in targets:
        d = Path(t.target_dir)
        try:
            if d.is_dir() and not any(d.rglob("*")):
                d.rmdir()
                report.removed_dirs.append(str(d))
        except OSError as exc:
            report.errors.append(f"{d}: could not remove empty folder ({exc})")

    return report
