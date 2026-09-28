"""Report whether the archive root still meets its RPO, without changing anything.

A scheduled export that fails, and a scheduler that never runs, look the same
from the inside: the last good archive is simply older than it should be.
Nothing in the repository answered that question, so an operator learned about
a missed backup from needing one. This tool is the read-only check to put on
the same schedule as the export:

  status  verify the archives in an archive root, newest first, and report the
          age of the newest one that verifies against the RPO. A root with no
          archive, an archive that does not verify, and an archive older than
          the window are each reported by name.

It writes nothing and copies nothing: the archives are the only copy of the
evidence, and a status check that could damage them is a second thing to
reason about during an incident. The restore drill
(tools/restore_drill.py) is what proves an archive can be read back; this
only says whether there is a recent one worth drilling.

Usage:
  uv run python tools/backup_status.py --root <archive-root>
  uv run python tools/backup_status.py --root <archive-root> --max-age-hours 24
  uv run python tools/backup_status.py --self-test
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import shutil
import sys
from dataclasses import dataclass
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import evidence_check as ec
import evidence_export as ee

Record = dict[str, Any]

# The evidence RPO (docs/OPERATIONS.md -> Targets): the oldest acceptable age
# of the newest verifying archive. An archive exactly this old is at the limit
# and still counts; past it, the window is open.
DEFAULT_MAX_AGE_HOURS = 24.0
# Archive directories are named evidence-<UTC stamp>; anything else in the root
# is not this tool's business and is left alone rather than guessed at.
ARCHIVE_PREFIX = "evidence-"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def created_utc(archive: pathlib.Path) -> dt.datetime | None:
    """The archive's own creation stamp, read from the manifest whose
    self-digest is checked by the verifier. The directory mtime is a filesystem
    detail that a copy off the server resets, so it is never the age."""
    path = archive / ee.MANIFEST_NAME
    if not path.is_file():
        return None
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    stamp = manifest.get("createdUtc") if isinstance(manifest, dict) else None
    if not isinstance(stamp, str):
        return None
    try:
        return dt.datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.UTC)
    except ValueError:
        return None


def archive_dirs(root: pathlib.Path) -> list[pathlib.Path]:
    if not root.is_dir():
        return []
    return [d for d in root.iterdir() if d.is_dir() and d.name.startswith(ARCHIVE_PREFIX)]


@dataclass(frozen=True)
class BackupStatus:
    """What the newest verifying archive proves, and what is wrong with the rest.

    `failed` names the archives newer than the one that verified: those are the
    runs whose output an operator would otherwise assume is covered, and a
    failure there means the effective RPO is the age of the older archive, not
    the newest one on disk.
    """

    fresh: pathlib.Path | None
    age_hours: float | None
    failed: list[tuple[str, str]]
    undated: list[str]
    total: int


def check(root: pathlib.Path, now: dt.datetime | None = None) -> BackupStatus:
    """Verify newest first and stop at the first archive that verifies. Returns
    the status; it never writes to the root."""
    moment = now or _now()
    found = archive_dirs(root)
    if not found:
        return BackupStatus(None, None, [], [], 0)
    dated: list[tuple[float, pathlib.Path]] = []
    undated: list[str] = []
    for archive in found:
        stamp = created_utc(archive)
        if stamp is None:
            undated.append(archive.name)
            continue
        dated.append(((moment - stamp).total_seconds() / 3600, archive))
    dated.sort(key=lambda pair: pair[0])
    fresh: pathlib.Path | None = None
    age: float | None = None
    failed: list[tuple[str, str]] = []
    for archive_age, archive in dated:
        errs = ee.verify(archive)
        if errs:
            failed.append((archive.name, errs[0]))
            continue
        if fresh is None:
            fresh, age = archive, archive_age
    return BackupStatus(fresh, age, failed, undated, len(found))


def report(
    status: BackupStatus, root: pathlib.Path, max_age_hours: float = DEFAULT_MAX_AGE_HOURS
) -> list[str]:
    """The findings for a status, in the order an operator acts on them."""
    errs: list[str] = []
    if status.total == 0:
        return [f"{root}: no {ARCHIVE_PREFIX}* archive; the RPO window is open in full"]
    if status.undated:
        errs.append(
            f"{', '.join(sorted(status.undated))}: no readable createdUtc in "
            f"{ee.MANIFEST_NAME}; age unknown, so not counted as a backup"
        )
    for name, first in status.failed:
        errs.append(f"{name}: does not verify ({first})")
    if status.fresh is None or status.age_hours is None:
        errs.append(
            f"{root}: none of the {status.total} archive(s) verifies; "
            "the RPO window is open in full"
        )
        return errs
    if status.age_hours > max_age_hours:
        errs.append(
            f"{status.fresh.name}: newest verifying archive is {status.age_hours:.1f} h old, "
            f"past the {max_age_hours:.0f} h RPO; evidence written since it is not backed up"
        )
    return errs


def _self_test() -> list[str]:
    """Pin the three states that matter: a current archive, a stale one, and a
    root whose newest archive is corrupt (the older one is then the real
    backup, and the corruption is reported)."""
    errs: list[str] = []
    scratch = ec.SCRATCH / "backup-status-self-test"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        source = scratch / "source"
        archives = scratch / "archives"
        ee._write_sample_stream(source)
        if export_errs := ee.export(source, archives, ec.DEFAULT_INDEX, stamp="20260721T000000Z"):
            return [f"self-test: could not build an archive: {export_errs}"]
        archive = next(p for p in sorted(archives.iterdir()) if p.is_dir())
        # The export is stamped with a fixed name, so "now" is pinned to the same
        # minute: age is what is under test, not the wall clock.
        now = dt.datetime(2026, 7, 21, 0, 1, tzinfo=dt.UTC)

        fresh = check(archives, now=now)
        if fresh.fresh is None or fresh.fresh != archive:
            errs.append(f"self-test: a current archive was not found: {fresh}")
        if report(fresh, archives):
            errs.append(
                f"self-test: a current archive was reported stale: {report(fresh, archives)}"
            )
        missing = report(check(scratch / "no-such-root", now=now), scratch / "no-such-root")
        if not missing:
            errs.append("self-test: a missing archive root reported no issue")

        stale = check(archives, now=now + dt.timedelta(days=2))
        if not any("past the" in e for e in report(stale, archives)):
            errs.append(f"self-test: a stale archive was not reported: {stale}")

        # Corrupt the newest: the older archive becomes the effective backup and
        # the broken one is named, which is the state a silent rotation leaves.
        target = archive / "evidence-2026-07-22-000000.jsonl"
        target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        broken = check(archives, now=now)
        if not broken.failed:
            errs.append("self-test: a corrupted archive verified clean")
        if not any("does not verify" in e for e in report(broken, archives)):
            errs.append(f"self-test: a corrupted archive was not reported: {broken.failed}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true", help="run the status self-tests and exit")
    ap.add_argument("--root", type=pathlib.Path, help="archive root to inspect")
    ap.add_argument(
        "--max-age-hours",
        type=float,
        default=DEFAULT_MAX_AGE_HOURS,
        help="how old the newest verifying archive may be before the RPO is reported open",
    )
    args = ap.parse_args()

    if args.self_test:
        errs = _self_test()
        print(f"backup-status self-test: {len(errs)} failure(s)")
        for e in errs:
            print("  " + e)
        return 1 if errs else 0

    if args.root is None:
        ap.print_help()
        return 2
    if not 0 < args.max_age_hours <= DEFAULT_MAX_AGE_HOURS:
        print(f"--max-age-hours must be in (0, {DEFAULT_MAX_AGE_HOURS:.0f}]")
        return 2

    status = check(args.root)
    errs = report(status, args.root, args.max_age_hours)
    if status.fresh is not None and status.age_hours is not None and not errs:
        print(
            f"backup status {args.root}: newest verifying archive {status.fresh.name} "
            f"is {status.age_hours:.1f} h old of {status.total} present"
        )
        return 0
    if status.fresh is not None and status.age_hours is not None:
        print(
            f"backup status {args.root}: newest verifying archive {status.fresh.name} "
            f"is {status.age_hours:.1f} h old of {status.total} present",
            file=sys.stderr,
        )
    print(f"{len(errs)} issue(s)", file=sys.stderr)
    for e in errs:
        print("  " + e, file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
