"""Restore an archive into a scratch directory and prove the result reads.

An archive that has never been restored is a hypothesis (docs/OPERATIONS.md ->
Restore drill). Verifying an archive in place proves its bytes; it does not
prove the restore, which is a copy back under the file names the writer
rotated to, followed by a chain walk over the copy and a read of what came out.
This tool performs exactly that, off the live store, so the drill is a command
with an exit code instead of a procedure whose steps are skipped when the month
is short.

  drill  verify the archive against its manifest, copy its segments and index
         into an empty work directory keeping the file names, re-verify the
         chain over the copy, and read the oldest and newest records back out.
         With --config it also checks the two artifacts the archive cannot
         restore: the pseudonym identity map and the HMAC key. A drill that
         restores evidence but cannot resolve a pseudonym has proved half of
         the recovery.

Nothing here touches the live evidence directory: the work directory is the only
thing written, and a work directory that already holds files is refused rather
than merged, because a restore that silently keeps a stale segment is the exact
failure the drill exists to catch.

Usage:
  uv run python tools/restore_drill.py --archive <archive-dir> --work <empty-dir>
  uv run python tools/restore_drill.py --archive <d> --work <d> --config <config.json>
  uv run python tools/restore_drill.py --self-test
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
import config_check as cc
import evidence_check as ec
import evidence_export as ee

Record = dict[str, Any]

# The identity map and HMAC key are copied on the 7-day cycle
# (docs/OPERATIONS.md -> Targets). A drill that finds them older than this is
# reporting the scheduled copy as not run, which is the same failure as a
# missing evidence archive and is only visible if something looks.
KEY_COPY_CYCLE_DAYS = 7
KEY_MAX_AGE_HOURS = 24 * KEY_COPY_CYCLE_DAYS


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _parse_stamp(value: object) -> dt.datetime | None:
    """The archive's own createdUtc, or None when it is absent or malformed."""
    if not isinstance(value, str):
        return None
    try:
        return dt.datetime.strptime(value, ee.STAMP_FORMAT).replace(tzinfo=dt.UTC)
    except ValueError:
        return None


def _manifest(archive: pathlib.Path) -> Record | None:
    path = archive / ee.MANIFEST_NAME
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def work_dir_errors(work: pathlib.Path) -> list[str]:
    """A restore target that is absent, empty, or a non-directory.

    A missing work directory is created and an existing empty one is used as is;
    an existing non-empty one is refused, so a drill can never pass on a mixture
    of restored and leftover files.
    """
    if not work.exists():
        return []
    if not work.is_dir():
        return [f"{work}: work path exists and is not a directory"]
    held = sorted(p.name for p in work.iterdir())
    if held:
        return [f"{work}: not empty ({', '.join(held[:3])}); a restore needs an empty target"]
    return []


def restore(archive: pathlib.Path, work: pathlib.Path, index_name: str) -> list[str]:
    """Copy every archived member into work under its own name, then verify the
    copy. Names are preserved because the cross-segment links are name ordered."""
    errs = work_dir_errors(work)
    if errs:
        return errs
    members = [archive / name for name in sorted(p.name for p in archive.glob(ee.SEGMENT_GLOB))]
    index = archive / index_name
    if index.is_file():
        members.append(index)
    if not members:
        return [f"{archive}: archive holds no {ee.SEGMENT_GLOB} segments to restore"]
    work.mkdir(parents=True, exist_ok=True)
    for member in members:
        shutil.copy2(member, work / member.name)
        if ee.file_digest(member) != ee.file_digest(work / member.name):
            return [f"{member.name}: restored copy does not match the archive"]
    return [f"chain: {e}" for e in ec.verify_dir(work, index_name)]


def readback(work: pathlib.Path, expected_index: str) -> tuple[list[str], str]:
    """The restored chain walked end to end, and a one-line description of what
    came out. A chain that verifies but yields no readable record is not a
    restore, so the first and last records are parsed and reported by eventId."""
    errs: list[str] = []
    first: Record | None = None
    last: Record | None = None
    count = 0
    for segment in sorted(work.glob(ee.SEGMENT_GLOB), key=ec.segment_sort_key):
        for _line_no, record, _raw in ec.iter_records(segment):
            if first is None:
                first = record
            last = record
            count += 1
    if count == 0 or first is None or last is None:
        return [f"{work}: restored chain holds no readable records"], ""
    summary = (
        f"{count} record(s) across {len(list(work.glob(ee.SEGMENT_GLOB)))} segment(s); "
        f"oldest {first.get('type')}/{first.get('eventId')}, "
        f"newest {last.get('type')}/{last.get('eventId')}"
    )
    if expected_index and not (work / expected_index).is_file():
        errs.append(f"{expected_index}: restored without the segment index the archive held")
    return errs, summary


def _resolve(value: object, runtime_root: pathlib.Path) -> pathlib.Path:
    """A configured path, absolute as written and relative to the runtime root.
    The resolved path is named in every finding, so an operator reading a failure
    can see whether the file is missing or merely looked for in the wrong place."""
    candidate = pathlib.Path(str(value))
    return candidate if candidate.is_absolute() else runtime_root / candidate


def secrets_errors(
    config: Record, runtime_root: pathlib.Path, max_age_hours: float, now: dt.datetime
) -> list[str]:
    """The identity map and HMAC key, which no archive contains. A missing one
    is reported as a failure, not a note: without the key a restored chain
    cannot resolve a pseudonym at all, and without the map a key epoch resolves
    to nothing."""
    errs: list[str] = []
    for section in ("identityMap", "hmacKey"):
        block = config.get(section)
        path_value = block.get("path") if isinstance(block, dict) else None
        if not isinstance(path_value, str) or not path_value:
            errs.append(f"config: {section}.path is not set; {section} cannot be restored")
            continue
        path = _resolve(path_value, runtime_root)
        if not path.is_file():
            errs.append(f"{section}: {path} is missing; a restore cannot resolve pseudonyms")
            continue
        size = path.stat().st_size
        if size == 0:
            errs.append(f"{section}: {path} is zero bytes; an empty key is not a key")
            continue
        age_hours = (now.timestamp() - path.stat().st_mtime) / 3600
        if age_hours > max_age_hours:
            errs.append(
                f"{section}: {path} was last written {age_hours:.1f} h ago, past the "
                f"{max_age_hours:.0f} h backup cycle; the scheduled copy has not run"
            )
    return errs


@dataclass(frozen=True)
class DrillRequest:
    """One drill run. `now` and `max_age_hours` are injection points for the
    self-test; a real run leaves them at the cycle default and the wall clock."""

    archive: pathlib.Path
    work: pathlib.Path
    config_path: pathlib.Path | None = None
    runtime_root: pathlib.Path | None = None
    max_age_hours: float = KEY_MAX_AGE_HOURS
    now: dt.datetime | None = None


def drill(request: DrillRequest) -> tuple[list[str], str]:
    """Run the whole drill. Returns (errors, summary); an empty error list means
    the archive restored, the copy verified, records read back, and the two
    non-archiveable artifacts were present."""
    archive, work, config_path = request.archive, request.work, request.config_path
    errs: list[str] = []
    manifest = _manifest(archive)
    if manifest is None:
        return [f"{archive}: no readable {ee.MANIFEST_NAME}"], ""
    errs += ee.verify(archive)
    if errs:
        # A copy of an archive that does not verify would only produce a second
        # copy of the same problem, in a directory the operator might then trust.
        return errs, ""
    # An archive of a store that wrote no index holds none, and restoring it
    # must not fail for a file it never contained. The chain walk still names
    # the default index, which the chain verifier treats as absent.
    archived_index = manifest.get("indexFile")
    index_name = archived_index if isinstance(archived_index, str) else ec.DEFAULT_INDEX
    errs += restore(archive, work, index_name)
    if errs:
        return errs, ""
    chain_errs, summary = readback(work, archived_index if isinstance(archived_index, str) else "")
    errs += chain_errs
    if config_path is not None:
        loaded, load_error = cc.load(config_path)
        if loaded is None:
            errs.append(f"{config_path}: {load_error or 'unreadable'}")
        else:
            root = request.runtime_root or config_path.resolve().parent
            errs += secrets_errors(loaded, root, request.max_age_hours, request.now or _now())
    return errs, summary


def _report(label: str, errors: list[str], summary: str) -> int:
    stream = sys.stdout if not errors else sys.stderr
    print(f"{label}: {len(errors)} issue(s)", file=stream)
    for error in errors:
        print("  " + error, file=stream)
    if summary and not errors:
        print(f"  {summary}", file=stream)
    return 1 if errors else 0


def _self_test_restore() -> list[str]:
    """A good archive restores into an empty directory, and the copy verifies
    and reads back. This is the case the monthly drill exists to prove."""
    errs: list[str] = []
    scratch = ec.SCRATCH / "restore-drill-self-test"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        source = scratch / "source"
        archives = scratch / "archives"
        ee.write_sample_stream(source)
        export_errs = ee.export(source, archives, ec.DEFAULT_INDEX, stamp="20260721T000000Z")
        if export_errs:
            return [f"self-test: could not build an archive: {export_errs}"]
        archive = next(p for p in sorted(archives.iterdir()) if p.is_dir())
        found, summary = drill(DrillRequest(archive=archive, work=scratch / "work"))
        if found:
            errs.append(f"self-test: a valid archive did not restore: {found}")
        if "3 record(s)" not in summary:
            errs.append(f"self-test: readback did not report the restored records: {summary!r}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def _self_test_without_index() -> list[str]:
    """A store that wrote no segment index archives none, and the restore must
    not fail for a file the archive never held."""
    errs: list[str] = []
    scratch = ec.SCRATCH / "restore-drill-self-test-no-index"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        source = scratch / "source"
        archives = scratch / "archives"
        source.mkdir(parents=True, exist_ok=True)
        record: Record = {
            "schemaVersion": 1,
            "type": "health",
            "eventId": "00000000-0000-4000-8000-000000000000",
            "chainPrev": ec.GENESIS,
        }
        (source / "evidence-2026-07-21-000000.jsonl").write_text(
            ec.canonical(record) + "\n", encoding="utf-8"
        )
        if export_errs := ee.export(source, archives, ec.DEFAULT_INDEX, stamp="20260721T000000Z"):
            return [f"self-test: could not build an indexless archive: {export_errs}"]
        archive = next(p for p in sorted(archives.iterdir()) if p.is_dir())
        found, summary = drill(DrillRequest(archive=archive, work=scratch / "work"))
        if found:
            errs.append(f"self-test: an archive with no segment index did not restore: {found}")
        if "1 record(s)" not in summary:
            errs.append(f"self-test: indexless readback reported {summary!r}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def _self_test_refusals() -> list[str]:
    """A drill that cannot fail is not a drill: a non-empty work directory, an
    archive that does not verify, and a missing HMAC key each have to be
    reported rather than passed over."""
    errs: list[str] = []
    scratch = ec.SCRATCH / "restore-drill-self-test-refusals"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        source = scratch / "source"
        archives = scratch / "archives"
        ee.write_sample_stream(source)
        if export_errs := ee.export(source, archives, ec.DEFAULT_INDEX, stamp="20260721T000000Z"):
            return [f"self-test: could not build an archive: {export_errs}"]
        archive = next(p for p in sorted(archives.iterdir()) if p.is_dir())

        occupied = scratch / "occupied"
        occupied.mkdir(parents=True)
        (occupied / "leftover.jsonl").write_text("stale\n", encoding="utf-8")
        if not drill(DrillRequest(archive=archive, work=occupied))[0]:
            errs.append("self-test: a restore over a non-empty directory reported success")

        if not drill(DrillRequest(archive=scratch / "no-such-archive", work=scratch / "absent"))[0]:
            errs.append("self-test: a missing archive reported success")

        # A segment edited in the archive after export: the manifest digest is
        # the first thing that catches it, and the drill must not restore past it.
        tampered = scratch / "tampered"
        shutil.copytree(archive, tampered)
        target = tampered / "evidence-2026-07-22-000000.jsonl"
        target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        if not drill(DrillRequest(archive=tampered, work=scratch / "work-tampered"))[0]:
            errs.append("self-test: an edited archive reported success")
        if (scratch / "work-tampered").exists():
            errs.append("self-test: an unverified archive was copied into the work directory")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def _self_test_secrets() -> list[str]:
    """A config whose key paths do not resolve to files is a drill failure, and a
    present key written inside the cycle is not."""
    errs: list[str] = []
    scratch = ec.SCRATCH / "restore-drill-self-test-secrets"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        scratch.mkdir(parents=True, exist_ok=True)
        config: Record = {
            "identityMap": {"path": "identity-map.json"},
            "hmacKey": {"path": "hmac.key"},
        }
        found = secrets_errors(config, scratch, KEY_MAX_AGE_HOURS, _now())
        errs += [
            f"self-test: a missing {section} was not reported: {found}"
            for section in ("identityMap", "hmacKey")
            if not any(section in e for e in found)
        ]
        (scratch / "identity-map.json").write_text("{}\n", encoding="utf-8")
        (scratch / "hmac.key").write_text("k\n", encoding="utf-8")
        if found := secrets_errors(config, scratch, KEY_MAX_AGE_HOURS, _now()):
            errs.append(f"self-test: a present key and map were reported missing: {found}")
        # An age far past the cycle is a scheduled copy that did not run, which
        # is the same failure as a missing archive and the drill has to name it.
        stale = secrets_errors(
            config, scratch, KEY_MAX_AGE_HOURS, _now() + dt.timedelta(days=KEY_COPY_CYCLE_DAYS * 2)
        )
        if not any("backup cycle" in e for e in stale):
            errs.append(f"self-test: a key past the backup cycle was not reported: {stale}")
        (scratch / "hmac.key").write_text("", encoding="utf-8")
        if not any(
            "zero bytes" in e for e in secrets_errors(config, scratch, KEY_MAX_AGE_HOURS, _now())
        ):
            errs.append("self-test: a zero-byte key was not reported")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def self_test() -> list[str]:
    errs = _self_test_restore()
    errs += _self_test_without_index()
    errs += _self_test_refusals()
    errs += _self_test_secrets()
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true", help="run the drill self-tests and exit")
    ap.add_argument("--archive", type=pathlib.Path, help="archive directory to restore")
    ap.add_argument("--work", type=pathlib.Path, help="empty directory to restore into")
    ap.add_argument("--config", type=pathlib.Path, help="config file naming the key and map paths")
    ap.add_argument(
        "--runtime-root",
        type=pathlib.Path,
        help="root for relative key and map paths (default: the config file's directory)",
    )
    ap.add_argument(
        "--key-max-age-hours",
        type=float,
        default=KEY_MAX_AGE_HOURS,
        help="how old the identity map and HMAC key may be before the drill reports it",
    )
    args = ap.parse_args()

    if args.self_test:
        return _report("restore-drill self-test", self_test(), "")

    if not args.archive:
        ap.print_help()
        return 2
    if not args.work:
        print("usage: --archive requires --work <empty-dir>")
        return 2
    if not 0 < args.key_max_age_hours <= KEY_MAX_AGE_HOURS:
        print(f"--key-max-age-hours must be in (0, {KEY_MAX_AGE_HOURS:.0f}]")
        return 2

    errs, summary = drill(
        DrillRequest(
            archive=args.archive,
            work=args.work,
            config_path=args.config,
            runtime_root=args.runtime_root,
            max_age_hours=args.key_max_age_hours,
        )
    )
    return _report(f"restore drill {args.archive}", errs, summary)


if __name__ == "__main__":
    sys.exit(main())
