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
         With --config it also checks the three artifacts the archive cannot
         restore: that the config is the one the restored records were written
         under, and the pseudonym identity map and HMAC key it names. A drill
         that restores evidence but cannot resolve a pseudonym, or that pairs
         it with a config nobody was running, has proved half of the recovery.

Nothing here touches the live evidence directory: the work directory is the only
thing written, and a work directory that already holds files is refused rather
than merged, because a restore that silently keeps a stale segment is the exact
failure the drill exists to catch.

Usage:
  uv run python tools/restore_drill.py --archive <archive-dir> --work <empty-dir>
  uv run python tools/restore_drill.py --archive <d> --work <d> --config <config.json>
  uv run python tools/restore_drill.py --self-test
  make drill-restore ARCHIVE=/path/to/archive WORK=/path/to/scratch

Exit codes: 0 the archive restored and reads back, 1 the drill found a problem,
2 usage error. The one-line verdict goes to stdout and the per-issue detail to
stderr, whether or not the run found something, so a redirected run records the
verdict and never mixes it with its diagnostics.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import io
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
# The instant the self-tests export at, matching the archive stamp they name. The
# export reads the wall clock to decide what a dead run's staging directory is,
# so a self-test that left that to the host read the clock on every run and
# could not be replayed from a pin.
SELF_TEST_NOW = dt.datetime(2026, 7, 21, 0, 0, tzinfo=dt.UTC)

# A run that never started work: an unknown flag, a bare run, or an argument the
# tool refuses before it touches the archive. An archive that does not exist or
# does not verify is a drill failure (1), not a usage error.
USAGE_ERROR = 2


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


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
    members = ee.archive_members(archive, index_name)
    if not members:
        return [f"{archive}: archive holds no {ee.SEGMENT_GLOB} segments to restore"]
    work.mkdir(parents=True, exist_ok=True)
    for member in members:
        shutil.copy2(member, work / member.name)
        if ee.file_digest(member) != ee.file_digest(work / member.name):
            return [f"{member.name}: restored copy does not match the archive"]
    return [f"chain: {e}" for e in ec.verify_dir(work, index_name)]


def readback(work: pathlib.Path, expected_index: str) -> tuple[list[str], str, set[str]]:
    """The restored chain walked end to end, and a one-line description of what
    came out. A chain that verifies but yields no readable record is not a
    restore, so the first and last records are parsed and reported by eventId.

    The `configHash` values carried by the records come back with it: they say
    which config the restored stream was written under, which is the only
    evidence of that the archive holds."""
    errs: list[str] = []
    first: Record | None = None
    last: Record | None = None
    count = 0
    hashes: set[str] = set()
    segments = sorted(work.glob(ee.SEGMENT_GLOB), key=ec.segment_sort_key)
    for segment in segments:
        for _line_no, record, _raw in ec.iter_records(segment):
            if first is None:
                first = record
            last = record
            count += 1
            carried = record.get("configHash")
            if isinstance(carried, str) and carried:
                hashes.add(carried)
    if count == 0 or first is None or last is None:
        return [f"{work}: restored chain holds no readable records"], "", hashes
    summary = (
        f"{count} record(s) across {len(segments)} segment(s); "
        f"oldest {first.get('type')}/{first.get('eventId')}, "
        f"newest {last.get('type')}/{last.get('eventId')}"
    )
    if expected_index and not (work / expected_index).is_file():
        errs.append(f"{expected_index}: restored without the segment index the archive held")
    return errs, summary, hashes


def config_match_errors(config: Record, hashes: set[str], config_path: pathlib.Path) -> list[str]:
    """Is the config being restored the one the restored records were written under.

    The archive restores the records; it does not restore the config that
    decided what those records mean. Every record carries the `configHash` the
    effective config had when it was written (SCHEMAS.md -> Config schema), and
    the deployed file hashes to the same value, so a config that matches is
    proven and one that does not is a pairing nobody ran: restored findings
    would be read against thresholds, modes, and an `evidence.dir` that were
    never in force.

    Several distinct hashes are not a failure. An operator who retunes a
    threshold writes records under two configs in one archive, and each record
    carries the config that wrote it, so the drill passes on the one that wrote
    them. A config matching none of them is the failure.
    """
    if not hashes:
        return [
            f"{config_path}: no restored record carries a configHash, so the config "
            "the archive was written under cannot be confirmed"
        ]
    schema = json.loads(cc.SCHEMA_PATH.read_text(encoding="utf-8"))
    digest = cc.config_hash(cc.effective_config(config, schema))
    if digest in hashes:
        return []
    return [
        f"{config_path}: hashes to {digest[:12]}, which no restored record was written "
        f"under (the archive holds {', '.join(sorted(h[:12] for h in hashes))}); "
        "these are not the config that produced this evidence"
    ]


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
    chain_errs, summary, hashes = readback(
        work, archived_index if isinstance(archived_index, str) else ""
    )
    errs += chain_errs
    if config_path is not None:
        loaded, load_error = cc.load(config_path)
        if loaded is None:
            errs.append(f"{config_path}: {load_error or 'unreadable'}")
        else:
            errs += config_match_errors(loaded, hashes, config_path)
            root = request.runtime_root or config_path.resolve().parent
            errs += secrets_errors(loaded, root, request.max_age_hours, request.now or _now())
    elif summary:
        # The summary is what a drill record is written from, so an unrun
        # cross-check says so there rather than leaving the record to imply one.
        summary += "; config not supplied, so the config, identity map, and HMAC key went unchecked"
    return errs, summary


def _report(label: str, errors: list[str], summary: str) -> int:
    """The one-line verdict on stdout and the per-issue detail on stderr, whether
    or not the run found something (tools/README.md), so a redirected run records
    the verdict and leaves the diagnostics on the terminal. `label` is the verdict
    line, already carrying the issue count."""
    print(label)
    for error in errors:
        print("  " + error, file=sys.stderr)
    if summary and not errors:
        print(f"  {summary}")
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
        export_errs = ee.export(
            source, archives, ec.DEFAULT_INDEX, stamp="20260721T000000Z", now=SELF_TEST_NOW
        )
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
        if export_errs := ee.export(
            source, archives, ec.DEFAULT_INDEX, stamp="20260721T000000Z", now=SELF_TEST_NOW
        ):
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
        if export_errs := ee.export(
            source, archives, ec.DEFAULT_INDEX, stamp="20260721T000000Z", now=SELF_TEST_NOW
        ):
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

        not_a_dir = scratch / "work-is-a-file"
        not_a_dir.write_text("not a directory\n", encoding="utf-8")
        if not drill(DrillRequest(archive=archive, work=not_a_dir))[0]:
            errs.append("self-test: a work path that is a file reported success")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def _self_test_config() -> list[str]:
    """`--config` is the half of the drill an archive cannot carry, and the whole
    path from flag to finding is only exercised here.

    `secrets_errors` covers the missing and stale cases against a config it is
    handed, but the operator runs `drill`: the config has to load, its relative
    paths have to resolve against the runtime root rather than the process's
    working directory, and a missing key has to fail the drill rather than ride
    along as a note beside a successful restore. The keys live in a directory
    that is not where the config is, so a resolution against the config's own
    parent reports them missing and the clean case below stops being clean.
    """
    errs: list[str] = []
    scratch = ec.SCRATCH / "restore-drill-self-test-config"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        source = scratch / "source"
        archives = scratch / "archives"
        deployed: Record = {
            "schemaVersion": 1,
            "identityMap": {"path": "identity-map.json"},
            "hmacKey": {"path": "keys/hmac.key"},
        }
        # The stream is written under this config's hash, so the drill's config
        # cross-check passes and the findings below are about the keys, which is
        # what this case is about.
        _write_stream_under(source, _config_digest(deployed))
        if export_errs := ee.export(source, archives, ec.DEFAULT_INDEX, stamp="20260721T000000Z"):
            return [f"self-test: could not build an archive: {export_errs}"]
        archive = next(p for p in sorted(archives.iterdir()) if p.is_dir())

        config_dir = scratch / "config"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "server-guard.json"
        config_path.write_text(json.dumps(deployed), encoding="utf-8")
        runtime = scratch / "runtime"
        (runtime / "keys").mkdir(parents=True)

        # Neither key is in the runtime root yet: a clean restore must not read as
        # a clean drill, and both sections have to be named.
        request = DrillRequest(
            archive=archive,
            work=scratch / "work-missing",
            config_path=config_path,
            runtime_root=runtime,
        )
        found = drill(request)[0]
        errs += [
            f"self-test: a drill with --config did not report {section}: {found}"
            for section in ("identityMap", "hmacKey")
            if not any(section in e for e in found)
        ]

        (runtime / "identity-map.json").write_text("{}\n", encoding="utf-8")
        (runtime / "keys" / "hmac.key").write_text("k\n", encoding="utf-8")
        if found := drill(
            DrillRequest(
                archive=archive,
                work=scratch / "work-present",
                config_path=config_path,
                runtime_root=runtime,
            )
        )[0]:
            errs.append(f"self-test: a drill with both keys present reported {found}")

        # A config the loader cannot read is named, not raised out of the drill.
        broken = scratch / "broken.json"
        broken.write_bytes(b'{"schemaVersion": 1, "level": "caf\xe9"}\n')
        if not any(
            "broken.json" in e
            for e in drill(
                DrillRequest(archive=archive, work=scratch / "work-broken", config_path=broken)
            )[0]
        ):
            errs.append("self-test: a drill with an unreadable config reported success")
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


def _main_contract_self_test() -> list[str]:
    """Pin the exit codes and stream split documented in tools/README.md.

    A scheduled drill branches on these: 0 restored, 1 the drill found a problem
    (an archive that does not exist included), 2 for a usage error, which writes
    its help or its message to stderr and leaves stdout empty so a redirected run
    cannot capture a help dump where a verdict belongs.
    """
    cases: list[tuple[str, list[str], int]] = [
        ("bare run", [], USAGE_ERROR),
        ("--archive without --work", ["--archive", "/nonexistent"], USAGE_ERROR),
        (
            "--key-max-age-hours out of range",
            ["--archive", "/a", "--work", "/b", "--key-max-age-hours", "0"],
            USAGE_ERROR,
        ),
        ("missing archive", ["--archive", "/nonexistent", "--work", "/nonexistent"], 1),
    ]
    errs: list[str] = []
    saved = sys.argv
    for label, argv, expected in cases:
        out, err = io.StringIO(), io.StringIO()
        sys.argv = ["restore_drill.py", *argv]
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main()
        except SystemExit as exc:  # argparse rejects a bad argument by exiting
            code = int(exc.code or 0)
        finally:
            sys.argv = saved
        if code != expected:
            errs.append(f"{label}: exit {code}, expected {expected}")
        if expected != USAGE_ERROR:
            if not out.getvalue():
                errs.append(f"{label}: a verdict run wrote nothing to stdout")
            continue
        if out.getvalue():
            errs.append(f"{label}: usage error wrote to stdout: {out.getvalue()!r}")
        if not err.getvalue():
            errs.append(f"{label}: usage error wrote nothing to stderr")
    return errs


def _write_stream_under(source: pathlib.Path, config_hash: str | None) -> None:
    """Two chained segments whose records carry `config_hash`, the way the writer
    stamps every record (SCHEMAS.md -> Evidence stream). `None` writes the records
    without the field, which no shipped record type does."""
    source.mkdir(parents=True, exist_ok=True)
    prev = ec.GENESIS
    for i, kind in enumerate(["health", "finding"]):
        record: Record = {
            "schemaVersion": 1,
            "type": kind,
            "eventId": f"0000000{i}-0000-4000-8000-00000000000{i}",
            "chainPrev": prev,
        }
        if config_hash is not None:
            record["configHash"] = config_hash
        prev = ec.record_hash(record)
        (source / f"evidence-2026-07-2{i + 1}-000000.jsonl").write_text(
            ec.canonical(record) + "\n", encoding="utf-8"
        )


def _config_digest(config: Record) -> str:
    schema = json.loads(cc.SCHEMA_PATH.read_text(encoding="utf-8"))
    return cc.config_hash(cc.effective_config(config, schema))


def _self_test_config_match() -> list[str]:
    """The config a drill is handed is the one the restored records were written
    under, and two ways of it not being are both reported: a config that hashes
    to something the archive never saw, and records carrying no hash to check."""
    errs: list[str] = []
    scratch = ec.SCRATCH / "restore-drill-self-test-config"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        source = scratch / "source"
        archives = scratch / "archives"
        scratch.mkdir(parents=True, exist_ok=True)
        deployed: Record = {
            "schemaVersion": 1,
            "evidence": {"retentionDays": 45},
            "identityMap": {"path": "identity-map.json"},
            "hmacKey": {"path": "hmac.key"},
        }
        config_path = scratch / "server-guard.json"
        config_path.write_text(json.dumps(deployed) + "\n", encoding="utf-8")
        (scratch / "identity-map.json").write_text("{}\n", encoding="utf-8")
        (scratch / "hmac.key").write_text("k\n", encoding="utf-8")

        # A stream written by the deployed config: the drill passes the cross-check.
        _write_stream_under(source, _config_digest(deployed))
        if export_errs := ee.export(source, archives, ec.DEFAULT_INDEX, stamp="20260721T000000Z"):
            return [f"self-test: could not build an archive: {export_errs}"]
        archive = next(p for p in sorted(archives.iterdir()) if p.is_dir())
        found, _summary = drill(
            DrillRequest(archive=archive, work=scratch / "work", config_path=config_path)
        )
        if errs_found := [e for e in found if "configHash" in e or "hashes to" in e]:
            errs.append(
                f"self-test: the config that wrote the evidence was not accepted: {errs_found}"
            )

        # A retuned config: the archive was written under another one, so pairing
        # them restores findings nobody can read against the thresholds in force.
        retuned: Record = {**deployed, "evidence": {"retentionDays": 60}}
        config_path.write_text(json.dumps(retuned) + "\n", encoding="utf-8")
        found, _summary = drill(
            DrillRequest(archive=archive, work=scratch / "work-retuned", config_path=config_path)
        )
        if not any("no restored record was written" in e for e in found):
            errs.append(f"self-test: a config the evidence was not written under passed: {found}")

        # Records that carry no configHash leave the cross-check impossible, which
        # is not a pass either: the drill was asked to confirm the config.
        config_path.write_text(json.dumps(deployed) + "\n", encoding="utf-8")
        bare = scratch / "bare-source"
        _write_stream_under(bare, None)
        bare_archives = scratch / "bare-archives"
        if export_errs := ee.export(
            bare, bare_archives, ec.DEFAULT_INDEX, stamp="20260721T000000Z"
        ):
            return [f"self-test: could not build a hashless archive: {export_errs}"]
        bare_archive = next(p for p in sorted(bare_archives.iterdir()) if p.is_dir())
        found, _summary = drill(
            DrillRequest(archive=bare_archive, work=scratch / "work-bare", config_path=config_path)
        )
        if not any("no restored record carries a configHash" in e for e in found):
            errs.append(f"self-test: a stream with no configHash was not reported: {found}")

        # Without a config the drill still restores, and says the config went unchecked
        # so the drill record does not imply a cross-check that never ran.
        found, summary = drill(DrillRequest(archive=archive, work=scratch / "work-no-config"))
        if found:
            errs.append(f"self-test: a drill without a config reported {found}")
        if "config not supplied" not in summary:
            errs.append(f"self-test: an unrun config cross-check was not stated: {summary!r}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def self_test() -> list[str]:
    errs = _self_test_restore()
    errs += _self_test_without_index()
    errs += _self_test_refusals()
    errs += _self_test_secrets()
    errs += _self_test_config()
    errs += _self_test_config_match()
    errs += _main_contract_self_test()
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--self-test", action="store_true", help="run the drill self-tests and exit")
    mode.add_argument("--archive", type=pathlib.Path, help="archive directory to restore")
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
        help="how old the identity map and HMAC key may be before the drill reports it "
        f"(default: {KEY_MAX_AGE_HOURS:g})",
    )
    args = ap.parse_args()

    if args.self_test:
        errs = self_test()
        return _report(f"restore-drill self-test: {len(errs)} issue(s)", errs, "")

    if not args.archive:
        ap.print_help(sys.stderr)
        return 2
    if not args.work:
        print("usage: --archive requires --work <empty-dir>", file=sys.stderr)
        return 2
    if not 0 < args.key_max_age_hours <= KEY_MAX_AGE_HOURS:
        print(f"--key-max-age-hours must be in (0, {KEY_MAX_AGE_HOURS:.0f}]", file=sys.stderr)
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
    return _report(f"restore drill {args.archive}: {len(errs)} issue(s)", errs, summary)


if __name__ == "__main__":
    sys.exit(main())
