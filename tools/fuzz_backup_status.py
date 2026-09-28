"""Fuzz the backup RPO check (tools/backup_status.py).

The RPO check is a scheduled command with an exit code, and every number it
reaches comes from outside this repo: the `createdUtc` an exporter wrote into
each archive manifest, the manifest JSON around it, the directory names a root
holds, and the `--max-age-hours` a scheduler passes. An archive whose manifest is
truncated, hand-dated, or carries a stamp in a shape strptime does not expect
must leave the window open, never close it by accident, and never abort the run
that is supposed to alert. Nothing fuzzed this tool, so this harness throws
structure-aware mutations at it:

  target 1  created_utc                                 (the manifest's own
                                                        creation stamp, read
                                                        from damaged bytes)
  target 2  check                                       (the whole root walk:
                                                        dated, undated, and
                                                        damaged archives beside
                                                        entries that are not
                                                        archives)
  target 3  gap_errors                                  (the spacing of the
                                                        series, over ages a
                                                        hand-entered stamp or a
                                                        degenerate bound can
                                                        produce)
  target 4  report                                      (the operator-facing
                                                        findings, over a status
                                                        no filesystem produced)

Invariants asserted per iteration:
  - created_utc never raises on any manifest bytes and returns a UTC datetime or
    None; a well-formed stamp parses to the instant it names, and two reads of
    the same bytes agree.
  - check never raises on any root and returns a BackupStatus whose `total` is
    the number of archive directories it found, whose `fresh` and `age_hours`
    are both set or both unset, and whose `series` is newest first.
  - An archive that does not verify is never the `fresh` one, and is named in
    `failed`.
  - gap_errors never raises and returns a list of str; it is deterministic, and a
    series with no gap in it reports nothing.
  - report never raises, returns a list of str, and reports a status with no
    archive at all rather than calling the window closed.
  - Pair assertions across the file boundary: a root holding a current archive
    reports nothing, one holding only a stale archive names the window, a
    damaged manifest becomes `undated` rather than dated, and a gap in the series
    is reported by the spacing alone.

Deterministic (seeded PRNG), stdlib only, no external fuzzer required.

Usage:
  uv run python tools/fuzz_backup_status.py [--iterations N] [--seed S]

Exit codes: 0 every invariant held, 1 an invariant broke, 2 usage error. The
replay of a reported failure is `uv run python tools/fuzz_backup_status.py
--seed <seed>`; the failure and its input go to stderr.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import pathlib
import random
import shutil
import sys
import tempfile
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import backup_status as bs
import evidence_check as ec
import evidence_export as ee
from fuzz_common import InvariantBrokenError, Mutator, add_fuzz_args, fuzz_args

# Manifest JSON, mutated past its declared types on purpose: the shape is what
# the check reads, so the harness cannot narrow it either.
Json = Any

# Temporary archive roots go to the repo's gitignored scratch dir, not the
# system temp dir: /tmp is tmpfs here, so every iteration would be charged to RAM.
SCRATCH = ec.SCRATCH
RUNS = SCRATCH / "fuzz-backup-status"

# The instant every run is evaluated at, so a seed that reproduces a failure
# reproduces it byte for byte. The archives are exported at offsets from it, so
# the ages under test are the ones the harness declares.
HARNESS_NOW = dt.datetime(2026, 7, 21, 0, 0, tzinfo=dt.UTC)

# Stamps an archive manifest can carry: the format the exporter writes, a stamp
# in the future (a clock step, a host ahead of this one), a hand-entered value,
# and the shapes strptime refuses.
STAMP_STRINGS = [
    "20260721T000000Z",
    "20260722T000000Z",
    "20260719T000000Z",
    "2026-07-21T00:00:00Z",
    "20260721T000000",
    "",
    "0",
    "99999999T999999Z",
    "20260230T000000Z",
    "20260721T250000Z",
    "20260721T00000Z",
    "20260721T000000Z ",
    " 20260721T000000Z",
    "20260721T000000Z\x00",
    "tomorrow",
    "\udcff",
    "2026年07月21日",
]

# Bounds a scheduler or an operator can pass, including the non-finite values a
# float flag accepts and a value so small the window is always open.
BOUNDS = [
    bs.DEFAULT_MAX_AGE_HOURS,
    0.0,
    -1.0,
    1.0,
    1e300,
    -1e300,
    1e-300,
    float("inf"),
    float("-inf"),
    float("nan"),
    2**53 + 1.0,
]

# Probability a corruption truncates the buffer rather than flipping one byte, and
# the probability a given archive in a root takes damage at all. Tuning knob: raise
# either to spend more of a run's budget on that shape.
P_TRUNCATE = 0.3
P_DAMAGE_ARCHIVE = 0.5
P_SINGLE_ARCHIVE = 0.5
# Ages are compared to the hour they were exported at, so a re-export can be a
# second off without that being a defect.
AGE_EPSILON_HOURS = 1e-6

# Relative probability of each way of damaging the manifest the stamp is read
# from. Tuning knob: raise a weight to spend more of a run's budget on that class.
STAMP_KIND_WEIGHTS = {
    "keep": 25,
    "manifest_value": 25,
    "stamp_bytes": 25,
    "drop_manifest": 15,
    "drop_dir": 10,
}

# The same, over an archive root whose archives are read as whole backups rather
# than as a manifest alone.
ARCHIVE_KIND_WEIGHTS = {
    "keep": 30,
    "manifest_value": 20,
    "manifest_bytes": 15,
    "segment_bytes": 20,
    "drop_manifest": 15,
}


def weighted(rng: random.Random, weights: dict[str, int]) -> str:
    """Pick one key from a name -> relative-weight table."""
    return rng.choices(list(weights), weights=list(weights.values()))[0]


def clone(value: Json) -> Json:
    """Independent copy of a parsed value, by the same JSON round trip the file uses."""
    return json.loads(json.dumps(value))


def corrupt(rng: random.Random, data: bytes) -> bytes:
    """Bytes that are damaged for certain: a no-op mutation would make the harness
    assert rejection of damage that never happened."""
    if not data:
        return data
    if rng.random() < P_TRUNCATE:
        cut = rng.randrange(len(data))
        return data[:cut] if cut else data[1:]
    pos = rng.randrange(len(data))
    replacement = rng.randrange(256)
    if replacement == data[pos]:
        replacement = (replacement + 1) % 256
    return data[:pos] + bytes([replacement]) + data[pos + 1 :]


def build_root(scratch: pathlib.Path, offsets_hours: list[float]) -> pathlib.Path:
    """An archive root holding one real archive per offset back from HARNESS_NOW."""
    source = scratch / "source"
    root = scratch / "archives"
    if not source.exists():
        ee.write_sample_stream(source)
    for hours in offsets_hours:
        moment = HARNESS_NOW - dt.timedelta(hours=hours)
        ee.export(
            source,
            root,
            ec.DEFAULT_INDEX,
            stamp=moment.strftime(ee.STAMP_FORMAT),
            now=moment,
        )
    return root


def check_status(status: bs.BackupStatus, expected: int) -> None:
    """The fields check() promised, on whatever the root turned out to hold."""
    if status.total != expected:
        raise InvariantBrokenError(
            f"check() counted {status.total} archive(s) over a root holding {expected}"
        )
    if (status.fresh is None) != (status.age_hours is None):
        raise InvariantBrokenError(f"check() set one of fresh/age_hours: {status}")
    if status.age_hours is not None and not math.isfinite(status.age_hours):
        raise InvariantBrokenError(f"check() returned a non-finite age: {status.age_hours!r}")
    if status.fresh is not None and not status.fresh.is_dir():
        raise InvariantBrokenError(
            f"check() named a fresh archive that is not a directory: {status}"
        )
    ages = [entry.age_hours for entry in status.series]
    if ages != sorted(ages):
        raise InvariantBrokenError(
            f"check() returned a series that is not newest first: {status.series}"
        )
    for name, _first in status.failed:
        if not isinstance(name, str):
            raise InvariantBrokenError(
                f"check() returned a non-string failure name: {status.failed}"
            )


def damage_stamp(archive: pathlib.Path, kind: str, rng: random.Random, mut: Mutator) -> None:
    """One class of damage aimed at the creation stamp the check reads."""
    manifest = archive / ee.MANIFEST_NAME
    if kind == "keep":
        return
    if kind == "manifest_value":
        try:
            loaded = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            loaded = {}
        manifest.write_text(json.dumps(mut.mutate(loaded)), encoding="utf-8")
        return
    if kind == "stamp_bytes":
        # The stamp is one string in the manifest, so byte damage is aimed at that
        # string rather than anywhere in the file, which would usually land on a
        # field the check never reads and prove nothing.
        text = manifest.read_text(encoding="utf-8")
        at = text.find("createdUtc")
        if at < 0:
            return
        pos = min(at + len("createdUtc") + rng.randrange(24), len(text) - 1)
        manifest.write_text(
            text[:pos] + chr(ord(text[pos]) ^ 0x20) + text[pos + 1 :], encoding="utf-8"
        )
        return
    if kind == "drop_manifest":
        manifest.unlink(missing_ok=True)
        return
    shutil.rmtree(archive)


def run_created_utc(rng: random.Random, mut: Mutator, iterations: int) -> dict[str, int]:
    """Target 1: the manifest's creation stamp, read from damaged bytes. Each
    iteration builds its own root, so one class of damage cannot leave the next
    iteration a root that is already broken."""
    stats = {"reads": 0, "dated": 0, "undated": 0}
    for i in range(iterations):
        scratch = RUNS / f"stamp-{i}"
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True, exist_ok=True)
        try:
            archive = build_root(scratch, [1.0])
            archive = next(p for p in sorted(archive.iterdir()) if p.is_dir())
            kind = weighted(rng, STAMP_KIND_WEIGHTS)
            damage_stamp(archive, kind, rng, mut)
            try:
                first = bs.created_utc(archive)
                second = bs.created_utc(archive)
            except Exception as exc:
                raise InvariantBrokenError(
                    f"created_utc raised {type(exc).__name__}: {exc} on a {kind} manifest"
                ) from exc
            if first != second:
                raise InvariantBrokenError("created_utc is not deterministic on the same manifest")
            if first is not None and first.tzinfo is not dt.UTC:
                raise InvariantBrokenError(f"created_utc returned a non-UTC stamp: {first!r}")
            stats["reads"] += 1
            stats["dated" if first is not None else "undated"] += 1
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    return stats


def damage_archives(archives: list[pathlib.Path], rng: random.Random, mut: Mutator) -> None:
    """Damage some of the archives in a root, in whichever class the run drew.

    Damage confined to a segment or the manifest is what check() has to notice: an
    archive that no longer verifies cannot be the fresh backup, and the finding
    names it.
    """
    for archive in archives:
        if rng.random() < P_DAMAGE_ARCHIVE:
            continue
        kind = weighted(rng, ARCHIVE_KIND_WEIGHTS)
        manifest = archive / ee.MANIFEST_NAME
        if kind == "manifest_value":
            try:
                loaded = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                loaded = {}
            manifest.write_text(json.dumps(mut.mutate(loaded)), encoding="utf-8")
        elif kind in ("manifest_bytes", "segment_bytes"):
            target = (
                manifest
                if kind == "manifest_bytes"
                else next(iter(sorted(archive.glob(ee.SEGMENT_GLOB))), None)
            )
            if target is not None and target.is_file():
                target.write_bytes(corrupt(rng, target.read_bytes()))
        elif kind == "drop_manifest" and manifest.is_file():
            manifest.unlink()


def run_check(rng: random.Random, mut: Mutator, iterations: int) -> dict[str, int]:
    """Target 2: the whole root walk, over a root holding damaged archives beside
    entries that are not archives."""
    stats = {"runs": 0, "clean": 0, "reported": 0, "undated": 0, "failed": 0}
    for i in range(iterations):
        scratch = RUNS / str(i)
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True, exist_ok=True)
        try:
            offsets = [1.0] if rng.random() < P_SINGLE_ARCHIVE else [1.0, 30.0, 48.0]
            root = build_root(scratch, offsets)
            damage_archives(sorted(p for p in root.iterdir() if p.is_dir()), rng, mut)
            # Entries the tool is documented to leave alone: a file and a
            # directory that are not archives, named so they carry no archive
            # prefix. Anything with the prefix is this tool's business, dated or
            # not, which is what keeps an unreadable manifest reported rather
            # than skipped.
            (root / "notes.txt").write_text("not an archive\n", encoding="utf-8")
            (root / "logs").mkdir(exist_ok=True)
            expected = len(
                [p for p in root.iterdir() if p.is_dir() and p.name.startswith(bs.ARCHIVE_PREFIX)]
            )
            try:
                first = bs.check(root, now=HARNESS_NOW)
                second = bs.check(root, now=HARNESS_NOW)
            except Exception as exc:
                raise InvariantBrokenError(f"check() raised {type(exc).__name__}: {exc}") from exc
            if first != second:
                raise InvariantBrokenError("check() is not deterministic on the same root")
            check_status(first, expected)
            if first.fresh is not None and ee.verify(first.fresh):
                raise InvariantBrokenError(
                    "check() called an archive that does not verify the fresh backup: "
                    f"{first.fresh}"
                )
            try:
                errs = bs.report(first, root, bs.DEFAULT_MAX_AGE_HOURS)
            except Exception as exc:
                raise InvariantBrokenError(f"report() raised {type(exc).__name__}: {exc}") from exc
            if not all(isinstance(e, str) for e in errs):
                raise InvariantBrokenError(f"report() returned a non-string error: {errs!r}")
            if first.total == 0 and len(errs) != 1:
                raise InvariantBrokenError(
                    f"report() gave {len(errs)} finding(s) for a root holding no archive"
                )
            stats["runs"] += 1
            stats["clean" if not errs else "reported"] += 1
            stats["undated"] += len(first.undated)
            stats["failed"] += len(first.failed)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    return stats


def run_gap(rng: random.Random, mut: Mutator, iterations: int) -> int:
    """Target 3: the spacing of the series, over ages and bounds no clock and no
    sane operator produces together."""
    for bound in BOUNDS:
        check_gap(bs.gap_errors([], bound), bound, "empty series")
        check_gap(bs.gap_errors([bs.ArchiveAge("one", 3.0)], bound), bound, "single entry")
    for _ in range(iterations):
        count = rng.randrange(0, 5)
        series: list[bs.ArchiveAge] = []
        for _ in range(count):
            age = mut.value(rng.choice([0.0, 1.5, 24.0, -3.0]))
            if not isinstance(age, (int, float)) or isinstance(age, bool):
                # A mutated age that is not a number is a case for report(), not
                # for the series: the real ages come from a parsed stamp.
                continue
            try:
                hours = float(age)
            except OverflowError:
                continue
            series.append(bs.ArchiveAge(f"evidence-2026-07-2{len(series) + 1}-000000", hours))
        if not all(math.isfinite(e.age_hours) for e in series):
            continue
        bound = rng.choice(BOUNDS)
        check_gap(bs.gap_errors(series, bound), bound, "mutated series")
    return iterations


def check_gap(errs: list[str], bound: float, what: str) -> None:
    """gap_errors promised a list of strings and no raise; the only bound it can be
    called with from the CLI is a finite positive one."""
    if not all(isinstance(e, str) for e in errs):
        raise InvariantBrokenError(f"gap_errors returned a non-string error for {what}: {errs!r}")
    if what == "single entry" and errs:
        raise InvariantBrokenError(f"gap_errors reported a gap in a one-entry series: {errs}")
    if not math.isfinite(bound) or bound <= 0:
        return
    for error in errs:
        if f"{bound:.0f} h window" not in error and f"{bound:.0f} h" not in error:
            raise InvariantBrokenError(
                f"gap_errors named a window the caller did not ask for: {error!r} (bound {bound})"
            )


def run_report(iterations: int) -> int:
    """Target 4: the operator-facing findings over a status no filesystem produced."""
    shapes = [
        bs.BackupStatus(None, None, [], [], 0, []),
        bs.BackupStatus(None, None, [], ["evidence-x"], 1, []),
        bs.BackupStatus(pathlib.Path("/root/evidence-20260721T000000Z"), 0.5, [], [], 1, []),
        bs.BackupStatus(pathlib.Path("/root/evidence-20260721T000000Z"), -5.0, [], [], 1, []),
        bs.BackupStatus(
            pathlib.Path("/root/evidence-20260721T000000Z"),
            1e300,
            [("evidence-20260722T000000Z", "does not verify")],
            [],
            2,
            [
                bs.ArchiveAge("evidence-20260722T000000Z", -1.0),
                bs.ArchiveAge("evidence-20260721T000000Z", 30.0),
            ],
        ),
    ]
    root = pathlib.Path("/root")
    for i in range(iterations):
        base = shapes[i % len(shapes)]
        status = bs.BackupStatus(
            fresh=base.fresh,
            age_hours=base.age_hours,
            failed=list(base.failed),
            undated=list(base.undated),
            total=base.total,
            series=list(base.series),
        )
        for bound in BOUNDS:
            try:
                errs = bs.report(status, root, bound)
            except Exception as exc:
                raise InvariantBrokenError(
                    f"report() raised {type(exc).__name__}: {exc} on {status} bound {bound}"
                ) from exc
            if not all(isinstance(e, str) for e in errs):
                raise InvariantBrokenError(f"report() returned a non-string error: {errs!r}")
            if status.total == 0 and len(errs) != 1:
                raise InvariantBrokenError(
                    f"report() gave {len(errs)} finding(s) for a status with no archive: {errs}"
                )
            if status.total > 0 and status.fresh is None and not errs:
                raise InvariantBrokenError("report() closed the window with no verifying archive")
            if bs.report(status, root, bound) != errs:
                raise InvariantBrokenError("report() is not deterministic on the same status")
    return iterations


def pair_assertions(root: pathlib.Path) -> None:
    """The states the tool exists to report, each read off a real archive root."""
    scratch = root / "pair"
    scratch.mkdir(parents=True, exist_ok=True)
    current = build_root(scratch, [1.0])
    archive = next(p for p in sorted(current.iterdir()) if p.is_dir())

    fresh = bs.check(current, now=HARNESS_NOW)
    one_hour_off = fresh.age_hours is None or abs(fresh.age_hours - 1.0) > AGE_EPSILON_HOURS
    if fresh.fresh != archive or one_hour_off:
        raise InvariantBrokenError(f"a current archive was not read as one hour old: {fresh}")
    if errs := bs.report(fresh, current, bs.DEFAULT_MAX_AGE_HOURS):
        raise InvariantBrokenError(f"a current archive was reported stale: {errs}")
    if bs.gap_errors(fresh.series, bs.DEFAULT_MAX_AGE_HOURS):
        raise InvariantBrokenError("a one-archive series reported a gap")

    # Only a stale archive: the window is open, and the age names it.
    stale_root = build_root(scratch / "stale", [72.0])
    stale = bs.report(bs.check(stale_root, now=HARNESS_NOW), stale_root)
    if not any("past the" in e for e in stale):
        raise InvariantBrokenError(f"a stale archive was not reported: {stale}")

    # A manifest that no longer parses leaves the archive undated, not dated at
    # some other value and not silently skipped.
    (archive / ee.MANIFEST_NAME).write_text("{ truncated", encoding="utf-8")
    undated = bs.check(current, now=HARNESS_NOW)
    if undated.undated != [archive.name] or undated.fresh is not None:
        raise InvariantBrokenError(f"an unreadable manifest was not reported undated: {undated}")
    if not any("no readable createdUtc" in e for e in bs.report(undated, current)):
        raise InvariantBrokenError("an undated archive was not named in the report")

    # A gap in the series is the run that never landed, and only the spacing says so.
    gapped = build_root(scratch / "gapped", [1.0, 96.0])
    gap = bs.gap_errors(bs.check(gapped, now=HARNESS_NOW).series, bs.DEFAULT_MAX_AGE_HOURS)
    if not any("no archive for" in e for e in gap):
        raise InvariantBrokenError(f"a 95 h hole in the series was not reported: {gap}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # Each iteration exports and verifies real archives, so this harness is slower
    # per iteration than the in-memory ones; 120 covers every damage class.
    add_fuzz_args(ap, default_iterations=120)
    args = fuzz_args(ap)
    rng = random.Random(args.seed)  # noqa: S311 - seeded corpus fuzzing, not a secret
    mut = Mutator(rng, weird_strings=STAMP_STRINGS, max_depth=3)

    SCRATCH.mkdir(exist_ok=True)
    try:
        stamps = run_created_utc(rng, mut, args.iterations)
        checks = run_check(rng, mut, max(args.iterations // 2, 1))
        gaps = run_gap(rng, mut, args.iterations)
        reports = run_report(max(args.iterations // 4, 1))
        with tempfile.TemporaryDirectory(prefix="fuzz-backup-status-pair-", dir=SCRATCH) as td:
            pair_assertions(pathlib.Path(td))
    except InvariantBrokenError as exc:
        print(f"fuzz-backup-status: FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(RUNS, ignore_errors=True)

    print(
        f"fuzz-backup-status: ok seed={args.seed} iterations={args.iterations} "
        f"stamp_reads={stamps['reads']} dated={stamps['dated']} undated={stamps['undated']} "
        f"check_runs={checks['runs']} clean={checks['clean']} reported={checks['reported']} "
        f"undated_archives={checks['undated']} failed_archives={checks['failed']} "
        f"gap_runs={gaps} report_runs={reports} sensitivity=ok"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
