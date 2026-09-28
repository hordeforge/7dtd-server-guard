"""Fuzz the restore drill (tools/restore_drill.py).

The drill is the only thing that proves an archive can be recovered, and it is
the one tool here that reads three untrusted inputs at once: an archive whose
manifest and segments were written by an older exporter or edited during an
incident, an operator config hand-edited on the Windows host that runs the
server, and the record stream inside the restored copy. Every one of those
arrives as bytes or as a hand-written path, and the drill indexes content
nothing upstream has narrowed (the manifest's index name, a config's
identityMap.path, the configHash carried by a record). An unhandled shape there
aborts the monthly recovery run with a traceback naming no archive, which reads
as a drill that never ran. This harness throws structure-aware mutations at all
of it:

  target 1  drill()                                        (the whole command end
                                                           to end: a damaged
                                                           archive, a mutated or
                                                           mis-encoded config,
                                                           and the restore each
                                                           one drives)
  target 2  config_match_errors / secrets_errors           (the config consumers,
                                                           on content the
                                                           loader never narrows)
  target 3  _resolve                                       (a hand-edited path
                                                           string, from either
                                                           separator and either
                                                           host)
  target 4  work_dir_errors / readback                     (the restore-target
                                                           refusal, and the chain
                                                           walk over a restored
                                                           copy)

Invariants asserted per iteration:
  - drill() never raises on any input shape, including a config that parses to
    a non-object and an archive with no manifest. It returns (list of str, str)
    and is deterministic: the same archive and config drilled into a second
    empty work directory report the same findings.
  - Damage the archive verifier is required to catch is reported, and a drill
    that reports something leaves nothing restored in the work directory, so
    the next run is not refused on its own leftovers.
  - config_match_errors and secrets_errors never raise on any object config and
    return a list of str; a config naming no path is reported rather than
    passing as a clean drill, and records carrying no configHash are reported.
  - _resolve never raises on any value, and a relative path resolves under the
    runtime root with either separator; only a drive-qualified server-host path
    resolves to None.
  - work_dir_errors returns a list of str and refuses a non-empty or
    non-directory work path; readback over a directory holding no records
    reports rather than claiming a restore.
  - Pair assertions across the file boundary: a valid archive drilled with the
    config its records were written under, and both keys present inside the copy
    cycle, reports nothing; a config from another deployment and a missing key
    are each named.

Deterministic (seeded PRNG), stdlib only, no external fuzzer required.

Usage:
  uv run python tools/fuzz_restore_drill.py [--iterations N] [--seed S]

Exit codes: 0 every invariant held, 1 an invariant broke, 2 usage error. The
replay of a reported failure is `uv run python tools/fuzz_restore_drill.py
--seed <seed>`; the failure and its input go to stderr.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import os
import pathlib
import random
import shutil
import sys
import tempfile
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import config_check as cc
import evidence_check as ec
import evidence_export as ee
import restore_drill as rd
from fuzz_common import (
    InvariantBrokenError,
    Mutator,
    add_fuzz_args,
    corrupt_bytes,
    fuzz_args,
    json_clone,
    nested,
    weighted_choice,
)

# Config JSON, mutated past its declared types on purpose: the shape is what the
# drill's consumers read, so the harness cannot narrow it either.
Json = Any

# Temporary archives and work directories go to the repo's gitignored scratch
# dir, not the system temp dir: /tmp is tmpfs here, so every iteration would be
# charged to RAM.
SCRATCH = ec.SCRATCH
RUNS = SCRATCH / "fuzz-restore-drill"

# The instant every run exports and ages at, so a seed that reproduces a failure
# reproduces it byte for byte.
HARNESS_NOW = dt.datetime(2026, 7, 21, 0, 0, tzinfo=dt.UTC)
HARNESS_STAMP = "20260721T000000Z"

# The config a healthy drill is handed: a relative identity map and key under the
# runtime root, which is the layout the drill resolves against.
DEPLOYED: Json = {
    "schemaVersion": 1,
    "identityMap": {"path": "identity-map.json"},
    "hmacKey": {"path": "keys/hmac.key"},
}

# Strings a hand-edited config carries in a path field: the Windows separator the
# server host's editor writes, a drive-qualified path only that host can open, a
# UNC path, and shapes no editor produces but no parser refuses either.
DOMAIN_STRINGS = [
    "identity-map.json",
    "keys\\hmac.key",
    "keys/hmac.key",
    "C:\\ProgramData\\7DaysToDie\\keys\\hmac.key",
    "C:/keys/hmac.key",
    "\\\\server\\share\\hmac.key",
    "/var/lib/7dtd/keys/hmac.key",
    "..\\..\\..\\etc\\passwd",
    "./keys/../keys/hmac.key",
    "keys//hmac.key",
    "",
    " ",
    "keys/../../../../../../../../etc/shadow",
    "keys/hmac.key\x00",
    "a" * 300 + "/hmac.key",
]

# Probability a run supplies a config at all, and that the exported stream carries
# a segment index. Tuning knob: raise or lower either to shift where the budget goes.
P_WITH_CONFIG = 0.7
P_WITH_INDEX = 0.7
# Probability a corruption truncates the buffer rather than flipping one byte in it.
P_TRUNCATE = 0.3

# Relative probability of each way of damaging a run's inputs. Tuning knob: raise
# a weight to spend more of a run's budget on that class of malformed input.
ARCHIVE_KIND_WEIGHTS = {
    "keep": 30,
    "manifest_value": 15,
    "manifest_bytes": 15,
    "segment_bytes": 20,
    "drop_segment": 10,
    "drop_manifest": 10,
}
CONFIG_KIND_WEIGHTS = {
    "keep": 35,
    "value": 30,
    "bytes": 20,
    "deep": 10,
    "not_json": 5,
}


def config_digest(config: Json) -> str:
    """The config hash a record carries when the server ran this config."""
    schema = json.loads(cc.SCHEMA_PATH.read_text(encoding="utf-8"))
    return cc.config_hash(cc.effective_config(config, schema))


def build_archive(
    scratch: pathlib.Path, *, config_hash: str | None, index: bool = True
) -> pathlib.Path:
    """An archive written the way export() writes one, over records stamped with
    `config_hash`, and the path of the archive directory."""
    source = scratch / "source"
    source.mkdir(parents=True, exist_ok=True)
    rd._write_stream_under(source, config_hash)
    if index:
        segments = sorted(p.name for p in source.glob(ee.SEGMENT_GLOB))
        (source / ec.DEFAULT_INDEX).write_text(
            json.dumps({"segments": [{"file": name} for name in segments]}), encoding="utf-8"
        )
    errs = ee.export(
        source, scratch / "archives", ec.DEFAULT_INDEX, stamp=HARNESS_STAMP, now=HARNESS_NOW
    )
    if errs:
        raise InvariantBrokenError(f"could not build a harness archive: {errs}")
    return next(p for p in sorted((scratch / "archives").iterdir()) if p.is_dir())


def build_runtime(scratch: pathlib.Path) -> pathlib.Path:
    """A runtime root holding the two artifacts no archive carries, both fresh at
    HARNESS_NOW, so a healthy drill has nothing to report about them."""
    runtime = scratch / "runtime"
    (runtime / "keys").mkdir(parents=True, exist_ok=True)
    paths = [runtime / "identity-map.json", runtime / "keys" / "hmac.key"]
    paths[0].write_text("{}\n", encoding="utf-8")
    paths[1].write_text("k\n", encoding="utf-8")
    stamp = HARNESS_NOW.timestamp()
    for path in paths:
        os.utime(path, (stamp, stamp))
    return runtime


def write_config(scratch: pathlib.Path, rng: random.Random, mut: Mutator) -> pathlib.Path:
    """The config file a drill is handed, damaged the way a hand edit and a
    corrupted copy each leave one."""
    config_dir = scratch / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    path = config_dir / "server-guard.json"
    kind = weighted_choice(rng, CONFIG_KIND_WEIGHTS)
    if kind == "keep":
        raw = json.dumps(DEPLOYED).encode("utf-8")
    elif kind == "value":
        raw = json.dumps(mut.mutate(json_clone(DEPLOYED))).encode("utf-8")
    elif kind == "bytes":
        raw = corrupt_bytes(rng, json.dumps(DEPLOYED).encode("utf-8"), truncate=P_TRUNCATE)
    elif kind == "deep":
        raw = json.dumps({**json_clone(DEPLOYED), "deep": nested(300)}).encode("utf-8")
    else:
        raw = b"{not json at all"
    path.write_bytes(raw)
    return path


def damage_archive(  # noqa: PLR0911, PLR0912 - one return and one branch per damage class
    archive: pathlib.Path, rng: random.Random, mut: Mutator
) -> tuple[bool, str]:
    """Apply one class of archive damage. Returns (the drill is required to report
    it, the damage kind), so a failure names the class that slipped through."""
    manifest = archive / ee.MANIFEST_NAME
    kind = weighted_choice(rng, ARCHIVE_KIND_WEIGHTS)
    if kind == "keep":
        return False, kind
    if kind == "manifest_value":
        try:
            loaded = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False, kind
        if not isinstance(loaded, dict):
            return False, kind
        # Only the fields verify() reads: the version, the index name, and each
        # entry's name, digest, and byte count. The rest is provenance (the
        # source path, the creation stamp, the record counts), and damage there
        # leaves the archive exactly as verifiable, so the harness asserts only
        # that a drill over it restores, not that it reports.
        entries = loaded.get("files")
        view: Json = {
            "manifestVersion": loaded.get("manifestVersion"),
            "indexFile": loaded.get("indexFile"),
            "files": [
                {k: e.get(k) for k in ("name", "sha256", "bytes")} if isinstance(e, dict) else e
                for e in (entries if isinstance(entries, list) else [])
            ],
        }
        damaged = mut.mutate(json_clone(view))
        # A mutation that is no longer an object, or that changed nothing, wrote
        # no damage: claiming otherwise would assert detection of damage the
        # archive never took.
        if not isinstance(damaged, dict) or damaged == view:
            return False, kind
        # Assign the three fields rather than merging over them: a mutation that
        # dropped one would otherwise leave the original value in place and the
        # manifest would read exactly as it did before.
        for field in view:
            if field in damaged:
                loaded[field] = damaged[field]
            else:
                loaded.pop(field, None)
        manifest.write_text(json.dumps(loaded), encoding="utf-8")
        return True, kind
    if kind == "manifest_bytes":
        # The manifest carries its own digest, so a flipped byte anywhere in it is
        # damage the verifier catches.
        manifest.write_bytes(corrupt_bytes(rng, manifest.read_bytes(), truncate=P_TRUNCATE))
        return True, kind
    if kind == "segment_bytes":
        for segment in sorted(archive.glob(ee.SEGMENT_GLOB)):
            segment.write_bytes(corrupt_bytes(rng, segment.read_bytes(), truncate=P_TRUNCATE))
            break
        return True, kind
    if kind == "drop_segment":
        segments = sorted(archive.glob(ee.SEGMENT_GLOB))
        if not segments:
            return False, kind
        segments[0].unlink()
        return True, kind
    manifest.unlink()
    return True, kind


def run_drill(
    scratch: pathlib.Path, archive: pathlib.Path, config: pathlib.Path | None
) -> tuple[list[str], str]:
    """One drill run, into a work directory of its own, then the work directory
    checked before it is removed."""
    request = rd.DrillRequest(
        archive=archive,
        work=scratch / "work",
        config_path=config,
        runtime_root=scratch / "runtime",
        max_age_hours=rd.KEY_MAX_AGE_HOURS,
        now=HARNESS_NOW,
    )
    try:
        errs, summary = rd.drill(request)
    except Exception as exc:
        raise InvariantBrokenError(
            f"drill() raised {type(exc).__name__}: {exc} (config={manifest_of(config)})"
        ) from exc
    if not all(isinstance(e, str) for e in errs):
        raise InvariantBrokenError(f"drill() returned non-string errors: {errs!r}")
    if not isinstance(summary, str):
        raise InvariantBrokenError(f"drill() returned a non-string summary: {summary!r}")
    # An archive that does not verify must leave nothing in the work directory:
    # leftovers are what make every later run refuse, turning one transient
    # failure into a drill nobody can run. A restore that succeeded and then
    # failed its config cross-check has legitimately left the copy, so the
    # check is against the archive rather than against the error list.
    work = scratch / "work"
    if errs and work.exists() and any(work.iterdir()) and ee.verify(archive):
        raise InvariantBrokenError(
            f"a drill over an archive that does not verify left "
            f"{sorted(p.name for p in work.iterdir())} in the work directory"
        )
    shutil.rmtree(work, ignore_errors=True)
    return errs, summary


def manifest_of(path: pathlib.Path | None) -> str:
    """The config a failing drill was handed, for the failure report."""
    if path is None:
        return "none"
    try:
        return path.read_text(encoding="utf-8")[:200]
    except (OSError, UnicodeDecodeError):
        return "unreadable"


def run_drills(rng: random.Random, mut: Mutator, iterations: int) -> dict[str, int]:
    """Target 1: the whole command, over a damaged archive and a mutated config,
    run twice so determinism is asserted on the same inputs."""
    stats = {"runs": 0, "reported": 0, "clean": 0, "configs": 0}
    for i in range(iterations):
        scratch = RUNS / str(i)
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True, exist_ok=True)
        try:
            with_config = rng.random() < P_WITH_CONFIG
            archive = build_archive(
                scratch,
                config_hash=config_digest(DEPLOYED) if with_config else None,
                index=rng.random() < P_WITH_INDEX,
            )
            build_runtime(scratch)
            damage, kind = damage_archive(archive, rng, mut)
            config = write_config(scratch, rng, mut) if with_config else None
            errs, _summary = run_drill(scratch, archive, config)
            replay, _replay_summary = run_drill(scratch, archive, config)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        if errs != replay:
            raise InvariantBrokenError(
                f"drill() is not deterministic on the same inputs: {errs} then {replay}"
            )
        if damage and not errs:
            raise InvariantBrokenError(
                f"drill() restored an archive damaged by {kind} and reported nothing"
            )
        stats["runs"] += 1
        stats["reported" if errs else "clean"] += 1
        stats["configs"] += int(config is not None)
    return stats


def run_config_consumers(rng: random.Random, mut: Mutator, iterations: int) -> int:
    """Target 2: the config consumers on object content the loader never narrows.

    A non-object config is a boundary case of the file, not of these two
    functions: `drill` is what refuses it, and target 1 runs those files through.
    """
    digest = config_digest(DEPLOYED)
    root = RUNS / "consumers"
    root.mkdir(parents=True, exist_ok=True)
    try:
        for _ in range(iterations):
            candidate = mut.mutate(json_clone(DEPLOYED))
            if not isinstance(candidate, dict):
                candidate = json_clone(DEPLOYED)
            hashes = rng.choice([{digest}, {digest[:16]}, set(), {"g" * 64}])
            try:
                matched = rd.config_match_errors(candidate, hashes, root / "server-guard.json")
                secrets = rd.secrets_errors(candidate, root, rd.KEY_MAX_AGE_HOURS, HARNESS_NOW)
            except Exception as exc:
                raise InvariantBrokenError(
                    f"config consumer raised {type(exc).__name__}: {exc} on {candidate!r}"
                ) from exc
            for name, out in (("config_match_errors", matched), ("secrets_errors", secrets)):
                if not all(isinstance(e, str) for e in out):
                    raise InvariantBrokenError(f"{name} returned a non-string error: {out!r}")
            # A field that names no readable path is reported, so a config whose
            # keys were dropped cannot pass as a clean drill.
            for section in ("identityMap", "hmacKey"):
                block = candidate.get(section)
                if (not isinstance(block, dict) or not block.get("path")) and not any(
                    section in e for e in secrets
                ):
                    raise InvariantBrokenError(
                        f"secrets_errors passed a config with no {section}.path: {candidate!r}"
                    )
            if not hashes and not any("configHash" in e for e in matched):
                raise InvariantBrokenError(
                    f"config_match_errors passed a stream carrying no configHash: {matched}"
                )
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return iterations


def run_resolve(rng: random.Random, mut: Mutator, iterations: int) -> int:
    """Target 3: a hand-edited path string, from either separator and either host."""
    root = pathlib.Path("/srv/7dtd")
    for value in DOMAIN_STRINGS:
        check_resolve(value, root)
    for _ in range(iterations):
        base = mut.value(rng.choice(DOMAIN_STRINGS))
        if isinstance(base, str):
            check_resolve(base, root)
    return iterations


def check_resolve(value: object, root: pathlib.Path) -> None:
    """_resolve on one value: a relative path lands under the runtime root, and
    only a drive-qualified path the drill host cannot open is given up on."""
    try:
        resolved = rd._resolve(value, root)
    except Exception as exc:
        raise InvariantBrokenError(
            f"_resolve raised {type(exc).__name__}: {exc} on {value!r}"
        ) from exc
    if resolved is None:
        text = str(value)
        if (
            not rd.WINDOWS_ABSOLUTE.match(text)
            or pathlib.Path(text.replace("\\", "/")).is_absolute()
        ):
            raise InvariantBrokenError(f"_resolve gave up on a resolvable path: {value!r}")
        return
    if not resolved.is_absolute():
        raise InvariantBrokenError(f"_resolve returned a relative path for {value!r}: {resolved}")


def run_work_and_readback(tmp: pathlib.Path, iterations: int) -> int:
    """Target 4: the work-target refusal, and the chain walk over a restored copy."""
    for i in range(iterations):
        work = tmp / f"work-target-{i}"
        work.mkdir(parents=True, exist_ok=True)
        try:
            if errs := rd.work_dir_errors(work):
                raise InvariantBrokenError(f"work_dir_errors refused an empty directory: {errs}")
            (work / "leftover.jsonl").write_text("stale\n", encoding="utf-8")
            if not rd.work_dir_errors(work):
                raise InvariantBrokenError(
                    "work_dir_errors accepted a directory holding a leftover"
                )
            shutil.rmtree(work)
            work.write_text("not a directory\n", encoding="utf-8")
            if not rd.work_dir_errors(work):
                raise InvariantBrokenError("work_dir_errors accepted a file as the restore target")
            work.unlink()
            if rd.work_dir_errors(work):
                raise InvariantBrokenError(
                    "work_dir_errors refused a target that does not exist yet"
                )
            # A chain walk over a directory holding no readable record is a
            # restore that proved nothing, and has to say so.
            errs, summary, hashes = rd.readback(work, "")
            if not errs or summary or hashes:
                raise InvariantBrokenError(
                    f"readback claimed a restore of an empty directory: {errs} {summary!r} {hashes}"
                )
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return iterations


def pair_assertions(root: pathlib.Path) -> None:
    """The cases the drill exists for, each asserted across the file boundary it
    crosses: a valid archive, the config its records were written under, and both
    keys present inside the copy cycle."""
    scratch = root / "pair"
    scratch.mkdir(parents=True, exist_ok=True)
    archive = build_archive(scratch, config_hash=config_digest(DEPLOYED))
    build_runtime(scratch)
    config_dir = scratch / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    config = config_dir / "server-guard.json"
    config.write_text(json.dumps(DEPLOYED), encoding="utf-8")

    def drill_into(name: str, cfg: pathlib.Path, runtime: pathlib.Path) -> tuple[list[str], str]:
        return rd.drill(
            rd.DrillRequest(
                archive=archive,
                work=scratch / name,
                config_path=cfg,
                runtime_root=runtime,
                max_age_hours=rd.KEY_MAX_AGE_HOURS,
                now=HARNESS_NOW,
            )
        )

    errs, summary = drill_into("work", config, scratch / "runtime")
    if errs:
        raise InvariantBrokenError(f"a valid archive drilled with its own config reported {errs}")
    if "2 record(s)" not in summary:
        raise InvariantBrokenError(f"readback did not report the restored records: {summary!r}")

    # The same drill with a config no record was written under names the mismatch
    # rather than passing the pairing over.
    elsewhere = {**copy.deepcopy(DEPLOYED), "schemaVersion": 2}
    other = config_dir / "elsewhere.json"
    other.write_text(json.dumps(elsewhere), encoding="utf-8")
    mismatch = drill_into("work-other", other, scratch / "runtime")[0]
    if not any("not the config that produced this evidence" in e for e in mismatch):
        raise InvariantBrokenError(f"a config from another deployment was not reported: {mismatch}")

    # A config holding valid JSON that is not an object is refused by name, not by
    # a traceback out of the run.
    array = config_dir / "array.json"
    array.write_text("[1, 2, 3]\n", encoding="utf-8")
    shaped = drill_into("work-array", array, scratch / "runtime")[0]
    if not any("must be a JSON object" in e for e in shaped):
        raise InvariantBrokenError(f"a config that is not an object was not reported: {shaped}")

    # A missing key is a drill failure, not a note beside a successful restore.
    (scratch / "runtime" / "keys" / "hmac.key").unlink()
    keyless = drill_into("work-keyless", config, scratch / "runtime")[0]
    if not any("hmacKey" in e for e in keyless):
        raise InvariantBrokenError(f"a drill with a missing HMAC key reported {keyless}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # Each iteration exports an archive, damages it, and drills it twice, so this
    # harness is far slower per iteration than the in-memory ones; 120 covers
    # every damage class and keeps the CI run inside its job budget.
    add_fuzz_args(ap, default_iterations=120)
    args = fuzz_args(ap)
    rng = random.Random(args.seed)  # noqa: S311 - seeded corpus fuzzing, not a secret
    mut = Mutator(rng, weird_strings=DOMAIN_STRINGS, max_depth=4)

    SCRATCH.mkdir(exist_ok=True)
    try:
        drills = run_drills(rng, mut, args.iterations)
        consumers = run_config_consumers(rng, mut, args.iterations * 2)
        resolves = run_resolve(rng, mut, args.iterations)
        with tempfile.TemporaryDirectory(prefix="fuzz-restore-drill-", dir=SCRATCH) as td:
            targets = run_work_and_readback(pathlib.Path(td), max(args.iterations // 4, 1))
            pair_assertions(pathlib.Path(td) / "pair-root")
    except InvariantBrokenError as exc:
        print(f"fuzz-restore-drill: FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(RUNS, ignore_errors=True)

    print(
        f"fuzz-restore-drill: ok seed={args.seed} iterations={args.iterations} "
        f"drill_runs={drills['runs']} reported={drills['reported']} clean={drills['clean']} "
        f"config_runs={drills['configs']} consumer_runs={consumers} "
        f"resolve_runs={resolves} work_runs={targets} sensitivity=ok"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
