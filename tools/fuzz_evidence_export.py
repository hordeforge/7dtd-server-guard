"""Fuzz the archive verifier and exporter (tools/evidence_export.py).

An archive is only as good as the check that accepts it, and the check reads
bytes this repo does not control: a manifest written by an older tool, a segment
hand-edited during an incident, a truncated copy. This harness throws
structure-aware mutations at it:

  target 1  verify() against a mutated manifest      (JSON shape, version, file list)
  target 2  verify() against mutated archive bytes  (segments, index, manifest text)

Invariants asserted per iteration:
  - verify() never raises: it returns a list of str naming what failed, and is
    deterministic across repeated calls on the same bytes.
  - Any damage the manifest records is detected: a wrong sha256, a wrong byte
    count, a missing listed file, an unlisted extra file, or a segment whose
    bytes no longer match the manifest.
  - Pair assertion across the persistence boundary: a directory exported by
    export() must verify with zero errors, and a directory that was never
    archived must be rejected.

Deterministic (seeded PRNG), stdlib only.

Usage:
  uv run python tools/fuzz_evidence_export.py [--iterations N] [--seed S]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import evidence_check as ec
import evidence_export as ee
from fuzz_common import InvariantBrokenError, Mutator, add_fuzz_args, fuzz_args

SCRATCH = ec.ROOT / ".scratch"

# Probability of each way of damaging an otherwise valid archive, so a run
# spends its budget on every class instead of one shape repeated.
P_MUTATE_MANIFEST_VALUE = 0.55
P_MUTATE_MANIFEST_BYTES = 0.15
P_MUTATE_SEGMENT_BYTES = 0.3
P_DROP_LISTED_FILE = 0.1
P_EXTRA_UNLISTED_FILE = 0.1
P_EDIT_SHA_FIELD = 0.2
P_EDIT_BYTES_FIELD = 0.2
# Probability of truncating a buffer instead of flipping one byte in it.
P_TRUNCATE_BYTES = 0.2


def _valid_stream(dest: pathlib.Path) -> None:
    """One valid segment plus its manifest, written the way export() writes them."""
    rec = {"schemaVersion": 1, "type": "health", "eventId": "seed", "chainPrev": ec.GENESIS}
    dest.mkdir(parents=True, exist_ok=True)
    seg = dest / "evidence-2026-07-21-000000.jsonl"
    seg.write_text(ec.canonical(rec) + "\n", encoding="utf-8")
    manifest = ee.build_manifest(dest, dest, "20260721T000000Z", ee.DEFAULT_INDEX_NAME)
    (dest / ee.MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True), "utf-8")


def _read_manifest(archive: pathlib.Path) -> object:
    """The manifest as JSON, or None when the byte damage left it unreadable: that
    is a case for verify() to reject, not for the harness to crash on."""
    try:
        return json.loads((archive / ee.MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _write_manifest(archive: pathlib.Path, manifest: object) -> None:
    (archive / ee.MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True), "utf-8")


def _verifier_view(manifest: object) -> object:
    """The part of a manifest verify() actually reads: the version, the index file
    name, and each entry's name, digest, and byte count. The rest (sourceDir,
    createdUtc, canonicalization, the record counts) is provenance verify() never
    looks at, so byte damage confined to it leaves the archive exactly as
    verifiable as it was before."""
    if not isinstance(manifest, dict):
        return manifest
    entries = manifest.get("files")
    return (
        manifest.get("manifestVersion"),
        manifest.get("indexFile"),
        (
            [
                (e.get("name"), e.get("sha256"), e.get("bytes"))
                for e in entries
                if isinstance(e, dict)
            ]
            if isinstance(entries, list)
            else entries
        ),
    )


def _mutate_manifest_sha_bytes(rng: random.Random, archive: pathlib.Path) -> bool:
    """Flip one byte inside a manifest sha256 digest, the damage verify() must catch.

    A flip anywhere else in the manifest text is not damage the verifier claims to
    detect: a timestamp or a source path is provenance, not integrity, so hitting
    one would assert a property the tool does not have.

    Returns False when the manifest holds no digest to damage.
    """
    manifest = _read_manifest(archive)
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        return False
    digests = [
        e["sha256"] for e in entries if isinstance(e, dict) and isinstance(e.get("sha256"), str)
    ]
    if not digests:
        return False
    digest = digests[rng.randrange(len(digests))]
    path = archive / ee.MANIFEST_NAME
    data = path.read_bytes()
    at = data.find(digest.encode("ascii"))
    if at < 0:
        return False
    pos = at + rng.randrange(len(digest))
    path.write_bytes(data[:pos] + bytes([(data[pos] + 1) % 256]) + data[pos + 1 :])
    return True


def _mutate_segment_bytes(rng: random.Random, data: bytes) -> bytes:
    """Damage bytes for certain: a no-op mutation would make the harness assert
    detection of damage that never happened."""
    if not data or rng.random() < P_TRUNCATE_BYTES:
        cut = rng.randrange(len(data))
        return data[:cut] if cut else data[1:]
    pos = rng.randrange(len(data))
    replacement = rng.randrange(256)
    if replacement == data[pos]:
        replacement = (replacement + 1) % 256
    return data[:pos] + bytes([replacement]) + data[pos + 1 :]


def _damage_archive(
    archive: pathlib.Path, rng: random.Random, mut: Mutator
) -> tuple[bool, list[str]]:
    """Apply random damage. Returns (verify must reject it, the damage kinds applied)."""
    must_fail = False
    damage: list[str] = []

    if rng.random() < P_MUTATE_MANIFEST_VALUE:
        # Generic JSON surgery: some mutations are semantically neutral (an
        # unknown key, an unchanged value), so this branch asserts only that
        # verify() survives them, not that it rejects them.
        _write_manifest(archive, mut.mutate(_read_manifest(archive)))
    elif rng.random() < P_MUTATE_MANIFEST_BYTES:
        path = archive / ee.MANIFEST_NAME
        before = _read_manifest(archive)
        path.write_bytes(_mutate_segment_bytes(rng, path.read_bytes()))
        # A flipped byte inside a field verify() never reads (the source path, the
        # canonicalization note) leaves the archive exactly as verifiable as it
        # was, so there is nothing for verify() to detect. Only damage that
        # changes what the manifest says about the archive, or that makes it
        # unreadable, is damage the verifier is required to catch.
        must_fail = _verifier_view(_read_manifest(archive)) != _verifier_view(before)
        if must_fail:
            damage.append("manifest-bytes")
    elif _mutate_manifest_sha_bytes(rng, archive):
        must_fail = True

    seg = archive / "evidence-2026-07-21-000000.jsonl"
    if rng.random() < P_MUTATE_SEGMENT_BYTES:
        seg.write_bytes(_mutate_segment_bytes(rng, seg.read_bytes()))
        must_fail = True
        damage.append("segment-bytes")

    if rng.random() < P_DROP_LISTED_FILE:
        seg.unlink()
        must_fail = True
        damage.append("drop-listed-file")

    if rng.random() < P_EXTRA_UNLISTED_FILE:
        (archive / "evidence-2026-01-01-000000.jsonl").write_text("{}\n", encoding="utf-8")
        must_fail = True
        damage.append("extra-unlisted-file")

    manifest = _read_manifest(archive)
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    first_entry = entries[0] if isinstance(entries, list) and entries else None
    if isinstance(first_entry, dict) and rng.random() < P_EDIT_SHA_FIELD:
        first_entry["sha256"] = "0" * 64
        _write_manifest(archive, manifest)
        must_fail = True
        damage.append("edit-sha-field")
    if isinstance(first_entry, dict):
        listed_bytes = first_entry.get("bytes")
        if (
            isinstance(listed_bytes, int)
            and not isinstance(listed_bytes, bool)
            and rng.random() < P_EDIT_BYTES_FIELD
        ):
            first_entry["bytes"] = listed_bytes + 1
            _write_manifest(archive, manifest)
            must_fail = True
            damage.append("edit-bytes-field")
    return must_fail, damage


def check_verify(tmp: pathlib.Path, rng: random.Random, mut: Mutator) -> bool:
    """Run verify() on a randomly damaged archive. Returns True when the damage was
    a kind verify() is required to catch."""
    archive = tmp / "archive"
    _valid_stream(archive)
    must_fail, damage = _damage_archive(archive, rng, mut)

    try:
        first = ee.verify(archive)
        second = ee.verify(archive)
    except Exception as exc:
        raise InvariantBrokenError(f"verify() raised {type(exc).__name__}: {exc}") from exc
    if first != second:
        raise InvariantBrokenError("verify() is not deterministic on the same archive")
    if not all(isinstance(e, str) for e in first):
        raise InvariantBrokenError("verify() returned a non-string error")
    if must_fail and not first:
        state = {
            "damage": damage,
            "files": sorted(p.name for p in archive.iterdir()),
            "manifest": _read_manifest(archive),
        }
        raise InvariantBrokenError(f"verify() accepted damaged archive bytes: {state}")
    return must_fail


def check_export_pair(tmp: pathlib.Path) -> None:
    """export() output must verify; a segment directory with no manifest must not."""
    source = tmp / "pair-source"
    out_root = tmp / "pair-archives"
    _valid_stream(source)
    errs = ee.export(source, out_root, ee.DEFAULT_INDEX_NAME)
    if errs:
        raise InvariantBrokenError(f"export() rejected a valid chain: {errs}")
    archives = sorted(p for p in out_root.iterdir() if p.is_dir())
    if len(archives) != 1:
        raise InvariantBrokenError("export() did not produce exactly one archive")
    if ee.verify(archives[0]):
        raise InvariantBrokenError("verify() rejected a fresh export")
    (source / ee.MANIFEST_NAME).unlink()
    if not ee.verify(source):
        raise InvariantBrokenError("verify() accepted a directory that was never archived")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # Each iteration writes and hashes real files twice, so this harness is far
    # slower per iteration than the in-memory ones; 300 covers every damage class
    # in about a minute.
    add_fuzz_args(ap, default_iterations=300)
    args = fuzz_args(ap)
    rng = random.Random(args.seed)  # noqa: S311 - seeded corpus fuzzing, not a secret
    mut = Mutator(rng, max_depth=3)
    stats = {"verify_runs": 0, "rejected": 0, "accepted": 0}

    SCRATCH.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fuzz-evidence-export-", dir=SCRATCH) as td:
        tmp = pathlib.Path(td)
        for _ in range(args.iterations):
            try:
                must_fail = check_verify(tmp / f"a{stats['verify_runs']}", rng, mut)
            except InvariantBrokenError as exc:
                print(f"fuzz-evidence-export: FAIL verify: {exc}", file=sys.stderr)
                return 1
            stats["verify_runs"] += 1
            stats["rejected" if must_fail else "accepted"] += 1
        try:
            check_export_pair(tmp)
        except InvariantBrokenError as exc:
            print(f"fuzz-evidence-export: FAIL pair: {exc}", file=sys.stderr)
            return 1
        stats["clean_pair"] = True

    print(
        f"fuzz-evidence-export: ok seed={args.seed} iterations={args.iterations} "
        f"verify_runs={stats['verify_runs']} rejected={stats['rejected']} "
        f"accepted={stats['accepted']} clean_pair=ok"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
