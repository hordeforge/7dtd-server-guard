"""Verify the evidence hash chain (docs/SCHEMAS.md -> Evidence stream).

Canonical serialization (pinned): JSON with sorted keys, no whitespace:
    json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
chainPrev of a record is sha256 hex of the canonical form of the previous record.
Genesis: the first record of the very first segment has chainPrev == "0"*64.
Segment linking: the first record of a segment chains to the last record of the
previous segment (in file order).

Usage:
  uv run python tools/evidence_check.py --dir <evidence-dir> [--index segment-index.json]
  uv run python tools/evidence_check.py --sample        verify the shipped sample chain
  uv run python tools/evidence_check.py --self-test     run negative tests (tamper, genesis)

Exit codes: 0 verified, 1 the chain failed verification, 2 usage error. A
verification report goes to stdout when clean and to stderr when it found
issues, so a redirected run never mixes a verdict with its diagnostics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from collections.abc import Iterable, Iterator
from typing import Any, NamedTuple

# An evidence record as parsed from a segment line. Fields are validated by
# _parse_line and the evidence.v1 JSON Schema, not by the type.
Record = dict[str, Any]
# (line number, record, raw line) for one non-empty segment line.
ParsedLine = tuple[int, Record, str]


class SegmentChain(NamedTuple):
    """What one segment's chain walk observed: mismatch errors, record count, the
    first record's chainPrev (the cross-segment link), and the last record's hash
    (the next segment's expected link)."""

    errors: list[str]
    record_count: int
    first_prev: str | None
    last_hash: str | None


# sha256 rendered as lowercase hex.
SHA256_HEX_LEN = 64
GENESIS = "0" * SHA256_HEX_LEN
ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "config" / "schemas" / "evidence.v1.sample.jsonl"
SEGMENT_DIGITS = re.compile(r"(\d+)")

# Segment index file name inside --dir when --index is not given.
DEFAULT_INDEX = "segment-index.json"


def segment_sort_key(path: pathlib.Path) -> tuple[tuple[int, int, str], ...]:
    """Order segments naturally, so an unpadded `<seq>` beyond 9 does not sort first.

    Segments are `evidence-<UTC-date>-<seq>.jsonl` and chain in that order; plain
    lexicographic order puts `...-10` before `...-2` and breaks the link check on a
    day with ten or more segments.
    """
    return tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part)
        for part in SEGMENT_DIGITS.split(path.name)
    )


def canonical(record: Record) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def record_hash(record: Record) -> str:
    return hashlib.sha256(canonical(record).encode("utf-8")).hexdigest()


def _parse_line(name: str, line_no: int, line: str) -> Record:
    """Parse and shape-check one segment line. Raises ValueError naming file:line."""
    try:
        rec = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name}:{line_no}: unparseable JSON: {exc}") from exc
    if not isinstance(rec, dict):
        raise ValueError(f"{name}:{line_no}: record is not an object")
    for field in ("schemaVersion", "type", "eventId", "chainPrev"):
        if field not in rec:
            raise ValueError(f"{name}:{line_no}: missing field {field!r}")
    if not isinstance(rec["chainPrev"], str):
        raise ValueError(f"{name}:{line_no}: chainPrev must be a string")
    if rec["schemaVersion"] != 1:
        raise ValueError(f"{name}:{line_no}: unsupported schemaVersion {rec['schemaVersion']}")
    return rec


def iter_records(path: pathlib.Path) -> Iterator[ParsedLine]:
    """Yield (line_no, record, raw) for non-empty lines, one line at a time.

    Segments are append-only server output with no size bound, so verification
    streams them: a segment costs one line of memory here, not the whole file
    plus every parsed record.
    """
    name = path.name
    try:
        with path.open(encoding="utf-8") as handle:
            for i, raw in enumerate(handle, 1):
                line = raw.strip()
                if not line:
                    continue
                yield (i, _parse_line(name, i, line), line)
    except UnicodeDecodeError as exc:
        raise ValueError(f"{name}: not valid UTF-8: {exc}") from exc


def load_records(path: pathlib.Path) -> list[ParsedLine]:
    """Return (line_no, record, raw) for non-empty lines, materializing the segment.

    Use iter_records for anything reading a whole segment: evidence has no upper
    size bound, and this list holds every parsed record at once.
    """
    return list(iter_records(path))


def verify_chain(records: Iterable[ParsedLine], first_of_stream: bool) -> SegmentChain:
    """Verify chainPrev continuity within one segment.

    first_of_stream: True for the very first segment (genesis applies to its first record).
    Consumes the iterable once, so a segment can be streamed from disk.
    """
    errs: list[str] = []
    prev_hash: str | None = None
    first_prev: str | None = None
    count = 0
    for line_no, rec, _raw in records:
        count += 1
        if first_prev is None:
            first_prev = rec["chainPrev"]
        if count == 1 and not first_of_stream:
            # The first record of a non-first segment chains to the previous
            # segment's last record; the caller checks that link.
            prev_hash = record_hash(rec)
            continue
        expected = prev_hash if prev_hash is not None else GENESIS
        actual = rec["chainPrev"]
        if actual != expected:
            errs.append(
                f"line {line_no}: chainPrev mismatch; expected {expected[:16]}... ("
                + ("previous record" if prev_hash else "genesis")
                + f"), got {actual[:16]}..."
            )
        prev_hash = record_hash(rec)
    return SegmentChain(errs, count, first_prev, prev_hash)


def load_index(index_path: pathlib.Path) -> tuple[dict[str, Any] | None, list[str]]:
    """Read the optional segment index. Returns (index, errors); index is None when absent
    or unusable."""
    if not index_path.exists():
        return None, []
    name = index_path.name
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, [f"{name} unparseable: {exc}"]
    except UnicodeDecodeError as exc:
        return None, [f"{name} not valid UTF-8: {exc}"]
    if not isinstance(index, dict):
        return None, [f"{name}: must be a JSON object"]
    return index, []


def verify_dir(evidence_dir: pathlib.Path, index_name: str) -> list[str]:
    segments = sorted(evidence_dir.glob("evidence-*.jsonl"), key=segment_sort_key)
    if not segments:
        return [f"no evidence-*.jsonl segments found in {evidence_dir}"]
    index, errs = load_index(evidence_dir / index_name)

    prev_segment_last_hash = None
    for si, seg in enumerate(segments):
        try:
            chain = verify_chain(iter_records(seg), first_of_stream=si == 0)
        except ValueError as exc:
            errs.append(str(exc))
            continue
        if chain.record_count == 0:
            errs.append(f"{seg.name}: empty segment")
            continue
        errs += [f"{seg.name}: {e}" for e in chain.errors]
        # cross-segment link
        if si == 0 and chain.first_prev != GENESIS:
            errs.append(f"{seg.name}: first record of the stream must chain to genesis")
        if si > 0:
            if prev_segment_last_hash is None:
                errs.append(f"{seg.name}: previous segment had no records to chain to")
            elif chain.first_prev != prev_segment_last_hash:
                errs.append(
                    f"{seg.name}: first record does not chain to previous segment's last record"
                )
        prev_segment_last_hash = chain.last_hash

    # cross-check the index if present
    if index and "segments" in index:
        entries = index["segments"]
        well_formed = isinstance(entries, list) and all(isinstance(e, dict) for e in entries)
        index_files = [e.get("file") for e in entries] if well_formed else None
        actual = [s.name for s in segments]
        if index_files != actual:
            errs.append(f"{index_name}: segment list does not match files on disk")
    return errs


def verify_sample() -> list[str]:
    try:
        chain = verify_chain(iter_records(SAMPLE), first_of_stream=True)
    except ValueError as exc:
        return [str(exc)]
    return [f"sample: {e}" for e in chain.errors]


def self_test() -> list[str]:
    """Negative tests: tamper and bad-genesis must be detected."""
    errs = []
    base = [
        {"schemaVersion": 1, "type": "health", "eventId": "a", "chainPrev": GENESIS, "x": 1},
        {"schemaVersion": 1, "type": "health", "eventId": "b", "chainPrev": "", "x": 2},
    ]
    # build a valid chain first
    recs: list[Record] = []
    for i, template in enumerate(base):
        rec = dict(template)
        rec["chainPrev"] = GENESIS if i == 0 else record_hash(recs[-1])
        recs.append(rec)
    # tamper: change an earlier record without fixing downstream hashes. Tampering the
    # last record alone is NOT detectable until the next append; that is inherent to an
    # append-only chain and is documented in SCHEMAS.md.
    bad = [dict(recs[0]), dict(recs[1])]
    bad[0]["x"] = 999
    from_tuples = [(i + 1, r, json.dumps(r)) for i, r in enumerate(bad)]
    found = verify_chain(from_tuples, first_of_stream=True).errors
    if not found:
        errs.append("self-test: tamper was not detected")
    # A non-first segment's first record chains across the segment boundary (the
    # caller checks that link), but every record after it must still chain
    # within the segment: dropping that check would let a tampered middle record
    # pass unnoticed, so pin it here.
    tail = [dict(recs[0]), dict(recs[1])]
    tail[0]["x"] = 999
    tail_errors = verify_chain(
        [(i + 1, r, json.dumps(r)) for i, r in enumerate(tail)], first_of_stream=False
    ).errors
    if len(tail_errors) != 1:
        errs.append(
            "self-test: tampered record inside a non-first segment went unchecked: "
            f"{tail_errors}"
        )

    # non-first-segment links are checked by the caller (verify_dir); exercise the skip
    # branch so it keeps running without raising.
    verify_chain([(1, dict(recs[0]), "")], first_of_stream=False)
    # Segment order decides which chain link crosses the segment boundary, so an
    # unpadded <seq> past 9 must sort after 2, not before it.
    names = [pathlib.Path(f"evidence-2026-09-28-{i}.jsonl") for i in (2, 10, 1, 11)]
    ordered = [p.name for p in sorted(names, key=segment_sort_key)]
    if ordered != [
        "evidence-2026-09-28-1.jsonl",
        "evidence-2026-09-28-2.jsonl",
        "evidence-2026-09-28-10.jsonl",
        "evidence-2026-09-28-11.jsonl",
    ]:
        errs.append(f"self-test: segments ordered wrongly: {ordered}")
    return errs


def _report(label: str, errors: list[str]) -> int:
    """Print a labeled report and return the process exit code.

    The whole report goes to one stream: stdout when clean, stderr when it found
    issues, so a redirected run never mixes a verdict with its diagnostics.
    """
    stream = sys.stdout if not errors else sys.stderr
    print(f"{label}: {len(errors)} issue(s)", file=stream)
    for error in errors:
        print("  " + error, file=stream)
    return 1 if errors else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--dir", type=pathlib.Path, help="evidence directory with evidence-*.jsonl segments"
    )
    mode.add_argument("--sample", action="store_true", help="verify the shipped sample chain")
    mode.add_argument("--self-test", action="store_true", help="run negative tests and exit")
    ap.add_argument(
        "--index",
        default=DEFAULT_INDEX,
        help=f"segment index file name inside --dir (default: {DEFAULT_INDEX})",
    )
    args = ap.parse_args()

    if args.index != DEFAULT_INDEX and not args.dir:
        ap.error(
            f"--index applies to --dir only; pass --dir or drop --index (default {DEFAULT_INDEX})"
        )

    if args.self_test:
        return _report("evidence-check self-test", self_test())
    if args.sample:
        return _report("sample chain", verify_sample())
    if args.dir:
        if not args.dir.is_dir():
            return _report(f"evidence chain ({args.dir})", [f"{args.dir}: no such directory"])
        return _report(f"evidence chain ({args.dir})", verify_dir(args.dir, args.index))
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
