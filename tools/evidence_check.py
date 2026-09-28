"""Verify the evidence hash chain (docs/SCHEMAS.md -> Evidence stream).

Canonical serialization (pinned): JSON with sorted keys, no whitespace:
    json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
               allow_nan=False)
chainPrev of a record is sha256 hex of the canonical form of the previous record.
Genesis: the first record of the very first segment has chainPrev == "0"*64.
Segment linking: the first record of a segment chains to the last record of the
previous segment (in file order).
Non-finite numbers (NaN, Infinity) are not JSON: a segment line carrying the bare
literal is rejected at parse time rather than hashed into the chain.

Usage:
  uv run python tools/evidence_check.py --dir <evidence-dir> [--index segment-index.json]
  uv run python tools/evidence_check.py --sample        verify the shipped sample chain
  uv run python tools/evidence_check.py --self-test     run negative tests (tamper, genesis)
  make self-test TOOL=evidence_check                    the same, through the task runner

Exit codes: 0 verified, 1 the chain failed verification, 2 usage error. The
one-line verdict goes to stdout and the per-issue detail to stderr, so a
redirected run records the verdict and never mixes it with its diagnostics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import sys
import tempfile
from collections import deque
from collections.abc import Iterable, Iterator
from typing import Any, NamedTuple

import report_text
from self_test_common import main_contract_errors

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
# Self-test scratch files go to the repo's gitignored scratch dir, not the system
# temp dir: /tmp is tmpfs on this host, so the file would be charged to RAM.
SCRATCH = ROOT / ".scratch"
SEGMENT_DIGITS = re.compile(r"(\d+)")
# What names a segment of the evidence stream. The exporter, the restore drill and
# the backup status check all decide which files are the evidence; one spelling
# here keeps them deciding over the same set.
SEGMENT_GLOB = "evidence-*.jsonl"
# Longest untrusted string a report quotes before it is cut. A record field
# reaches this tool from the server, which took it from a client, so it is
# bounded text: a finding that names it needs the leading characters, not the
# whole megabyte, and an unbounded one would put that megabyte on the
# operator's terminal.
MAX_REPORT_TEXT_LEN = 80
# How many recently walked eventIds the duplicate-append check remembers. A
# repeated record is written by a retry or a crash-restart replay, so the second
# copy lands within the retry horizon, not months later; the window is that
# horizon's memory cost and nothing more. A repeat older than the window is not
# reported, which is why the window is stated rather than implied.
DUPLICATE_WINDOW_RECORDS = 65536
# How many chain errors one segment reports. The walk is streamed so a segment of
# any size costs one record of memory, and an error list with no bound would take
# that back: a segment whose links are all wrong yields one message per record, so
# a large tampered segment would be held in memory and printed in full by the tool
# an operator runs during an incident. Past the cap the walk continues and counts,
# and the report says how many findings it left out rather than implying it read
# everything.
MAX_REPORTED_CHAIN_ERRORS = 50


class RecentEventIds:
    """The eventIds of the last `capacity` records walked, for repeat detection.

    The evidence stream is append-only and at-least-once: a writer that retries
    after a crash, or a hook that fires twice for one event, appends the same
    eventId a second time. The chain still verifies, because the repeat links to
    whatever record preceded it, so an operator reading the stream sees one event
    as two findings and two actions. This is the only place that can see it.

    The window is bounded so the verifier keeps the memory property documented in
    SCHEMAS.md; a repeat further back than the window is not detected.
    """

    def __init__(self, capacity: int = DUPLICATE_WINDOW_RECORDS) -> None:
        self._order: deque[str] = deque()
        self._ids: set[str] = set()
        self._capacity = capacity

    def seen_before(self, event_id: str) -> bool:
        """Whether event_id is already in the window, keeping the window's newest
        `capacity` ids."""
        if event_id in self._ids:
            return True
        self._ids.add(event_id)
        self._order.append(event_id)
        if len(self._order) > self._capacity:
            self._ids.discard(self._order.popleft())
        return False


# Segment index file name inside --dir when --index is not given.
DEFAULT_INDEX = "segment-index.json"
# The code main returns for an argument combination it refuses before it starts
# work. argparse exits 2 on its own for a bad flag, so the two agree.
USAGE_ERROR = 2
# Longest file name accepted from a directory or a manifest. The limit is in bytes,
# which is what the filesystem counts, and the ASCII allowlist below makes a
# character count and a byte count the same number, so a hostile name cannot reach
# the filesystem as a path the OS rejects (ENAMETOOLONG) instead of being reported.
MAX_FILE_NAME_LEN = 128
# The characters a name may be built from. `str.isalnum()` is not this: it accepts
# every Unicode letter, digit, and numeric form, so a fullwidth or Arabic-Indic
# spelling of a segment name would pass a check that reads as ASCII and resolve to
# a different file from the one the operator sees. Every name this repo writes is
# ASCII, so nothing legitimate is lost.
FILE_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
# Stems that name a device rather than a file on a Windows host, where the check
# is on the part before the first dot, so "nul" and "nul.jsonl" both resolve to
# the null device. The evidence directory lives on the host the server runs on, so
# a name that reads as a segment here can be a device there: the same manifest
# would then verify against something that was never written.
WINDOWS_DEVICE_STEMS = frozenset(
    ["con", "prn", "aux", "nul"]
    + [f"com{i}" for i in range(1, 10)]
    + [f"lpt{i}" for i in range(1, 10)]
)


def valid_file_name(name: object) -> bool:
    """True when `name` is a plain file name that can be joined onto a directory.

    A name reaching the filesystem from a CLI flag or a manifest is untrusted text:
    `directory / name` resolves an absolute name to itself and walks out of the
    directory on a `..` segment, so both are rejected here rather than joined.
    The allowlist admits no path separator, which is what makes both impossible.

    Two names that are ordinary files on a POSIX host are refused, because the
    archive has to mean the same thing on every host that restores it: a Windows
    device stem, and a trailing dot, which Windows strips so that "seg.jsonl."
    silently opens "seg.jsonl" instead.
    """
    return (
        isinstance(name, str)
        and 0 < len(name) <= MAX_FILE_NAME_LEN
        and name not in (".", "..")
        and not name.endswith(".")
        and name.split(".", 1)[0].lower() not in WINDOWS_DEVICE_STEMS
        and all(c in FILE_NAME_CHARS for c in name)
    )


def child_map(directory: pathlib.Path) -> dict[str, pathlib.Path]:
    """Every entry of `directory`, keyed by its exact name.

    A case-insensitive filesystem (NTFS, APFS, or ext4 mounted casefold) resolves
    "Segment-Index.json" to "segment-index.json", so joining a name from a
    manifest and opening it succeeds there and fails on a case-sensitive host.
    Names are matched against the directory's own entries instead, so a manifest
    that does not name the archived bytes exactly is reported on every host.

    The listing is taken once and looked up by name: a caller resolving every
    member of an archive re-listed the same directory once per member, and the
    cost of that was quadratic in the member count on a directory with more than
    a few hundred entries.
    """
    return {entry.name: entry for entry in directory.iterdir()}


def exact_child(directory: pathlib.Path, name: str) -> pathlib.Path | None:
    """The entry of `directory` whose name is exactly `name`, or None.

    One name at a time; a caller resolving a whole directory's worth of names
    takes the listing once with child_map instead.
    """
    return child_map(directory).get(name)


def _reject_non_finite(token: str) -> float:
    """parse_constant hook: the bare NaN/Infinity literals are not JSON."""
    raise ValueError(f"non-finite number {token!r}")


def display_text(value: object, limit: int = MAX_REPORT_TEXT_LEN) -> str:
    """Untrusted text as a report may print it.

    A record field reaches this tool from the game server, which took it from a
    client, so it is not the repository's own text: it can carry an ANSI escape
    that erases the line the finding is on, or a control character that moves
    the cursor and makes a spoofed finding appear where no other is. A terminal
    is the only place these reports are read, so the escape is the attack. Every
    control character is spelled out, rather than only the three or four escapes
    that erase a line, because a filter chosen from the ones seen is one more
    escape away from being wrong.

    Length is bounded for the same reason the characters are: a megabyte of
    quoted field would bury every other finding under it. The cut is marked, so
    a truncated value cannot be read as the whole one.
    """
    text = value if isinstance(value, str) else str(value)
    text = "".join(ch if ch.isprintable() else f"<U+{ord(ch):04X}>" for ch in text if ch != "\x7f")
    if len(text) > limit:
        text = text[:limit] + "..."
    return text


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
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def record_hash(record: Record) -> str:
    return hashlib.sha256(canonical(record).encode("utf-8")).hexdigest()


def _parse_line(name: str, line_no: int, line: str) -> Record:
    """Parse and shape-check one segment line. Raises ValueError naming file:line."""
    try:
        rec = json.loads(line, parse_constant=_reject_non_finite)
    except ValueError as exc:
        # ValueError, not just JSONDecodeError: the parse_constant hook runs
        # inside json.loads, so it cannot know which segment line it came from,
        # and a NaN/Infinity literal must be reported with the same file:line
        # context as any other bad line rather than escaping uncontextualized.
        raise ValueError(f"{name}:{line_no}: unparseable JSON: {exc}") from exc
    except RecursionError as exc:
        # RecursionError is a RuntimeError, not a ValueError, and the decoder
        # raises it on a line nested past the interpreter's recursion limit. A
        # segment is server output the verifier is meant to distrust, so one
        # crafted line carrying a hundred thousand open brackets would otherwise
        # abort the whole walk with a traceback and name no file and no line,
        # which is the one answer an operator mid-incident cannot act on.
        raise ValueError(
            f"{name}:{line_no}: unparseable JSON: nested too deeply to decode"
        ) from exc
    if not isinstance(rec, dict):
        raise ValueError(f"{name}:{line_no}: record is not an object")
    for field in ("schemaVersion", "type", "eventId", "chainPrev"):
        if field not in rec:
            raise ValueError(f"{name}:{line_no}: missing field {field!r}")
    if not isinstance(rec["chainPrev"], str):
        raise ValueError(f"{name}:{line_no}: chainPrev must be a string")
    if not isinstance(rec["eventId"], str):
        raise ValueError(f"{name}:{line_no}: eventId must be a string")
    if rec["schemaVersion"] != 1 or isinstance(rec["schemaVersion"], bool):
        # A bool is an int subclass, so `True != 1` is False and a record
        # declaring `"schemaVersion": true` would otherwise be read as a version-1
        # record, canonicalized to `true`, and hashed into the chain.
        raise ValueError(f"{name}:{line_no}: unsupported schemaVersion {rec['schemaVersion']!r}")
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
    except OSError as exc:
        raise ValueError(f"{name}: unreadable: {exc}") from exc


def load_records(path: pathlib.Path) -> list[ParsedLine]:
    """Return (line_no, record, raw) for non-empty lines, materializing the segment.

    Use iter_records for anything reading a whole segment: evidence has no upper
    size bound, and this list holds every parsed record at once.
    """
    return list(iter_records(path))


def verify_chain(
    records: Iterable[ParsedLine], first_of_stream: bool, seen: RecentEventIds
) -> SegmentChain:
    """Verify chainPrev continuity within one segment, and that no event is
    appended twice.

    first_of_stream: True for the very first segment (genesis applies to its first record).
    seen: the caller's cross-segment eventId window, so a repeat is caught whether
    it lands in one segment or two.
    Consumes the iterable once, so a segment can be streamed from disk.
    """
    errs: list[str] = []
    hidden = 0

    def report(message: str) -> None:
        """Keep the first MAX_REPORTED_CHAIN_ERRORS findings and count the rest.

        The walk does not stop at the cap: the record count and the last hash are
        what the cross-segment link is checked against, so a capped walk that gave
        up early would report a break that is not there.
        """
        nonlocal hidden
        if len(errs) < MAX_REPORTED_CHAIN_ERRORS:
            errs.append(message)
        else:
            hidden += 1

    prev_hash: str | None = None
    first_prev: str | None = None
    count = 0
    for line_no, rec, _raw in records:
        count += 1
        if seen.seen_before(rec["eventId"]):
            report(
                f"line {line_no}: eventId {display_text(rec['eventId'])} was already appended "
                f"earlier in the stream; the same event was written twice "
                f"(a retry or a replayed append)"
            )
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
            report(
                f"line {line_no}: chainPrev mismatch; expected {expected[:16]}... ("
                + ("previous record" if prev_hash else "genesis")
                + f"), got {display_text(actual, 16)}..."
            )
        prev_hash = record_hash(rec)
    if hidden:
        errs.append(
            f"{hidden} further chain error(s) not shown (capped at {MAX_REPORTED_CHAIN_ERRORS})"
        )
    return SegmentChain(errs, count, first_prev, prev_hash)


def load_index(index_path: pathlib.Path) -> tuple[dict[str, Any] | None, list[str]]:
    """Read the optional segment index. Returns (index, errors); index is None when absent
    or unusable. The caller owns the join onto the evidence directory and is
    responsible for the name; see verify_dir."""
    if not index_path.exists():
        return None, []
    name = index_path.name
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, [f"{name} unparseable: {exc}"]
    except UnicodeDecodeError as exc:
        return None, [f"{name} not valid UTF-8: {exc}"]
    except OSError as exc:
        return None, [f"{name} unreadable: {exc}"]
    if not isinstance(index, dict):
        return None, [f"{name}: must be a JSON object"]
    return index, []


def _index_errors(
    index: dict[str, Any] | None, segments: list[pathlib.Path], name: str
) -> list[str]:
    """Cross-check the optional segment index against the files on disk.

    A `segments` value that is not an array of objects is reported as such; it
    names no file list, so comparing it to the directory would report a mismatch
    that does not exist and bury the malformed index that caused it.
    """
    if not index or "segments" not in index:
        return []
    entries = index["segments"]
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        return [f"{name}: 'segments' must be an array of objects"]
    if [e.get("file") for e in entries] != [s.name for s in segments]:
        return [f"{name}: segment list does not match files on disk"]
    return []


def verify_dir(evidence_dir: pathlib.Path, index_name: str) -> list[str]:
    return verify_dir_with_counts(evidence_dir, index_name)[0]


def verify_dir_with_counts(
    evidence_dir: pathlib.Path, index_name: str
) -> tuple[list[str], dict[str, int]]:
    """The findings for a directory, and the records each walked segment holds.

    The counts are what the archive manifest attests to, and the chain walk
    already knows them: a caller that needed both used to read every segment a
    second time to count its records. A segment that failed to parse is absent
    from the map rather than carrying the partial count of the lines read before
    the bad one, so a caller falls back to its own count instead of being told a
    truncated segment is complete.
    """
    # The index name is joined onto the evidence directory below, and a name that
    # is absolute or walks up with `..` resolves outside it: the verifier would
    # then read, or archive, a file that is not part of this evidence stream.
    if not valid_file_name(index_name):
        return (
            [f"--index {index_name!r} is not a plain file name inside the evidence directory"],
            {},
        )
    segments = sorted(evidence_dir.glob(SEGMENT_GLOB), key=segment_sort_key)
    if not segments:
        return [f"no {SEGMENT_GLOB} segments found in {evidence_dir}"], {}
    # The index name is matched against the directory's own entries, not joined
    # onto it: on a case-insensitive host a joined name opens a differently
    # spelled file, and the cross-check below would then compare a spelling no
    # archive actually holds.
    index_path = exact_child(evidence_dir, index_name)
    index, errs = load_index(index_path) if index_path is not None else (None, [])

    # The eventId window spans segments, so a repeat is caught whether it lands in
    # one segment or two.
    seen = RecentEventIds()
    counts: dict[str, int] = {}
    # Last record hash of the segment before the current one, and the name of a
    # segment that yielded no usable records. A segment that failed to load or is
    # empty carries no hash to link to, so the next segment's link is unverifiable
    # rather than broken; reporting a mismatch there would bury the real cause.
    prev_last_hash: str | None = None
    prev_unlinked: str | None = None
    for si, seg in enumerate(segments):
        # A segment name comes off the filesystem, so it carries whatever the
        # server wrote. Every message below quotes it, so it is filtered once
        # here rather than at each of the seven sites.
        label = display_text(seg.name)
        try:
            chain: SegmentChain | None = verify_chain(
                iter_records(seg), first_of_stream=si == 0, seen=seen
            )
        except ValueError as exc:
            errs.append(str(exc))
            chain = None
        except RecursionError:
            # Canonicalizing a record recurses to the depth the decoder reached,
            # so a line that parses at the very edge of the interpreter's limit
            # can still exhaust it here. Reported against the segment rather than
            # raised: the walk continues to the next segment.
            errs.append(f"{label}: a record is nested too deeply to canonicalize")
            chain = None
        if chain is None:
            prev_last_hash, prev_unlinked = None, label
            continue
        counts[seg.name] = chain.record_count
        if chain.record_count == 0:
            errs.append(f"{label}: empty segment")
            prev_last_hash, prev_unlinked = None, label
            continue
        errs += [f"{label}: {e}" for e in chain.errors]
        # cross-segment link
        if si == 0 and chain.first_prev != GENESIS:
            errs.append(f"{label}: first record of the stream must chain to genesis")
        if si > 0:
            if prev_unlinked is not None:
                errs.append(
                    f"{label}: previous segment {prev_unlinked} yielded no records; "
                    "its link to this segment is unverified"
                )
            elif chain.first_prev != prev_last_hash:
                errs.append(
                    f"{label}: first record does not chain to previous segment's last record"
                )
        prev_last_hash, prev_unlinked = chain.last_hash, None

    errs += _index_errors(index, segments, index_name)
    return errs, counts


def verify_sample() -> list[str]:
    try:
        chain = verify_chain(iter_records(SAMPLE), first_of_stream=True, seen=RecentEventIds())
    except ValueError as exc:
        return [str(exc)]
    return [f"sample: {e}" for e in chain.errors]


def _unicode_self_test(errs: list[str]) -> None:
    """The chain is exact over the canonical form, whatever a record's text holds.

    `canonical` escapes every non-ASCII code point, so a record naming a player
    with an accent, carrying an astral emoji, or holding the NFD spelling of a
    word round-trips through the segment unchanged and hashes the same. The NFD
    and NFC spellings are different records with different hashes: the chain
    proves what was written, so the spelling a detector picks is the spelling the
    chain commits to, and normalizing one spelling into the other here would
    break verification of an already-appended segment rather than protect it.
    """
    spellings = [
        "Ünïcödé",
        "\U0001f600",  # astral, four UTF-8 bytes, one code point
        "e\u0301",  # NFD
        "\u00e9",  # NFC of the same word
        "\udcff",  # unpaired UTF-16 half, as a JSON escape carries it
    ]
    recs: list[Record] = []
    prev = GENESIS
    for i, text in enumerate(spellings):
        rec: Record = {
            "schemaVersion": 1,
            "type": "health",
            "eventId": f"0000000{i}-0000-4000-8000-00000000000{i}",
            "chainPrev": prev,
            "playerName": text,
        }
        prev = record_hash(rec)
        recs.append(rec)
    if len({record_hash(r) for r in recs}) != len(recs):
        errs.append("self-test: distinct spellings collapsed to one record hash")
    round_tripped = [json.loads(canonical(r)) for r in recs]
    if round_tripped != recs:
        errs.append("self-test: a non-ASCII record did not survive canonical serialization")
    if verify_chain(
        [(i + 1, r, "") for i, r in enumerate(round_tripped)],
        first_of_stream=True,
        seen=RecentEventIds(),
    ).errors:
        errs.append("self-test: a chain over non-ASCII records did not verify")

    scratch = SCRATCH / "evidence-check-self-test"
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    try:
        # A segment the server wrote with a truncated multi-byte sequence is
        # reported as a named error, never a traceback out of the gate.
        bad = scratch / "evidence-2026-07-21-000000.jsonl"
        bad.write_bytes(canonical(recs[0]).encode("utf-8")[:-1] + b"\xc3\n")
        reported = verify_dir(scratch, "segment-index.json")
        if not any("not valid UTF-8" in e for e in reported):
            errs.append(f"self-test: invalid UTF-8 was not reported: {reported}")
        # A non-ASCII file name is a legal name on this filesystem and must be
        # walked and reported by name, not dropped from the segment list.
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True, exist_ok=True)
        named = scratch / "evidence-2026-07-21-00000é.jsonl"
        named.write_text(canonical(recs[0]) + "\n", encoding="utf-8")
        if reported := verify_dir(scratch, "segment-index.json"):
            errs.append(f"self-test: a valid segment with a non-ASCII name failed: {reported}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def self_test() -> list[str]:
    """Negative tests: tamper, bad genesis, a re-appended event, non-finite numbers,
    and the damaged-directory reports."""
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
    found = verify_chain(from_tuples, first_of_stream=True, seen=RecentEventIds()).errors
    if not found:
        errs.append("self-test: tamper was not detected")
    # A non-first segment's first record chains across the segment boundary (the
    # caller checks that link), but every record after it must still chain
    # within the segment: dropping that check would let a tampered middle record
    # pass unnoticed, so pin it here.
    tail = [dict(recs[0]), dict(recs[1])]
    tail[0]["x"] = 999
    tail_errors = verify_chain(
        [(i + 1, r, json.dumps(r)) for i, r in enumerate(tail)],
        first_of_stream=False,
        seen=RecentEventIds(),
    ).errors
    if len(tail_errors) != 1:
        errs.append(
            "self-test: tampered record inside a non-first segment went unchecked: "
            f"{tail_errors}"
        )

    errs += _duplicate_append_test(recs)

    # non-first-segment links are checked by the caller (verify_dir); the skip branch
    # must leave the boundary record unchecked internally while still reporting the
    # link the caller needs: its chainPrev as first_prev, its own hash as last_hash.
    boundary = verify_chain([(1, dict(recs[0]), "")], first_of_stream=False, seen=RecentEventIds())
    if boundary.errors:
        errs.append(f"self-test: a non-first segment's first record was checked: {boundary.errors}")
    if (boundary.record_count, boundary.first_prev, boundary.last_hash) != (
        1,
        GENESIS,
        record_hash(recs[0]),
    ):
        errs.append(f"self-test: boundary link not reported to the caller: {boundary}")
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
    # A bare NaN/Infinity literal is not JSON, and a NaN would hash into the chain
    # as a token no reader reproduces, breaking the next verifier's digest.
    SCRATCH.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evidence-self-test-", dir=SCRATCH) as td:
        for literal in ("NaN", "Infinity", "-Infinity"):
            path = pathlib.Path(td) / "seg.jsonl"
            path.write_text(
                '{"schemaVersion":1,"type":"health","eventId":"a","chainPrev":"'
                + GENESIS
                + f'","confidence":{literal}}}\n',
                encoding="utf-8",
            )
            try:
                load_records(path)
            except ValueError:
                continue
            errs.append(f"self-test: record with {literal} was accepted")
    # canonical() refuses a non-finite value built in memory, before it can be hashed.
    try:
        canonical({**recs[0], "confidence": float("nan")})
    except ValueError:
        pass
    else:
        errs.append("self-test: canonical serialized a NaN")
    errs += _schema_version_test()
    errs += _dir_self_test(recs)
    errs += _index_name_test(recs)
    errs += _sample_chain_test()
    errs += _verify_dir_tests()
    errs += _untrusted_text_test()
    _unicode_self_test(errs)
    errs += _main_contract_self_test()
    return errs


def _main_contract_self_test() -> list[str]:
    """Pin the exit codes and stream split documented in tools/README.md.

    A monitoring job runs `--dir` on a schedule and reads the exit code, and the
    doccheck gate runs `--sample`, so both verdicts matter: 0 the chain verified,
    1 it did not (a directory that is not there included), 2 for a usage error.
    The bare run and the `--index`-without-`--dir` refusal are the two a
    half-written wrapper produces, and a usage error that printed on stdout would
    put a help dump where a report belongs.
    """
    cases: list[tuple[str, list[str], int]] = [
        ("bare run", [], USAGE_ERROR),
        ("--index with no --dir", ["--index", "other-index.json"], USAGE_ERROR),
        ("sample chain", ["--sample"], 0),
        ("missing directory", ["--dir", str(SCRATCH / "no-such-evidence-dir")], 1),
    ]
    return main_contract_errors(cases, script="evidence_check.py", run=main, usage_error=USAGE_ERROR)


def _untrusted_text_test() -> list[str]:
    """A record the server took from a client cannot rewrite the operator's terminal.

    Two properties, both on a report a real evidence directory can produce: a
    line nested past the interpreter's recursion limit is a reported finding
    naming its file and line rather than a traceback that names neither, and a
    field carrying an escape reaches the report with the control character
    spelled out rather than interpreted.
    """
    errs: list[str] = []
    with tempfile.TemporaryDirectory(dir=SCRATCH) as td:
        deep = "[" * 200000 + "]" * 200000
        try:
            _parse_line("evidence-deep.jsonl", 1, deep)
        except ValueError as exc:
            if "evidence-deep.jsonl:1" not in str(exc):
                errs.append(f"self-test: a deeply nested line was not reported by name: {exc}")
        except Exception as exc:  # the point is that nothing but ValueError escapes
            errs.append(f"self-test: a deeply nested line raised {type(exc).__name__}: {exc}")
        else:
            errs.append("self-test: a deeply nested line parsed as a record")

        directory = pathlib.Path(td)
        recs = _stream(2)
        recs[0]["eventId"] = "\x1b[2K\x07chain OK"
        recs[1]["eventId"] = recs[0]["eventId"]
        _write_segment(directory, "evidence-2026-09-28-1.jsonl", recs)
        found = verify_dir(directory, DEFAULT_INDEX)
        if any("\x1b" in error or "\x07" in error for error in found):
            errs.append(f"self-test: a control character reached the report raw: {found}")
        elif not any("U+001B" in error for error in found):
            errs.append(f"self-test: the duplicate eventId was not reported at all: {found}")
    return errs


def _schema_version_test() -> list[str]:
    """Only a JSON number 1 is schemaVersion 1.

    A bool is an int subclass, so `True != 1` is False: a record declaring
    `"schemaVersion": true` would be read as a version-1 record, canonicalized to
    `true`, and hashed into the chain. A float 1.0 is a different spelling of the
    same JSON number and stays valid.
    """
    errs: list[str] = []
    for bad in (True, False, "1", None, [1], {"v": 1}):
        rec: Record = {
            "schemaVersion": bad,
            "type": "health",
            "eventId": "a",
            "chainPrev": GENESIS,
        }
        try:
            _parse_line("seg.jsonl", 1, canonical(rec))
        except ValueError:
            continue
        errs.append(f"self-test: schemaVersion {bad!r} was accepted as version 1")
    return errs


def _duplicate_append_test(recs: list[Record]) -> list[str]:
    """A re-appended event must be reported as the second append, not as two findings."""
    errs: list[str] = []
    # A re-appended event: the same eventId written a second time, chained correctly
    # so only the repeat identifies it. This is what a retried or crash-replayed
    # append leaves in the stream, and an operator would read it as two findings and
    # two actions for one event.
    repeat = dict(recs[1])
    repeat["chainPrev"] = record_hash(recs[1])
    twice = [dict(recs[0]), dict(recs[1]), repeat]
    repeat_errors = verify_chain(
        [(i + 1, r, json.dumps(r)) for i, r in enumerate(twice)],
        first_of_stream=True,
        seen=RecentEventIds(),
    ).errors
    if not any("already appended" in e for e in repeat_errors):
        errs.append(f"self-test: a re-appended event was not reported: {repeat_errors}")
    # One run must not condemn the next: the same records verify clean in a fresh
    # window, so a repeat is reported as the second append and not as two findings.
    clean_errors = verify_chain(
        [(i + 1, r, json.dumps(r)) for i, r in enumerate(twice[:2])],
        first_of_stream=True,
        seen=RecentEventIds(),
    ).errors
    if clean_errors:
        errs.append(f"self-test: a single run of each record was reported: {clean_errors}")
    # A repeat older than the window is not detectable; the window must not grow past
    # its bound, and an id evicted from it must stop being reported.
    narrow = RecentEventIds(capacity=1)
    narrow.seen_before("a")
    if not narrow.seen_before("a"):
        errs.append("self-test: the duplicate window missed a repeat inside its bound")
    narrow.seen_before("b")
    if narrow.seen_before("a"):
        errs.append("self-test: the duplicate window did not evict the oldest eventId")
    return errs


def _dir_self_test(recs: list[Record]) -> list[str]:
    """Directory-level negatives: an unreadable segment and a malformed index.

    A segment that cannot be parsed must be reported once, and the segment after
    it must be reported as unlinked rather than as a chain mismatch: the link
    cannot be checked, and a mismatch would name a break that is not there.
    """
    errs: list[str] = []
    SCRATCH.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evidence-self-test-", dir=SCRATCH) as td:
        run = pathlib.Path(td)
        (run / "evidence-1.jsonl").write_text("{ not json\n", encoding="utf-8")
        (run / "evidence-2.jsonl").write_text(canonical(recs[0]) + "\n", encoding="utf-8")

        found = verify_dir(run, "segment-index.json")
        if not any("unparseable JSON" in e for e in found):
            errs.append(f"self-test: unreadable segment was not reported: {found}")
        if any("does not chain to previous segment" in e for e in found):
            errs.append(f"self-test: an unverifiable link was reported as a break: {found}")
        if not any("unverified" in e for e in found):
            errs.append(f"self-test: unverified link after a bad segment was not reported: {found}")

        (run / "segment-index.json").write_text(
            '{"segments": "evidence-1.jsonl"}', encoding="utf-8"
        )
        found = verify_dir(run, "segment-index.json")
        if not any("'segments' must be an array of objects" in e for e in found):
            errs.append(f"self-test: malformed index segments was not reported: {found}")
        if any("does not match files on disk" in e for e in found):
            errs.append(f"self-test: malformed index was reported as a file mismatch: {found}")
    return errs


def _index_name_test(recs: list[Record]) -> list[str]:
    """--index names a file inside --dir, so a name that resolves outside it is refused.

    `dir / name` resolves an absolute name to itself and walks out of the directory
    on a `..` segment, so an unchecked name would have the verifier read, and the
    exporter archive, a file that is not part of this evidence stream.
    """
    errs: list[str] = []
    SCRATCH.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evidence-self-test-", dir=SCRATCH) as td:
        run = pathlib.Path(td) / "run"
        run.mkdir()
        _write_segment(run, "evidence-2026-09-28-1.jsonl", [recs[0]])
        outside = pathlib.Path(td) / "not-the-index.json"
        outside.write_text(json.dumps({"segments": []}), encoding="utf-8")
        for name, what in (
            ("../not-the-index.json", "a parent-relative index name"),
            (str(outside), "an absolute index name"),
        ):
            found = verify_dir(run, name)
            if not any("not a plain file name" in e for e in found):
                errs.append(f"self-test: {what} was accepted: {found}")
        # The default name is a plain file name, and the same run with it verifies.
        if found := verify_dir(run, DEFAULT_INDEX):
            errs.append(f"self-test: a directory with no index was rejected: {found}")
    return errs


def _report(label: str, errors: list[str]) -> int:
    """Print a labeled report and return the process exit code.

    The verdict goes to stdout and the detail to stderr, the split every tool in
    tools/ uses, so `evidence_check.py > report.txt` records the verdict and
    leaves the diagnostics on the terminal.
    """
    print(f"{label}: {len(errors)} issue(s)")
    for error in errors:
        print("  " + error, file=sys.stderr)
    return 1 if errors else 0


def _sample_chain_test() -> list[str]:
    """The shipped sample is the chain operators are told to copy, so it must verify."""
    failures = verify_sample()
    return [f"self-test: shipped sample chain is invalid: {failures}"] if failures else []


def _stream(count: int) -> list[Record]:
    """`count` records chaining from genesis, one eventId and payload per position."""
    recs: list[Record] = []
    for i in range(count):
        recs.append(
            {
                "schemaVersion": 1,
                "type": "health",
                "eventId": f"e{i}",
                "chainPrev": GENESIS if not recs else record_hash(recs[-1]),
                "x": i,
            }
        )
    return recs


def _write_segment(directory: pathlib.Path, name: str, records: list[Record]) -> None:
    (directory / name).write_text(
        "".join(f"{json.dumps(rec)}\n" for rec in records), encoding="utf-8"
    )


def _verify_dir_tests() -> list[str]:
    """Pin the directory walk: the cross-segment link, the genesis link, and the index.

    verify_dir is what `make verify-evidence` runs, and the cross-segment link is the
    property the tool exists for, yet nothing deterministic covered it. Each case gets
    its own directory, so no case can leave a segment behind for the next one.
    """
    scratch = SCRATCH
    scratch.mkdir(exist_ok=True)
    cases = (
        _case_well_formed,
        _case_unlinked,
        _case_detached,
        _case_empty_segment,
        _case_error_cap,
        _case_index_mismatch,
        _case_unreadable_index,
        _case_absent_index,
        _case_no_segments,
    )
    with tempfile.TemporaryDirectory(prefix="evidence-self-test-", dir=scratch) as td:
        root = pathlib.Path(td)
        return [errs for i, case in enumerate(cases) for errs in case(str(root / str(i)))]


def _segment_dir(root: str) -> pathlib.Path:
    directory = pathlib.Path(root)
    directory.mkdir(parents=True)
    return directory


def _expect_reported(found: list[str], needle: str, what: str) -> list[str]:
    if not _reports(found, needle):
        return [f"self-test: {what} went unreported: {found}"]
    return []


def _case_well_formed(root: str) -> list[str]:
    """Positive control. Without it every negative case would also pass against a
    verify_dir that rejects everything."""
    directory = _segment_dir(root)
    stream = _stream(3)
    _write_segment(directory, "evidence-2026-09-28-1.jsonl", stream[:2])
    _write_segment(directory, "evidence-2026-09-28-2.jsonl", stream[2:])
    found = verify_dir(directory, "segment-index.json")
    return [f"self-test: a well-formed two-segment stream was rejected: {found}"] if found else []


def _case_unlinked(root: str) -> list[str]:
    """A second segment re-linking to genesis breaks the stream even though every
    segment verifies internally."""
    directory = _segment_dir(root)
    stream = _stream(3)
    stream[2] = {**stream[2], "chainPrev": GENESIS}
    _write_segment(directory, "evidence-2026-09-28-1.jsonl", stream[:2])
    _write_segment(directory, "evidence-2026-09-28-2.jsonl", stream[2:])
    return _expect_reported(
        verify_dir(directory, "segment-index.json"),
        "chain to previous segment",
        "a segment not chaining to its predecessor",
    )


def _case_detached(root: str) -> list[str]:
    """A first segment off genesis is a self-consistent stream that is not on the chain."""
    directory = _segment_dir(root)
    stream = _stream(3)
    stream[0] = {**stream[0], "chainPrev": record_hash(stream[0])}
    _write_segment(directory, "evidence-2026-09-28-1.jsonl", stream[:2])
    _write_segment(directory, "evidence-2026-09-28-2.jsonl", stream[2:])
    return _expect_reported(
        verify_dir(directory, "segment-index.json"),
        "chain to genesis",
        "a stream not starting at genesis",
    )


def _case_empty_segment(root: str) -> list[str]:
    """An empty segment is skipped, so its successor has no hash to chain to and must
    say so rather than silently verify."""
    directory = _segment_dir(root)
    stream = _stream(3)
    _write_segment(directory, "evidence-2026-09-28-1.jsonl", [])
    _write_segment(directory, "evidence-2026-09-28-2.jsonl", stream[2:])
    found = verify_dir(directory, "segment-index.json")
    return [
        *_expect_reported(found, "empty segment", "an empty segment"),
        *_expect_reported(found, "yielded no records", "an empty predecessor segment"),
    ]


def _case_error_cap(root: str) -> list[str]:
    """A segment whose every link is wrong reports a bounded number of findings.

    Evidence segments have no size bound and the chain walk is streamed, so an
    error list without a bound would put one message per record in memory and in
    the report. The walk still runs to the end of the segment (the cross-segment
    link is checked against its last hash), and the report names how many findings
    it left out instead of reading as a complete account.
    """
    directory = _segment_dir(root)
    stream = _stream(MAX_REPORTED_CHAIN_ERRORS + 20)
    # Every record after the first points at nothing, so every line mismatches.
    stream[1:] = [{**rec, "chainPrev": "0" * SHA256_HEX_LEN} for rec in stream[1:]]
    _write_segment(directory, "evidence-2026-09-28-1.jsonl", stream)
    found = verify_dir(directory, "segment-index.json")
    if len(found) > MAX_REPORTED_CHAIN_ERRORS + 1:
        return [
            (
                f"self-test: a wholly broken segment reported {len(found)} findings, "
                f"which is not bounded: {found[:3]}"
            )
        ]
    return _expect_reported(
        found, "further chain error", "a fully broken segment's hidden findings"
    )


def _case_index_mismatch(root: str) -> list[str]:
    """The index is what names a segment the chain cannot see."""
    directory = _segment_dir(root)
    stream = _stream(3)
    _write_segment(directory, "evidence-2026-09-28-1.jsonl", stream[:2])
    (directory / "segment-index.json").write_text(
        json.dumps({"segments": [{"file": "evidence-2026-09-28-9.jsonl"}]}), encoding="utf-8"
    )
    return _expect_reported(
        verify_dir(directory, "segment-index.json"),
        "does not match files on disk",
        "an index naming a segment that is not on disk",
    )


def _case_unreadable_index(root: str) -> list[str]:
    """An index that cannot be read is an error, not a silent "no index"."""
    directory = _segment_dir(root)
    stream = _stream(2)
    _write_segment(directory, "evidence-2026-09-28-1.jsonl", stream)
    index = directory / "segment-index.json"
    errs: list[str] = []
    for body, needle, what in (
        ("{", "unparseable", "an unparseable index"),
        ("[]", "must be a JSON object", "a non-object index"),
    ):
        index.write_text(body, encoding="utf-8")
        errs += _expect_reported(verify_dir(directory, "segment-index.json"), needle, what)
    return errs


def _case_absent_index(root: str) -> list[str]:
    """No index is the normal case and must stay quiet."""
    directory = _segment_dir(root)
    index, load_errs = load_index(directory / "segment-index.json")
    if index is not None or load_errs:
        return [f"self-test: a missing index was not reported as absent: {index} {load_errs}"]
    return []


def _case_no_segments(root: str) -> list[str]:
    directory = _segment_dir(root)
    return _expect_reported(
        verify_dir(directory, "segment-index.json"),
        "no evidence-*.jsonl",
        "a directory with no segments",
    )


def _reports(found: list[str], needle: str) -> bool:
    return any(needle in error for error in found)


def main() -> int:
    report_text.safe_report_streams()
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
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
    ap.print_help(sys.stderr)
    return USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
