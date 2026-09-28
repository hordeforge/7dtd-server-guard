"""Copy an evidence directory to an archive and prove the copy is restorable.

An evidence directory is the only record of what a detector did and why an
operator acted. The store is append-only JSONL segments plus a segment index on
the server's local disk (SCHEMAS.md -> Evidence stream), it is gitignored, and
retention expiry deletes segments. A backup that is never verified is a
hypothesis, so this tool refuses to copy anything it cannot verify first:

  export  verify the hash chain, copy every segment and the index, re-hash the
          copies, and write archive-manifest.json describing exactly what was
          archived: a per-file SHA-256 and byte count, a record count for the
          segments, and a manifestSha256 over the manifest's own remaining
          fields. A chain error, an empty copy, or a byte mismatch aborts before
          any archive is declared complete. A retry of an export whose archive name
          the previous second already claimed converges on that archive when it
          holds the same evidence, and is refused when it does not. The same rule
          settles two exports naming one archive at once, so the one that loses
          that race does not report a backup that is present and verified as
          failed.
  verify  re-check an existing archive against its manifest and re-verify the
          chain inside it. This is the restore drill: an archive that passes
          can be copied back into place and read. A manifestVersion 1 archive
          carries no self-digest and is reported as an unsupported version.

Secrets are never archived here. The identity map and the HMAC key live outside
the evidence directory (SCHEMAS.md config keys identityMap.path and
hmacKey.path) and are backed up separately, by the procedure in
docs/OPERATIONS.md -> Backup and restore. Archiving a pseudonym key beside the
records it unmasks would hand one stolen copy both halves.

Exit codes: 0 verified, 1 the archive or export failed, 2 usage error. A verdict
goes to stdout and the detail to stderr, so a redirected run records the verdict
alone.

Usage:
  uv run python tools/evidence_export.py --dir <evidence-dir> --out <archive-root>
  uv run python tools/evidence_export.py --archive <archive-dir>
  uv run python tools/evidence_export.py --self-test
  make self-test TOOL=evidence_export                   the same, through the task runner
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import shutil
import sys
import tempfile
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import evidence_check as ec
import report_text

Record = dict[str, Any]
# One archived file: the manifest entry, keyed by file name.
ManifestFile = dict[str, Any]

MANIFEST_NAME = "archive-manifest.json"
MANIFEST_VERSION = 2
# The archive-name stamp: the format the writer emits and the two readers that
# read a stamp back out of a manifest have to agree on, so it is stated once.
STAMP_FORMAT = "%Y%m%dT%H%M%SZ"
# The name an archive directory carries in its root, before the stamp. Every
# staging directory is named from it, so the sweep below can match the leftovers
# of a run that died at any second rather than only at this export's own.
ARCHIVE_DIR_PREFIX = "evidence-"
STAGING_PREFIX = f".staging-{ARCHIVE_DIR_PREFIX}"
# The manifest's self-digest field, and the canonicalization the digest covers:
# every field except the digest itself, so a byte edited anywhere in the manifest
# (a source path, the creation stamp, a count) is detectable. The per-file
# SHA-256s prove the archived bytes; this proves the attestation describing them.
MANIFEST_DIGEST_FIELD = "manifestSha256"
# A segment is whatever the chain verifier calls one, spelled in one place there.
SEGMENT_GLOB = ec.SEGMENT_GLOB
# A raw line separator inside a record's text. `str.splitlines()` treats it as a
# line break and the chain reader's line iteration does not, which is the whole
# reason the record count is not computed with splitlines (see _record_count).
RAW_LINE_SEP = "\u2028"
DEFAULT_INDEX_NAME = ec.DEFAULT_INDEX
# Read/write block size for copying and hashing, so archive size does not set the
# process's memory ceiling.
COPY_CHUNK_BYTES = 1 << 20
# Archive-name stamp the self-tests pin, so a name collision under test is a
# property of the export guard and not of when the test happened to run.
SELF_TEST_STAMP = "20260723T120000Z"
# A staged archive is verified and renamed inside one export, so a staging
# directory older than this belongs to a run that died. Without the bound a
# killed run would leave one directory behind per death, forever.
STALE_STAGING_AGE_SECONDS = 24 * 60 * 60
# The instant the staging self-test ages its leftovers against, so what the sweep
# sweeps is a property of the export guard and not of when the test happened to
# run. Pinned alongside the stamp the same self-test exports under.
SELF_TEST_NOW = dt.datetime.strptime(SELF_TEST_STAMP, STAMP_FORMAT).replace(tzinfo=dt.UTC)


def as_utc(moment: dt.datetime, what: str) -> dt.datetime:
    """`moment` as an aware UTC instant, refusing a naive one.

    A naive datetime is server-local wall time, and every stamp here carries a
    `Z`: formatting one as UTC persists an instant that is wrong by the host's
    offset, an offset that is not even the same in winter and in summer in a DST
    zone. `.timestamp()` on one is the same defect seen from the other side, a
    cutoff that moves with the host's `TZ`. The archive name, the manifest's
    `createdUtc`, and the staging sweep all read the clock through here, so they
    cannot disagree about which instant it was.
    """
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError(f"{what} must be an aware datetime; a naive one is local wall time")
    return moment.astimezone(dt.UTC)


def utc_stamp(now: dt.datetime | None = None) -> str:
    """The archive-name stamp for `now`, or the wall clock's second when omitted.

    An explicit instant is how a caller names a second it means rather than
    depending on where the clock is, which is what a replay of a run or a
    self-test that must land on the same name twice needs. An instant from
    another zone is converted, so the `Z` in the name is the one the string
    claims to be.
    """
    return as_utc(now or dt.datetime.now(dt.UTC), "now").strftime(STAMP_FORMAT)


def file_digest(path: pathlib.Path) -> tuple[str, int]:
    """Return (sha256 hex, byte count) for a file, read in chunks."""
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as fh:
        while chunk := fh.read(COPY_CHUNK_BYTES):
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def _record_count(path: pathlib.Path) -> int:
    """The record count the chain verifier would see in this segment.

    The count was `str.splitlines()` over the whole text, which breaks on more
    boundaries than the chain reader's line iteration does: `\x0c`, `\u2028`, and
    friends. A record carrying one of those inside a string (a hand-edited note)
    parses as one record for `iter_records` but counted as two, so the manifest
    attested a count the stream did not hold. Reading the file the way the
    verifier does, counting the lines it would keep, is one definition of a
    record.

    Streamed, not slurped, so a large segment does not set this process's
    memory ceiling (the property file_digest keeps). A truncated final line
    still counts as the record it was.
    """
    with path.open(encoding="utf-8") as handle:
        return sum(1 for raw in handle if raw.strip())


def archive_members(source: pathlib.Path, index_name: str) -> list[pathlib.Path]:
    """The files an archive must contain: every segment, plus the index when present.

    Segments come in the order the chain links them, the same order
    `verify_dir` walks them, so an archive and the walk that checks it agree on
    what the first record of a restore is.
    """
    members = sorted(source.glob(SEGMENT_GLOB), key=ec.segment_sort_key)
    index = source / index_name
    if index.is_file():
        members.append(index)
    return members


def manifest_digest(manifest: dict[str, Any]) -> str:
    """The SHA-256 over the manifest's canonical form, digest field excluded."""
    covered = {k: v for k, v in manifest.items() if k != MANIFEST_DIGEST_FIELD}
    canonical = json.dumps(covered, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_manifest(
    source: pathlib.Path,
    dest: pathlib.Path,
    created_utc: str,
    index_name: str,
    digests: dict[str, tuple[str, int]] | None = None,
) -> dict[str, Any]:
    """Describe what was copied, from the copies (not from the source) so the
    manifest records what a restore would actually read.

    `digests` carries the sha256 and byte count a caller already computed over the
    staged copies (`copy_verified` hashes both sides of every copy it makes, and
    only reaches here when they matched). Passing them back saves re-reading the
    whole archive; a name absent from the map is digested here as before.
    """
    known = digests or {}
    files: list[ManifestFile] = []
    for name in sorted(p.name for p in dest.iterdir() if p.is_file() and p.name != MANIFEST_NAME):
        path = dest / name
        sha, size = known.get(name) or file_digest(path)
        entry: ManifestFile = {"name": name, "sha256": sha, "bytes": size}
        if path.suffix == ".jsonl":
            entry["records"] = _record_count(path)
        files.append(entry)
    manifest: dict[str, Any] = {
        "manifestVersion": MANIFEST_VERSION,
        "createdUtc": created_utc,
        "sourceDir": str(source),
        "indexFile": index_name if (source / index_name).is_file() else None,
        "canonicalization": "json.dumps(record, sort_keys=True, separators=(',', ':'), "
        "ensure_ascii=True); chainPrev is the sha256 of the previous record's canonical form",
        "files": files,
        "totalBytes": sum(int(f["bytes"]) for f in files),
        "totalRecords": sum(int(f.get("records", 0)) for f in files),
    }
    manifest[MANIFEST_DIGEST_FIELD] = manifest_digest(manifest)
    return manifest


def preflight(source: pathlib.Path, index_name: str) -> tuple[list[pathlib.Path], list[str]]:
    """Decide whether a directory may be archived at all. Returns (members, errors);
    a non-empty error list means nothing gets written."""
    if not source.is_dir():
        return [], [f"{source}: no such evidence directory"]
    chain_errors = ec.verify_dir(source, index_name)
    if chain_errors:
        return [], [f"refusing to archive a chain that does not verify: {e}" for e in chain_errors]
    members = archive_members(source, index_name)
    if not members:
        return [], [f"{source}: no {SEGMENT_GLOB} segments to archive"]
    try:
        empty = [
            f"{m.name}: zero-byte file; a zero-byte segment is a failed write, not a backup"
            for m in members
            if m.stat().st_size == 0
        ]
    except OSError as exc:
        return [], [f"archive failed: {members[0].parent}: {exc}"]
    if empty:
        return [], empty
    return members, []


def copy_verified(
    members: list[pathlib.Path], staging: pathlib.Path
) -> tuple[list[str], dict[str, tuple[str, int]]]:
    """Copy each member and prove the copy is byte-identical to the source.

    Returns the errors and the digest of every staged copy. The digest is of the
    copy, not the source, and is what `build_manifest` records; both sides were
    just read to compare them, so returning it saves the manifest a second full
    pass over the archive.
    """
    errs: list[str] = []
    digests: dict[str, tuple[str, int]] = {}
    for member in members:
        target = staging / member.name
        shutil.copy2(member, target)
        source_digest = file_digest(member)
        target_digest = file_digest(target)
        digests[member.name] = target_digest
        if source_digest != target_digest:
            errs.append(f"{member.name}: copy does not match the source")
    return errs, digests


def stage(
    staging: pathlib.Path,
    source: pathlib.Path,
    members: list[pathlib.Path],
    index_name: str,
    created_utc: str,
) -> list[str]:
    """Fill the staging directory and prove it is a restorable archive."""
    copy_errors, digests = copy_verified(members, staging)
    if copy_errors:
        return copy_errors
    manifest = build_manifest(source, staging, created_utc, index_name, digests)
    if not manifest["totalBytes"] or not manifest["totalRecords"]:
        return [f"{source}: archive would be empty; refusing to record a zero-byte backup"]
    (staging / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    # The archive is only declared complete once the copies themselves verify.
    return [f"archive did not verify: {e}" for e in verify(staging)]


def archive_file_names(archive: pathlib.Path) -> set[str]:
    """The names an archive's own contents claim, ignoring the manifest itself.

    A redo and a verify both ask this: which files are here, as opposed to which
    the manifest says. The manifest is excluded, so a stale or forged one cannot
    add a name to its own set.
    """
    return {p.name for p in archive.glob(SEGMENT_GLOB)} | {
        p.name for p in archive.glob("*.json") if p.name != MANIFEST_NAME
    }


def redo_errors(dest: pathlib.Path, members: list[pathlib.Path]) -> list[str]:
    """What stops a re-run of the same export from being a no-op.

    The archive name carries a one-second stamp, so a retried export lands on the
    directory the first attempt already wrote. The retry has to converge on that
    directory when it holds exactly the members this run would copy, byte for
    byte: the first attempt's verified archive *is* the result this run would
    produce, and reporting a refusal would turn a delivered backup into a
    non-zero exit, which the runbook (OPERATIONS.md -> Schedule) alerts on. An
    archive holding a different evidence set is a different export, and the
    second must not overwrite the first.
    """
    archived = archive_file_names(dest)
    if archived != {m.name for m in members}:
        return [
            (
                f"{dest}: an archive for this second holds a different evidence set; "
                "refusing to overwrite an existing archive"
            )
        ]
    diverged = [m.name for m in members if file_digest(m) != file_digest(dest / m.name)]
    if diverged:
        return [
            (
                f"{dest}: archived {', '.join(sorted(diverged))} differ from the source; "
                "refusing to overwrite an existing archive"
            )
        ]
    return []


def _sweep_stale_staging(
    out_root: pathlib.Path, now: dt.datetime, keep: pathlib.Path | None = None
) -> None:
    """Remove staging directories a dead run left behind, this run's excepted.

    Each export stages into its own directory, so a concurrent export cannot
    delete a copy in progress: only a directory older than
    STALE_STAGING_AGE_SECONDS is swept, and a live run's is younger than that.
    The leftovers of a killed run would otherwise accumulate in the archive
    root, each holding a full copy of the evidence stream, so a run older than
    STALE_STAGING_AGE_SECONDS is swept.

    The match is on STAGING_PREFIX alone, not on one archive's name: an archive
    name carries a one-second stamp, so a match on it would only ever see the
    leftovers of a run that died in the same second as this one, and every other
    killed run would stay in the archive root forever.

    `now` is the instant the age is measured against, passed in by the caller so
    a replay of a run sweeps the same directories it swept the first time. It
    must be aware: an mtime is an absolute epoch, so a naive cutoff would be
    read against the host's `TZ` and the same replay would sweep a different set
    of directories on a server set to a local zone.
    """
    cutoff = as_utc(now, "now").timestamp() - STALE_STAGING_AGE_SECONDS
    for path in out_root.glob(f"{STAGING_PREFIX}*"):
        if path == keep or not path.is_dir():
            continue
        try:
            if path.stat().st_mtime < cutoff:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            continue


def _rename_into_place(
    staging: pathlib.Path, dest: pathlib.Path, members: list[pathlib.Path]
) -> list[str]:
    """Claim `dest` for this run's staged archive, or converge on the run that claimed it.

    The redo check above is a read followed by a write, so two exports naming the
    same archive can both see it absent. The loser of that race fails the rename
    with the directory already there, and reporting that raw failure would turn a
    backup that is present and verified into a non-zero exit the schedule alerts
    on, which is what the redo check exists to prevent. So the race is decided by
    the same rule the check applies: the run that finds the name holding exactly
    the evidence it would have written reports success, and the one that finds a
    different evidence set is refused with the reason the check would have given.
    """
    try:
        staging.rename(dest)
    except OSError as exc:
        if dest.exists():
            return redo_errors(dest, members)
        return [f"archive failed: {exc}"]
    return []


def export(
    source: pathlib.Path,
    out_root: pathlib.Path,
    index_name: str,
    stamp: str | None = None,
    now: dt.datetime | None = None,
) -> list[str]:
    """Verify, copy, and manifest. Returns errors; empty means the archive is
    complete and verified. Nothing is written when verification fails. A retry of
    a run whose archive already exists is a no-op, not a failure.

    The archive is named after `stamp`, defaulting to the current second. An
    explicit stamp names an archive rather than timestamping one, so a caller
    that must land twice on the same name, which is what a retry does and what
    the redo check is keyed on, says which name it means instead of depending
    on where the clock happens to be. The name carries a one-second timestamp, so
    two exports into the same root inside one second meet the redo check; the
    self-test passes the same stamp rather than depending on where the second
    boundary falls.

    `now` is the same seam for the instant the stale-staging sweep ages
    leftovers against, which the export reads off the clock twice otherwise:
    once to name this archive and once to decide what a dead run left behind. A
    caller replaying a run passes the instant it is replaying, and the export
    names the same archive and sweeps the same directories. It must be aware:
    `as_utc` refuses a naive one rather than reading it as server-local time.
    """
    members, errs = preflight(source, index_name)
    if errs:
        return errs

    # One instant and one stamp, each named once: the stamp is the archive
    # directory's name and the manifest's createdUtc, and deriving it twice let
    # the two drift apart.
    moment = as_utc(now, "now") if now is not None else dt.datetime.now(dt.UTC)
    label = stamp if stamp is not None else utc_stamp(moment)
    dest = out_root / f"{ARCHIVE_DIR_PREFIX}{label}"
    out_root.mkdir(parents=True, exist_ok=True)
    # Swept before the redo check, not after staging: the runs that die are the
    # ones whose preflight or copy failed, and a sweep those paths skipped left
    # a full copy of the evidence stream in the root per death. The stamp is
    # kept in the directory name so a human reading the root can tell which run
    # a leftover belongs to; the sweep matches on STAGING_PREFIX, which carries
    # no stamp, so it reaches the leftovers of every earlier run.
    _sweep_stale_staging(out_root, now=moment)
    if dest.exists():
        return redo_errors(dest, members)
    staging = pathlib.Path(tempfile.mkdtemp(prefix=f"{STAGING_PREFIX}{label}-", dir=out_root))
    _sweep_stale_staging(out_root, now=moment, keep=staging)
    try:
        staging_errors = stage(staging, source, members, index_name, label)
        if staging_errors:
            return staging_errors
        return _rename_into_place(staging, dest, members)
    except OSError as exc:
        return [f"archive failed: {exc}"]
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _is_size(value: object) -> bool:
    """A byte count is a non-negative integer. bool is excluded: `true` is not 1 byte."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_int(value: object) -> bool:
    """True for a JSON integer. A bool is an int subclass and is not a byte count."""
    return isinstance(value, int) and not isinstance(value, bool)


def _read_member(
    members: dict[str, pathlib.Path], name: str, records: int | None
) -> tuple[str, int, int | None] | str:
    """(sha256, bytes, records) for a named member, or the message naming why not.

    A restore drill runs against whatever survived the disk, so a member the
    filesystem refuses to read, or one the server wrote with a truncated multi-byte
    sequence, is an answer the report carries. A traceback out of the verifier names
    no file and leaves every other entry unchecked.

    `members` is the archive's own listing, taken once, and `records` the count the
    chain walk already computed for a segment; a member the walk did not reach is
    counted here, since its own number is the one that answers for it.
    """
    try:
        path = members.get(name)
        if path is None or not path.is_file():
            return f"{name}: listed in the manifest but missing from the archive"
        sha, size = file_digest(path)
        if path.suffix != ".jsonl":
            records = None
        elif records is None:
            records = _record_count(path)
    except (OSError, UnicodeDecodeError) as exc:
        return f"{name}: unreadable: {exc}"
    return sha, size, records


def _entry_name(entry: object) -> str | None:
    """The file name a manifest entry claims, or None when the entry is unusable.

    One definition of "a manifest entry that names a file", so the callers that
    read a name (the byte check, the per-member check, the listed-name set) agree
    on which entries they accept.
    """
    if not isinstance(entry, dict):
        return None
    name = entry.get("name")
    return name if isinstance(name, str) and ec.valid_file_name(name) else None


def _member_errors(
    members: dict[str, pathlib.Path], counts: dict[str, int], entry: object
) -> list[str]:
    """What one manifest file entry claims about its file, against the bytes on disk."""
    name = _entry_name(entry)
    if name is None or not isinstance(entry, dict):
        return [f"{MANIFEST_NAME}: malformed file entry"]
    read = _read_member(members, name, counts.get(name))
    if isinstance(read, str):
        return [read]
    sha, size, records = read
    if sha != entry.get("sha256"):
        return [f"{name}: sha256 mismatch (archive is corrupt or was edited)"]
    if size != entry.get("bytes"):
        return [f"{name}: byte count mismatch ({size} vs {entry.get('bytes')})"]
    if entry.get("records") is None:
        return []
    return (
        []
        if records == entry["records"]
        else [f"{name}: record count mismatch ({records} vs {entry['records']})"]
    )


def _entry_total(entries: list[object], field: str) -> int:
    return sum(int(e[field]) for e in entries if isinstance(e, dict) and _is_int(e.get(field)))


def _attestation_errors(manifest: object) -> list[str]:
    """The manifest's own shape: version, self-digest, file list, index name.

    Checked before any file is read, so a manifest that cannot be trusted is not
    used to name what to read.
    """
    if not isinstance(manifest, dict) or manifest.get("manifestVersion") != MANIFEST_VERSION:
        return [f"{MANIFEST_NAME}: unsupported manifest version"]
    if manifest.get(MANIFEST_DIGEST_FIELD) != manifest_digest(manifest):
        return [
            (
                f"{MANIFEST_NAME}: {MANIFEST_DIGEST_FIELD} does not match the manifest; "
                "the attestation itself was edited or is truncated"
            )
        ]
    if not isinstance(manifest.get("files"), list) or not manifest["files"]:
        return [f"{MANIFEST_NAME}: no file list"]
    if not ec.valid_file_name(manifest.get("indexFile") or DEFAULT_INDEX_NAME):
        return [f"{MANIFEST_NAME}: indexFile is not a plain file name"]
    return []


def verify(archive: pathlib.Path) -> list[str]:
    """Re-check an archive against its manifest and re-verify its chain."""
    manifest_path = archive / MANIFEST_NAME
    if not manifest_path.is_file():
        return [f"{archive}: no {MANIFEST_NAME}"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [f"{MANIFEST_NAME}: unreadable: {exc}"]
    if not isinstance(manifest, dict):
        return [f"{MANIFEST_NAME}: manifest is not a JSON object"]
    attestation = _attestation_errors(manifest)
    if attestation:
        return attestation
    entries = manifest["files"]
    index_name = manifest.get("indexFile") or DEFAULT_INDEX_NAME

    # The chain walk runs first so the record counts it computes are available to
    # the per-member checks below; its findings are appended last, in the order
    # they were reported before. The archive's own listing is taken once and
    # looked up per member: re-listing the directory for every entry made the cost
    # of verifying an archive quadratic in its member count.
    chain_errors, counts = ec.verify_dir_with_counts(archive, index_name)
    members = ec.child_map(archive)

    errs: list[str] = []
    listed: set[str] = set()
    for entry in entries:
        name = _entry_name(entry)
        if name is not None and not _is_size(entry.get("bytes")):
            # The manifest is untrusted text, so a byte count that is not a
            # non-negative integer is reported as a malformed entry. Summing it
            # would raise out of the verifier instead of naming the bad entry.
            errs.append(f"{MANIFEST_NAME}: file entry for {name} has no integer byte count")
            listed.add(name)
            continue
        errs += _member_errors(members, counts, entry)
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            listed.add(entry["name"])
    present = archive_file_names(archive)
    errs.extend(
        f"{name}: present in the archive but not in the manifest"
        for name in sorted(present - listed)
    )
    for field in ("bytes", "records"):
        if _entry_total(entries, field) != manifest.get(f"total{field.capitalize()}"):
            errs.append(f"total{field.capitalize()} does not match the sum of its file entries")
    errs += [f"chain: {e}" for e in chain_errors]
    return errs


def write_sample_stream(source: pathlib.Path) -> pathlib.Path:
    """Two linked segments plus a segment index: the smallest real evidence dir."""
    source.mkdir(parents=True, exist_ok=True)
    recs: list[Record] = []
    prev = ec.GENESIS
    for i, kind in enumerate(["finding", "health", "audit"]):
        rec: Record = {
            "schemaVersion": 1,
            "type": kind,
            "eventId": f"0000000{i}-0000-4000-8000-00000000000{i}",
            "chainPrev": prev,
        }
        prev = ec.record_hash(rec)
        recs.append(rec)
    seg1 = source / "evidence-2026-07-21-000000.jsonl"
    seg2 = source / "evidence-2026-07-22-000000.jsonl"
    seg1.write_text("".join(ec.canonical(r) + "\n" for r in recs[:2]), encoding="utf-8")
    seg2.write_text(ec.canonical(recs[2]) + "\n", encoding="utf-8")
    (source / DEFAULT_INDEX_NAME).write_text(
        json.dumps({"segments": [{"file": seg1.name}, {"file": seg2.name}]}), encoding="utf-8"
    )
    return seg2


def _self_test_happy_path(
    source: pathlib.Path, out_root: pathlib.Path
) -> tuple[list[str], list[pathlib.Path]]:
    errs: list[str] = []
    # One fixed archive name for both exports: the collision refusal is a
    # same-second one, and reading the clock here made the case fail whenever the
    # second boundary happened to fall between the two calls.
    if export(source, out_root, DEFAULT_INDEX_NAME, SELF_TEST_STAMP, now=SELF_TEST_NOW):
        errs.append("self-test: export of a valid chain reported errors")
    archives = sorted(p for p in out_root.iterdir() if p.is_dir())
    if len(archives) != 1:
        return [*errs, "self-test: export did not produce exactly one archive"], archives
    if archives[0].name != f"evidence-{SELF_TEST_STAMP}":
        return [*errs, "self-test: export did not honor the requested stamp"], archives
    if verify(archives[0]):
        errs.append("self-test: fresh archive did not verify")
    # A retry naming the same archive must converge on it: no second directory,
    # no rewrite, no error. The stamp is pinned rather than taken from the clock,
    # so the retry lands on the archive the first call wrote instead of racing the
    # wall-clock second, and the redo check is the export guard's doing. Reporting
    # a refusal here would raise a backup alert for a backup that is present and
    # verified (OPERATIONS.md -> Schedule). The refusals themselves are the
    # divergence cases below.
    before = {p.name: file_digest(p) for p in archives[0].iterdir() if p.is_file()}
    redo = export(source, out_root, DEFAULT_INDEX_NAME, SELF_TEST_STAMP, now=SELF_TEST_NOW)
    if redo:
        errs.append(f"self-test: a retried export of the same evidence reported {redo}")
    if sorted(p for p in out_root.iterdir() if p.is_dir()) != archives:
        errs.append("self-test: a retried export left a new archive behind")
    after = {p.name: file_digest(p) for p in archives[0].iterdir() if p.is_file()}
    if after != before:
        errs.append("self-test: a retried export rewrote the archive that already existed")
    if verify(archives[0]):
        errs.append("self-test: a refused export disturbed the live archive")
    errs += _self_test_redo_divergence(source, out_root)
    return errs, archives


def _self_test_redo_divergence(source: pathlib.Path, out_root: pathlib.Path) -> list[str]:
    """A redo converges only on the evidence it would have copied.

    Two different evidence sets can land on the same one-second archive name.
    The second is a different export, so it must be refused rather than replace
    the archive an operator may already have copied off the server.
    """
    errs: list[str] = []
    archive = min(p for p in out_root.iterdir() if p.is_dir())
    other = archive.parent / "other-source"
    write_sample_stream(other)
    # Same file names, different bytes: the segment a restore would read differs.
    target = other / "evidence-2026-07-21-000000.jsonl"
    target.write_text(
        target.read_text(encoding="utf-8").replace('"type":"finding"', '"type":"health"'),
        encoding="utf-8",
    )
    members = archive_members(other, DEFAULT_INDEX_NAME)
    if not any("refusing to overwrite" in e for e in redo_errors(archive, members)):
        errs.append("self-test: a redo over different bytes was treated as a no-op")
    # A different evidence set, same second: also refused.
    extra = other / "evidence-2026-07-23-000000.jsonl"
    extra.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
    members = archive_members(other, DEFAULT_INDEX_NAME)
    if not any("refusing to overwrite" in e for e in redo_errors(archive, members)):
        errs.append("self-test: a redo over a different evidence set was treated as a no-op")
    # The evidence this run would have written converges.
    if redo_errors(archive, archive_members(source, DEFAULT_INDEX_NAME)):
        errs.append("self-test: a redo over the same evidence was refused")
    shutil.rmtree(other, ignore_errors=True)
    return errs


def _self_test_refusal(
    scratch: pathlib.Path, source: pathlib.Path, out_root: pathlib.Path
) -> list[str]:
    """A source whose chain does not verify is never copied."""
    errs: list[str] = []
    tampered = scratch / "tampered"
    shutil.copytree(source, tampered)
    target = tampered / "evidence-2026-07-21-000000.jsonl"
    lines = target.read_text(encoding="utf-8").splitlines()
    broken = json.loads(lines[0])
    broken["eventId"] = "99999999-0000-4000-8000-000000000009"
    lines[0] = ec.canonical(broken)
    target.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    before = sorted(p.name for p in out_root.iterdir())
    if not export(tampered, out_root, DEFAULT_INDEX_NAME):
        errs.append("self-test: export archived a chain that does not verify")
    if sorted(p.name for p in out_root.iterdir()) != before:
        errs.append("self-test: a refused export still wrote an archive")
    return errs


def _self_test_corrupt_archive(archive: pathlib.Path, seg2: pathlib.Path) -> list[str]:
    """A damaged or padded archive fails verification, and says which file."""
    errs: list[str] = []
    seg2.write_text(seg2.read_text(encoding="utf-8") + '{"x": 1}\n', encoding="utf-8")
    if not verify(archive):
        errs.append("self-test: verify accepted a corrupted archive")
    (archive / "evidence-2026-07-23-000000.jsonl").write_text("{}\n", encoding="utf-8")
    if not verify(archive):
        errs.append("self-test: verify accepted an archive with an unlisted file")
    errs += _self_test_edited_manifest(archive)
    return errs


def _self_test_edited_manifest(archive: pathlib.Path) -> list[str]:
    """An edited attestation is rejected, and so is one whose digest field is gone.

    The per-file SHA-256s prove the archived bytes but say nothing about the
    fields describing them, so a manifest edited in place (a rewritten source
    path, a corrected record count) would otherwise verify clean.
    """
    errs: list[str] = []
    path = archive / MANIFEST_NAME
    text = path.read_text(encoding="utf-8")
    before = verify(archive)
    try:
        manifest = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"self-test: exported manifest unreadable: {exc}"]
    manifest["totalRecords"] = 0
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not any(MANIFEST_DIGEST_FIELD in e for e in verify(archive)):
        errs.append("self-test: verify accepted an edited manifest")
    stripped = {k: v for k, v in manifest.items() if k != MANIFEST_DIGEST_FIELD}
    path.write_text(json.dumps(stripped, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not any(MANIFEST_DIGEST_FIELD in e for e in verify(archive)):
        errs.append("self-test: verify accepted a manifest with no self-digest")
    path.write_text(text, encoding="utf-8")
    if verify(archive) != before:
        errs.append("self-test: the restored manifest did not verify as it did before")
    return errs


def _self_test_member_names() -> list[str]:
    """The member-name allowlist is ASCII, and a lookalike spelling is not a member.

    A manifest is untrusted text that names files. A name spelled with characters
    outside ASCII (fullwidth Latin, Arabic-Indic digits, a combining mark) reads to
    an operator as a segment name it is not, so it must be reported rather than
    resolved; the names this tool writes are ASCII and must keep passing. A name a
    Windows host resolves to a device or strips a dot off is refused for the same
    reason: the archive has to name the same bytes on every host that restores it.
    """
    errs: list[str] = []
    accepted = [
        "evidence-2026-07-21-000000.jsonl",
        "segment-index.json",
        "archive-manifest.json",
    ]
    rejected = [
        "ｅｖｉｄｅｎｃｅ-2026-07-21.jsonl",  # noqa: RUF001 - fullwidth Latin
        "evidence-2026-07-21-٠٠٠٠٠٠.jsonl",  # noqa: RUF001 - Arabic-Indic digits
        "evidence-2026-07-21-00000é.jsonl",  # NFD: e + combining acute
        "evidence-2026-07-21-000000\U0001f600.jsonl",  # astral
        "evidence-2026-07-21-000000.jsonl ",  # trailing space
        "evidence-2026-07-21-000000.jsonl.",  # trailing dot: stripped by a Windows host
        "nul",  # Windows device stem, so also "nul.jsonl" below
        "nul.jsonl",
        "COM1.jsonl",
        "lpt9",
    ]
    errs.extend(
        f"self-test: archive member name rejected: {name!r}"
        for name in accepted
        if not ec.valid_file_name(name)
    )
    errs.extend(
        f"self-test: archive member name accepted that is not a plain portable file name: {name!r}"
        for name in rejected
        if ec.valid_file_name(name)
    )
    return errs


def _self_test_case_variant_name(archive: pathlib.Path) -> list[str]:
    """A manifest name that differs only in case is reported on every host.

    On a case-insensitive filesystem (NTFS, APFS) joining a name and opening it
    succeeds anyway, so an archive whose manifest names "EVIDENCE-..." would verify
    clean there and fail on a case-sensitive host. The name is matched against the
    archive's own entries, so the two hosts cannot disagree about what was
    archived.
    """
    errs: list[str] = []
    path = archive / MANIFEST_NAME
    text = path.read_text(encoding="utf-8")
    try:
        manifest = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"self-test: exported manifest unreadable: {exc}"]
    segment = next(e for e in manifest["files"] if e["name"].endswith(".jsonl"))
    segment["name"] = segment["name"].upper()
    manifest[MANIFEST_DIGEST_FIELD] = manifest_digest(manifest)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        found = verify(archive)
        if not any("missing from the archive" in e for e in found):
            errs.append(f"self-test: a case-variant member name verified: {found}")
    finally:
        path.write_text(text, encoding="utf-8")
    if verify(archive):
        errs.append("self-test: the restored manifest did not verify after the case-variant case")
    return errs


def _self_test_manifest_bytes() -> list[str]:
    """A manifest byte count that is not a non-negative integer is reported, not summed.

    A manifest is untrusted text, so its byte counts reach `int()` and the totals
    check. Summing a value that is not a number raises out of the verifier instead
    of naming the entry that is wrong.
    """
    errs: list[str] = []
    scratch = ec.ROOT / ".scratch" / "evidence-export-self-test-bytes"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        write_sample_stream(scratch)
        manifest = build_manifest(scratch, scratch, "20260721T000000Z", DEFAULT_INDEX_NAME)
        (scratch / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
        for bad, what in (
            (True, "a bool"),
            ("12", "a string"),
            (None, "null"),
            (-1, "a negative count"),
        ):
            manifest["files"][0]["bytes"] = bad
            # Reseal, or the self-digest check reports the edit and the byte count
            # this case exists to exercise is never read.
            manifest[MANIFEST_DIGEST_FIELD] = manifest_digest(manifest)
            (scratch / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
            try:
                found = verify(scratch)
            except Exception as exc:
                errs.append(
                    f"self-test: verify raised {type(exc).__name__} on {what} byte count: {exc}"
                )
                continue
            if not any("integer byte count" in e for e in found):
                errs.append(f"self-test: {what} byte count went unreported: {found}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def _self_test_record_count() -> list[str]:
    """A record count is the count the chain verifier sees.

    `str.splitlines()` breaks on more boundaries than the line iteration the chain
    reader uses, so a record holding a raw U+2028 in a string (a hand-edited note)
    is one record to the verifier and two to a splitlines count. The manifest
    would then attest a record count the stream does not hold.
    """
    errs: list[str] = []
    scratch = ec.ROOT / ".scratch" / "evidence-export-self-test-count"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        write_sample_stream(scratch)
        seg = scratch / "evidence-2026-07-21-000000.jsonl"
        rec = json.loads(seg.read_text(encoding="utf-8").splitlines()[0])
        rec["note"] = f"a{RAW_LINE_SEP}b"
        seg.write_text(ec.canonical(rec).replace(r"\u2028", RAW_LINE_SEP) + "\n", encoding="utf-8")
        counted = _record_count(seg)
        if counted != 1:
            errs.append(
                f"self-test: a segment with one record counted as {counted}: "
                "the manifest would attest a count the stream does not hold"
            )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def _self_test_unreadable_files() -> list[str]:
    """A file the filesystem refuses is named in the report, not raised out of it.

    A restore drill runs after the disk has already lost something, so an unreadable
    member or manifest is a case the verifier exists to report. A traceback names no
    file and leaves every other entry unchecked. The case runs only where a mode bit
    actually denies a read: a gate running as root cannot make the read fail, and
    there it is skipped rather than reported as a pass.
    """
    errs: list[str] = []
    scratch = ec.ROOT / ".scratch" / "evidence-export-self-test-unreadable"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        write_sample_stream(scratch)
        manifest = build_manifest(scratch, scratch, "20260721T000000Z", DEFAULT_INDEX_NAME)
        (scratch / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
        for path, what in (
            (scratch / manifest["files"][0]["name"], "an unreadable member"),
            (scratch / MANIFEST_NAME, "an unreadable manifest"),
        ):
            path.chmod(0o000)
            try:
                path.read_bytes()
            except OSError:
                pass
            else:
                path.chmod(0o600)
                continue
            try:
                found = verify(scratch)
            except Exception as exc:
                errs.append(f"self-test: verify raised {type(exc).__name__} on {what}: {exc}")
            else:
                if not any("unreadable" in e for e in found):
                    errs.append(f"self-test: {what} went unreported: {found}")
            finally:
                path.chmod(0o600)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def _self_test_stale_staging(source: pathlib.Path) -> list[str]:
    """A killed run's staging copy is swept by the next export, whatever second it
    died in, and a concurrent run's is not.

    The staging directory holds a full copy of the evidence stream, so one left in
    the archive root per killed run is a per-death leak in a root that is otherwise
    only ever read. A run that dies in the same second as a later export is swept by
    a name-keyed match; a run that dies in any other second never is. The sweep runs
    before the redo check as well as before the copy, so an export that converges on
    an archive it already wrote still cleans up after the runs that died.
    """
    errs: list[str] = []
    scratch = ec.ROOT / ".scratch" / "evidence-export-self-test-staging"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        out_root = scratch / "archives"
        out_root.mkdir(parents=True, exist_ok=True)
        stale = out_root / f"{STAGING_PREFIX}20260719T000000Z-abc"
        stale.mkdir()
        (stale / "half-copied-segment.jsonl").write_text('{"partial": true}\n', encoding="utf-8")
        # A second whose name no later export will ask for again, aged past the
        # window the sweep compares against.
        old = SELF_TEST_NOW.timestamp() - STALE_STAGING_AGE_SECONDS - 60
        os.utime(stale, (old, old))
        running = out_root / f"{STAGING_PREFIX}20991231T235959Z-live"
        running.mkdir()
        # A concurrent export stages at the same instant this one is replaying
        # at, so its directory is younger than the window and has to survive the
        # sweep. Both mtimes are set: read off the host clock they would be
        # seconds, not a day, either side of the pinned instant.
        moment = SELF_TEST_NOW.timestamp()
        os.utime(running, (moment, moment))

        if errs_found := export(
            source, out_root, DEFAULT_INDEX_NAME, SELF_TEST_STAMP, now=SELF_TEST_NOW
        ):
            errs.append(
                f"self-test: could not export into a root with staging leftovers: {errs_found}"
            )
        if stale.exists():
            errs.append(f"self-test: a dead run's staging directory {stale.name} was not swept")
        if not running.exists():
            errs.append(
                f"self-test: the sweep deleted the staging directory of a live run: {running}"
            )

        # The same root, swept on the run that converges on an archive it already
        # wrote. A scheduled export that keeps meeting its own redo check is the
        # run that keeps leaving a dead run's copy behind, since the copy is only
        # made by the runs that die.
        again = out_root / f"{STAGING_PREFIX}20260719T010000Z-def"
        again.mkdir()
        (again / "half-copied-segment.jsonl").write_text('{"partial": true}\n', encoding="utf-8")
        os.utime(again, (old, old))
        if errs_found := export(source, out_root, DEFAULT_INDEX_NAME, SELF_TEST_STAMP):
            errs.append(f"self-test: a re-run of a completed export reported {errs_found}")
        if again.exists():
            errs.append(
                f"self-test: a converged re-run left {again.name} behind; a root whose "
                "exports keep meeting the redo check never sweeps"
            )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def _self_test_rename_race(source: pathlib.Path) -> list[str]:
    """The export that loses the race for an archive name converges on the winner.

    Two exports naming the same archive can both find it absent, so the loser of
    the rename has to apply the redo rule itself. Reporting that as a failed
    archive would raise a backup alert for a backup that is present and verified.
    The race is not timed: the loser is staged and the winner's archive is already
    in place, which is the state the rename failure reports.
    """
    errs: list[str] = []
    scratch = ec.ROOT / ".scratch" / "evidence-export-self-test-race"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        out_root = scratch / "archives"
        if found := export(source, out_root, DEFAULT_INDEX_NAME, SELF_TEST_STAMP):
            return [f"self-test: could not build an archive: {found}"]
        dest = out_root / f"{ARCHIVE_DIR_PREFIX}{SELF_TEST_STAMP}"
        winner = {p.name: file_digest(p) for p in dest.iterdir() if p.is_file()}
        members = archive_members(source, DEFAULT_INDEX_NAME)
        staging = out_root / f"{STAGING_PREFIX}loser"
        staging.mkdir()
        (staging / "evidence-2026-07-21-000000.jsonl").write_text(
            (source / "evidence-2026-07-21-000000.jsonl").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        if found := _rename_into_place(staging, dest, members):
            errs.append(f"self-test: the export that lost the name race reported {found}")
        if {p.name: file_digest(p) for p in dest.iterdir() if p.is_file()} != winner:
            errs.append(
                "self-test: the export that lost the name race disturbed the winner's archive"
            )
        # A different evidence set under the same name is a different export, and
        # the race is not a way around that refusal.
        other = scratch / "other-source"
        write_sample_stream(other)
        (other / "evidence-2026-07-23-000000.jsonl").write_text(
            (other / "evidence-2026-07-21-000000.jsonl").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        stranger = out_root / f"{STAGING_PREFIX}stranger"
        stranger.mkdir()
        found = _rename_into_place(stranger, dest, archive_members(other, DEFAULT_INDEX_NAME))
        if not any("refusing to overwrite" in e for e in found):
            errs.append(f"self-test: losing the name race over other evidence reported {found}")
        shutil.rmtree(other, ignore_errors=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def _self_test_clock_zone(source: pathlib.Path) -> list[str]:
    """The stamp and the sweep read UTC, whichever zone the caller speaks from.

    A caller that hands over a local instant (a server configured for local time
    rather than UTC, or any code holding `datetime.now()`) gets a name and a
    `createdUtc` that are wrong by its offset, and a sweep that deletes by the
    host's `TZ`. The two instants below are 02:00 in Europe/Warsaw in January
    and in July, which is +01:00 and +02:00 in the zone database; a conversion
    that added one fixed offset instead of converting passes one and fails the
    other. The offsets are written out rather than read from the host's zone
    data, so the case runs the same on a host that ships no tzdata.
    """
    errs: list[str] = []
    scratch = ec.ROOT / ".scratch" / "evidence-export-self-test-zone"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        for wall, want in (
            ("2026-01-15T02:00:00+01:00", "20260115T010000Z"),
            ("2026-07-15T02:00:00+02:00", "20260715T000000Z"),
        ):
            moment = dt.datetime.fromisoformat(wall)
            got = utc_stamp(moment)
            if got != want:
                errs.append(f"self-test: a {wall} instant stamped {got}, not {want}")
            out_root = scratch / want
            out_root.mkdir(parents=True, exist_ok=True)
            if export_errs := export(source, out_root, DEFAULT_INDEX_NAME, now=moment):
                errs.append(f"self-test: export at {wall} reported {export_errs}")
            names = sorted(p.name for p in out_root.iterdir() if p.is_dir())
            if names != [f"{ARCHIVE_DIR_PREFIX}{want}"]:
                errs.append(f"self-test: an export at {wall} named the archive {names}")
            if not names:
                continue
            manifest = json.loads((out_root / names[0] / MANIFEST_NAME).read_text(encoding="utf-8"))
            if manifest.get("createdUtc") != want:
                errs.append(
                    f"self-test: createdUtc {manifest.get('createdUtc')!r} is not the UTC instant"
                )
        # A naive instant is the host's wall time, and a `Z` on it would persist
        # that wall time as UTC. It is refused rather than guessed at. The value
        # comes from the parser so it is naive by construction, which is the point
        # of the case and what DTZ001 would otherwise forbid writing.
        naive = dt.datetime.fromisoformat("2026-07-21T00:00:00")
        for label, call in (
            ("utc_stamp", lambda: utc_stamp(naive)),
            ("export", lambda: export(source, scratch / "naive", DEFAULT_INDEX_NAME, now=naive)),
        ):
            try:
                call()
            except ValueError:
                continue
            errs.append(f"self-test: {label} accepted a naive datetime as UTC")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def self_test() -> list[str]:
    """Exercise the paths that decide whether a backup is trustworthy."""
    scratch = ec.ROOT / ".scratch" / "evidence-export-self-test"
    shutil.rmtree(scratch, ignore_errors=True)
    try:
        source = scratch / "source"
        out_root = scratch / "archives"
        seg2 = write_sample_stream(source)
        errs, archives = _self_test_happy_path(source, out_root)
        errs += _self_test_refusal(scratch, source, out_root)
        errs += _self_test_stale_staging(source)
        errs += _self_test_rename_race(source)
        errs += _self_test_clock_zone(source)
        errs += _self_test_member_names()
        errs += _self_test_manifest_bytes()
        errs += _self_test_record_count()
        errs += _self_test_unreadable_files()
        if archives:
            errs += _self_test_case_variant_name(archives[0])
            errs += _self_test_corrupt_archive(archives[0], archives[0] / seg2.name)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return errs


def _report(summary: str, errs: list[str]) -> int:
    """Print the verdict on stdout and the detail on stderr, per tools/README.md."""
    print(summary)
    for e in errs:
        print("  " + e, file=sys.stderr)
    return 1 if errs else 0


def main() -> int:
    report_text.safe_report_streams()
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--self-test", action="store_true", help="run the archive self-tests and exit")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dir", type=pathlib.Path, help="evidence directory to archive")
    mode.add_argument("--archive", type=pathlib.Path, help="archive directory to verify")
    ap.add_argument("--out", type=pathlib.Path, help="archive root; a timestamped dir is created")
    ap.add_argument(
        "--index",
        default=DEFAULT_INDEX_NAME,
        help=f"segment index file name inside --dir (default: {DEFAULT_INDEX_NAME})",
    )
    args = ap.parse_args()

    if args.index != DEFAULT_INDEX_NAME and not args.dir:
        ap.error(
            "--index applies to --dir only; pass --dir or drop --index "
            f"(default {DEFAULT_INDEX_NAME})"
        )

    if args.self_test:
        errs = self_test()
        return _report(f"evidence-export self-test: {len(errs)} failure(s)", errs)

    if args.archive:
        errs = verify(args.archive)
        return _report(f"archive {args.archive}: {len(errs)} issue(s)", errs)

    if args.dir:
        if args.out is None:
            ap.error("--dir requires --out <archive-root>")
        errs = export(args.dir, args.out, args.index)
        return _report(f"export {args.dir}: {len(errs)} issue(s)", errs)

    ap.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
