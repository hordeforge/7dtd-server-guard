"""Copy an evidence directory to an archive and prove the copy is restorable.

An evidence directory is the only record of what a detector did and why an
operator acted. The store is append-only JSONL segments plus a segment index on
the server's local disk (SCHEMAS.md -> Evidence stream), it is gitignored, and
retention expiry deletes segments. A backup that is never verified is a
hypothesis, so this tool refuses to copy anything it cannot verify first:

  export  verify the hash chain, copy every segment and the index, re-hash the
          copies, and write manifest.json describing exactly what was archived.
          A chain error, an empty copy, or a byte mismatch aborts before any
          archive is declared complete.
  verify  re-check an existing archive against its manifest and re-verify the
          chain inside it. This is the restore drill: an archive that passes
          can be copied back into place and read.

Secrets are never archived here. The identity map and the HMAC key live outside
the evidence directory (SCHEMAS.md config keys identityMap.path and
hmacKey.path) and are backed up separately, by the procedure in
docs/OPERATIONS.md -> Backup and restore. Archiving a pseudonym key beside the
records it unmasks would hand one stolen copy both halves.

Usage:
  uv run python tools/evidence_export.py --dir <evidence-dir> --out <archive-root>
  uv run python tools/evidence_export.py --archive <archive-dir>
  uv run python tools/evidence_export.py --self-test
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import shutil
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import evidence_check as ec

Record = dict[str, Any]
# One archived file: the manifest entry, keyed by file name.
ManifestFile = dict[str, Any]

MANIFEST_NAME = "archive-manifest.json"
MANIFEST_VERSION = 2
# The manifest's self-digest field, and the canonicalization the digest covers:
# every field except the digest itself, so a byte edited anywhere in the manifest
# (a source path, the creation stamp, a count) is detectable. The per-file
# SHA-256s prove the archived bytes; this proves the attestation describing them.
MANIFEST_DIGEST_FIELD = "manifestSha256"
SEGMENT_GLOB = "evidence-*.jsonl"
DEFAULT_INDEX_NAME = ec.DEFAULT_INDEX
# Read/write block size for copying and hashing, so archive size does not set the
# process's memory ceiling.
COPY_CHUNK_BYTES = 1 << 20


def utc_stamp() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")


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
    """Non-empty lines in a segment. Streamed, not slurped, so a large segment
    does not set this process's memory ceiling (the property file_digest keeps).
    Text-mode iteration splits on the newline every writer of a JSONL segment
    uses, and a truncated final line still counts as the record it was."""
    with path.open("r", encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


def archive_members(source: pathlib.Path, index_name: str) -> list[pathlib.Path]:
    """The files an archive must contain: every segment, plus the index when present."""
    members = sorted(source.glob(SEGMENT_GLOB))
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
    source: pathlib.Path, dest: pathlib.Path, created_utc: str, index_name: str
) -> dict[str, Any]:
    """Describe what was copied, from the copies (not from the source) so the
    manifest records what a restore would actually read."""
    files: list[ManifestFile] = []
    for name in sorted(p.name for p in dest.iterdir() if p.is_file() and p.name != MANIFEST_NAME):
        path = dest / name
        sha, size = file_digest(path)
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
    empty = [
        f"{m.name}: zero-byte file; a zero-byte segment is a failed write, not a backup"
        for m in members
        if m.stat().st_size == 0
    ]
    if empty:
        return [], empty
    return members, []


def copy_verified(members: list[pathlib.Path], staging: pathlib.Path) -> list[str]:
    """Copy each member and prove the copy is byte-identical to the source."""
    errs: list[str] = []
    for member in members:
        target = staging / member.name
        shutil.copy2(member, target)
        if file_digest(member) != file_digest(target):
            errs.append(f"{member.name}: copy does not match the source")
    return errs


def stage(
    staging: pathlib.Path, source: pathlib.Path, members: list[pathlib.Path], index_name: str
) -> list[str]:
    """Fill the staging directory and prove it is a restorable archive."""
    copy_errors = copy_verified(members, staging)
    if copy_errors:
        return copy_errors
    created_utc = staging.name.removeprefix(".staging-").removeprefix("evidence-")
    manifest = build_manifest(source, staging, created_utc, index_name)
    if not manifest["totalBytes"] or not manifest["totalRecords"]:
        return [f"{source}: archive would be empty; refusing to record a zero-byte backup"]
    (staging / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    # The archive is only declared complete once the copies themselves verify.
    return [f"archive did not verify: {e}" for e in verify(staging)]


def export(
    source: pathlib.Path, out_root: pathlib.Path, index_name: str, stamp: str | None = None
) -> list[str]:
    """Verify, copy, and manifest. Returns errors; empty means the archive is
    complete and verified. Nothing is written when verification fails.

    `stamp` names the archive and defaults to the current second. It is a
    parameter rather than a direct utc_stamp() call so a caller that must hit
    the overwrite refusal, which is keyed on that name, can say which name it
    means instead of depending on where the clock happens to be. The name
    carries a one-second timestamp, so two exports into the same root inside
    one second are refused as a collision; a caller that has to exercise that
    refusal (the self-test) passes the same stamp rather than depending on
    where the second boundary falls.
    """
    members, errs = preflight(source, index_name)
    if errs:
        return errs

    dest = out_root / f"evidence-{stamp if stamp is not None else utc_stamp()}"
    out_root.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return [f"{dest}: archive already exists; refusing to overwrite an existing archive"]
    staging = out_root / f".staging-{dest.name}"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    try:
        staging_errors = stage(staging, source, members, index_name)
        if staging_errors:
            return staging_errors
        staging.rename(dest)
    except OSError as exc:
        return [f"archive failed: {exc}"]
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return []


def _is_size(value: object) -> bool:
    """A byte count is a non-negative integer. bool is excluded: `true` is not 1 byte."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_int(value: object) -> bool:
    """True for a JSON integer. A bool is an int subclass and is not a byte count."""
    return isinstance(value, int) and not isinstance(value, bool)


def _member_errors(archive: pathlib.Path, entry: object) -> list[str]:
    """What one manifest file entry claims about its file, against the bytes on disk."""
    if not isinstance(entry, dict) or not ec.valid_file_name(entry.get("name")):
        return [f"{MANIFEST_NAME}: malformed file entry"]
    name = entry["name"]
    path = ec.exact_child(archive, name)
    if path is None or not path.is_file():
        return [f"{name}: listed in the manifest but missing from the archive"]
    sha, size = file_digest(path)
    if sha != entry.get("sha256"):
        return [f"{name}: sha256 mismatch (archive is corrupt or was edited)"]
    if size != entry.get("bytes"):
        return [f"{name}: byte count mismatch ({size} vs {entry.get('bytes')})"]
    if entry.get("records") is None:
        return []
    records = _record_count(path)
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
            f"{MANIFEST_NAME}: {MANIFEST_DIGEST_FIELD} does not match the manifest; "
            "the attestation itself was edited or is truncated"
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
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [f"{MANIFEST_NAME}: unreadable: {exc}"]
    if not isinstance(manifest, dict):
        return [f"{MANIFEST_NAME}: manifest is not a JSON object"]
    attestation = _attestation_errors(manifest)
    if attestation:
        return attestation
    entries = manifest["files"]
    index_name = manifest.get("indexFile") or DEFAULT_INDEX_NAME

    errs: list[str] = []
    listed: set[str] = set()
    for entry in entries:
        if (
            isinstance(entry, dict)
            and ec.valid_file_name(entry.get("name"))
            and not _is_size(entry.get("bytes"))
        ):
            # The manifest is untrusted text, so a byte count that is not a
            # non-negative integer is reported as a malformed entry. Summing it
            # would raise out of the verifier instead of naming the bad entry.
            errs.append(
                f"{MANIFEST_NAME}: file entry for {entry['name']} has no integer byte count"
            )
            listed.add(entry["name"])
            continue
        errs += _member_errors(archive, entry)
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            listed.add(entry["name"])
    present = {p.name for p in archive.glob(SEGMENT_GLOB)} | {
        p.name for p in archive.glob("*.json") if p.name != MANIFEST_NAME
    }
    errs.extend(
        f"{name}: present in the archive but not in the manifest"
        for name in sorted(present - listed)
    )
    for field in ("bytes", "records"):
        if _entry_total(entries, field) != manifest.get(f"total{field.capitalize()}"):
            errs.append(f"total{field.capitalize()} does not match the sum of its file entries")
    errs += [f"chain: {e}" for e in ec.verify_dir(archive, index_name)]
    return errs


def _write_sample_stream(source: pathlib.Path) -> pathlib.Path:
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
    stamp = "20260721T000000Z"
    if export(source, out_root, DEFAULT_INDEX_NAME, stamp=stamp):
        errs.append("self-test: export of a valid chain reported errors")
    archives = sorted(p for p in out_root.iterdir() if p.is_dir())
    if len(archives) != 1:
        return [*errs, "self-test: export did not produce exactly one archive"], archives
    if verify(archives[0]):
        errs.append("self-test: fresh archive did not verify")
    # A second export under the same archive name must refuse, not overwrite. The
    # name is pinned rather than left to the clock, or the case only runs when two
    # exports happen to land in the same second and silently stops testing anything.
    if not export(source, out_root, DEFAULT_INDEX_NAME, stamp=stamp):
        errs.append("self-test: a same-second export overwrote a live archive")
    if sorted(p for p in out_root.iterdir() if p.is_dir()) != archives:
        errs.append("self-test: a refused export still left a new archive behind")
    errs += [
        f"self-test: a refused export disturbed the live archive {archive.name}"
        for archive in archives
        if not archive.is_dir() or verify(archive)
    ]
    return errs, archives


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
        _write_sample_stream(scratch)
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


def self_test() -> list[str]:
    """Exercise the paths that decide whether a backup is trustworthy."""
    scratch = ec.ROOT / ".scratch" / "evidence-export-self-test"
    shutil.rmtree(scratch, ignore_errors=True)
    source = scratch / "source"
    out_root = scratch / "archives"
    seg2 = _write_sample_stream(source)
    errs, archives = _self_test_happy_path(source, out_root)
    errs += _self_test_refusal(scratch, source, out_root)
    errs += _self_test_member_names()
    errs += _self_test_manifest_bytes()
    if archives:
        errs += _self_test_case_variant_name(archives[0])
        errs += _self_test_corrupt_archive(archives[0], archives[0] / seg2.name)
    shutil.rmtree(scratch, ignore_errors=True)
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true", help="run the archive self-tests and exit")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dir", type=pathlib.Path, help="evidence directory to archive")
    mode.add_argument("--archive", type=pathlib.Path, help="archive directory to verify")
    ap.add_argument("--out", type=pathlib.Path, help="archive root; a timestamped dir is created")
    ap.add_argument("--index", default="segment-index.json", help="segment index file name")
    args = ap.parse_args()

    if args.self_test:
        errs = self_test()
        print(f"evidence-export self-test: {len(errs)} failure(s)")
        for e in errs:
            print("  " + e)
        return 1 if errs else 0

    if args.archive:
        errs = verify(args.archive)
        print(f"archive {args.archive}: {len(errs)} issue(s)")
        for e in errs:
            print("  " + e)
        return 1 if errs else 0

    if args.dir:
        if args.out is None:
            print("usage: --dir requires --out <archive-root>")
            return 2
        errs = export(args.dir, args.out, args.index)
        print(f"export {args.dir}: {len(errs)} issue(s)")
        for e in errs:
            print("  " + e)
        return 1 if errs else 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
