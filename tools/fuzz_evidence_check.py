#!/usr/bin/env python3
"""Fuzz the evidence hash-chain parser (tools/evidence_check.py).

Evidence segments are server-generated files of unknown integrity; this harness
throws structure-aware mutations at every entry point that consumes them:

  target 1  load_records / record_hash / canonical   (per-record parsing + hashing)
  target 2  verify_dir end to end                    (segments + segment index)

Invariants asserted per iteration:
  - load_records either returns records or raises ValueError naming file:line;
    no other exception escapes.
  - Every accepted record canonicalizes round-trip (json.loads(canonical(r)) == r)
    and hashes to a 64-char lowercase hex sha256.
  - verify_dir never raises on any byte content; it returns a list of str and is
    deterministic across repeated runs on the same bytes.
  - Pair assertion across the persistence boundary: a valid chain built in memory,
    written canonically to disk, must read back and verify with zero errors.

Deterministic (seeded PRNG), stdlib only, no external fuzzer required.

Usage:
  python3 tools/fuzz_evidence_check.py [--iterations N] [--seed S]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import random
import string
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import evidence_check as ec  # noqa: E402
from fuzz_common import InvariantBroken, Mutator  # noqa: E402

SAMPLE = ec.ROOT / "config" / "schemas" / "evidence.v1.sample.jsonl"


def seed_records() -> list[dict]:
    recs = []
    for line in SAMPLE.read_text(encoding="utf-8").splitlines():
        if line.strip():
            recs.append(json.loads(line))
    # synthetic genesis + chained tail so both chain positions are represented
    first = {"schemaVersion": 1, "type": "health", "eventId": "fuzz-genesis",
             "chainPrev": ec.GENESIS}
    second = {"schemaVersion": 1, "type": "kill", "eventId": "fuzz-tail",
              "chainPrev": ec.record_hash(first)}
    return recs + [first, second]


def mutate_line_bytes(rng: random.Random, line: bytes) -> bytes:
    roll = rng.random()
    if roll < 0.10:
        return line[: max(0, len(line) // rng.randrange(2, 5))]
    if roll < 0.18:
        return b""
    if roll < 0.26:
        return b"\xef\xbb\xbf" + line
    if roll < 0.34:
        i = rng.randrange(max(1, len(line)))
        return line[:i] + bytes([rng.randrange(256)]) + line[i:]
    if roll < 0.42:
        return b"[1, 2, 3]\n"
    if roll < 0.50:
        return b"null\n"
    return line


def check_load_records(tmp: pathlib.Path, lines: list[bytes]) -> int:
    path = tmp / "seg.jsonl"
    path.write_bytes(b"\n".join(lines) + b"\n")
    try:
        records = ec.load_records(path)
    except ValueError as exc:
        if not str(exc).startswith(f"{path.name}:"):
            raise InvariantBroken(f"ValueError lacks file:line context: {exc!r}") from exc
        return 0
    except Exception as exc:  # noqa: BLE001
        raise InvariantBroken(f"load_records raised {type(exc).__name__}: {exc}") from exc
    for _, rec, _raw in records:
        canon = ec.canonical(rec)
        if json.loads(canon) != rec:
            raise InvariantBroken(f"canonical round-trip failed: {rec!r}")
        digest = ec.record_hash(rec)
        if len(digest) != 64 or digest != digest.lower() or not all(
            c in string.hexdigits for c in digest
        ):
            raise InvariantBroken(f"bad digest shape: {digest!r}")
    return len(records)


VALID_INDEX = {"segments": []}


def check_verify_dir(tmp: pathlib.Path, files: dict[str, bytes], index: bytes | None) -> list[str]:
    run = tempfile.mkdtemp(dir=tmp)  # fresh state per iteration
    run = pathlib.Path(run)
    for name, blob in files.items():
        (run / name).write_bytes(blob)
    if index is not None:
        (run / "segment-index.json").write_bytes(index)
    try:
        errs = ec.verify_dir(run, "segment-index.json")
    except Exception as exc:  # noqa: BLE001
        raise InvariantBroken(f"verify_dir raised {type(exc).__name__}: {exc}") from exc
    if not isinstance(errs, list) or not all(isinstance(e, str) for e in errs):
        raise InvariantBroken(f"verify_dir returned non-list-of-str: {errs!r}")
    again = ec.verify_dir(run, "segment-index.json")
    if again != errs:
        raise InvariantBroken(f"verify_dir nondeterministic: {errs!r} vs {again!r}")
    return errs


def build_valid_segment(n: int) -> list[dict]:
    rec = {"schemaVersion": 1, "type": "health", "eventId": "genesis",
           "chainPrev": ec.GENESIS}
    out = [rec]
    for i in range(n - 1):
        nxt = {"schemaVersion": 1, "type": "health", "eventId": f"e{i}",
               "chainPrev": ec.record_hash(out[-1])}
        out.append(nxt)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iterations", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0x5EED)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    mut = Mutator(rng, max_depth=1)  # record-level surgery, values replaced whole
    seeds = seed_records()
    stats = {"t1_records": 0, "t1_rejected": 0, "t2_runs": 0, "clean_chain_ok": False}

    with tempfile.TemporaryDirectory(prefix="fuzz-evidence-") as td:
        tmp = pathlib.Path(td)

        # target 1: record-level parsing + hashing
        for _ in range(args.iterations):
            n_lines = rng.randrange(1, 6)
            lines = []
            for _ in range(n_lines):
                rec = mut.mutate(rng.choice(seeds))
                raw = json.dumps(rec)
                lines.append(mutate_line_bytes(rng, raw.encode("utf-8")))
            try:
                got = check_load_records(tmp, lines)
            except InvariantBroken as exc:
                print(f"fuzz-evidence-check: FAIL target1: {exc}", file=sys.stderr)
                print("input:", b"\n".join(lines)[:400], file=sys.stderr)
                return 1
            if got:
                stats["t1_records"] += got
            else:
                stats["t1_rejected"] += 1

        # target 2: directory-level verification incl. index
        for _ in range(args.iterations):
            seg_a = [mut.mutate(rng.choice(seeds)) for _ in range(rng.randrange(1, 4))]
            seg_b = [mut.mutate(rng.choice(seeds)) for _ in range(rng.randrange(1, 4))]
            files = {
                "evidence-1.jsonl": ("\n".join(json.dumps(r) for r in seg_a)).encode("utf-8"),
                "evidence-2.jsonl": ("\n".join(json.dumps(r) for r in seg_b)).encode("utf-8"),
            }
            if rng.random() < 0.5:
                files["evidence-1.jsonl"] = mutate_line_bytes(rng, files["evidence-1.jsonl"])
            index = None
            if rng.random() < 0.7:
                idx = dict(VALID_INDEX)
                if rng.random() < 0.6:
                    idx["segments"] = mut.value([{"file": "evidence-1.jsonl"}])
                index = json.dumps(idx).encode("utf-8")
                if rng.random() < 0.3:
                    index = mutate_line_bytes(rng, index)
            try:
                check_verify_dir(tmp, files, index)
            except InvariantBroken as exc:
                print(f"fuzz-evidence-check: FAIL target2: {exc}", file=sys.stderr)
                return 1
            stats["t2_runs"] += 1

        # pair assertion: built-in-memory chain -> disk -> parse -> zero errors
        good = build_valid_segment(5)
        files = {"evidence-1.jsonl": ("\n".join(ec.canonical(r) for r in good)).encode("utf-8")}
        index = json.dumps({"segments": [{"file": "evidence-1.jsonl"}]}).encode("utf-8")
        errs = check_verify_dir(tmp, files, index)
        if errs:
            print(f"fuzz-evidence-check: FAIL pair assertion: valid chain reported broken: {errs}",
                  file=sys.stderr)
            return 1
        stats["clean_chain_ok"] = True

    print(
        f"fuzz-evidence-check: ok seed={args.seed} iterations={args.iterations} "
        f"records_parsed={stats['t1_records']} rejected_inputs={stats['t1_rejected']} "
        f"dir_runs={stats['t2_runs']} clean_chain_pair={'ok' if stats['clean_chain_ok'] else 'FAIL'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
