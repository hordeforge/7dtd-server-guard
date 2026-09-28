"""Fuzz the JSON Schema validator (tools/doccheck.py -> _schema_validate).

_schema_validate is the reference validator behind every schema gate in this repo:
doccheck runs it over the example config, the generated manifest, the evidence
sample, and the replay-trace fixture, and the Phase 2 strict config loader is
specified from the same schemas (docs/SCHEMAS.md). It walks fully attacker-shaped
documents with unbounded recursion, so this harness throws structure-aware
mutations at it:

  target 1  _schema_validate over mutated schema/instance pairs built from all
            four shipped schema + data pairs
  target 2  deep-nesting probe: instances nested far past any legitimate document

Invariants asserted per iteration:
  - Totality: no exception (RecursionError included) escapes the validator.
  - The result is a list of str.
  - Determinism: two consecutive runs on the same input return equal results.
  - Sensitivity pair assertion: deleting a required key from a pristine valid
    instance must produce at least one error.
  - Pristine shipped pairs validate clean.
  - The evidence schema refuses personal-data keys in its open value bags.

Deterministic (seeded PRNG), stdlib only, no external fuzzer required.

Usage:
  uv run python tools/fuzz_schema_validate.py [--iterations N] [--seed S]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import doccheck as dc
from fuzz_common import InvariantBroken, Mutator, nested

# Schemas and instances are arbitrary JSON by construction here: the harness
# exists to feed the validator documents no static type would admit.
Json = Any

ROOT = pathlib.Path(__file__).resolve().parent.parent

# A finding hands `context`, `observations`, `expected`, and `actual` to the
# exporter, the operator, and the webhook consumer, so a key that could hold a
# raw identity, a contact address, a network address, or a credential must be
# rejected there. The spelling variants matter: the schema matches keys
# case-insensitively because a detector's local naming is its own choice.
PERSONAL_DATA_KEYS = (
    "steamId",
    "STEAM_ID",
    "steam_id",
    "platformId",
    "platform_id",
    "playerName",
    "player_name",
    "username",
    "client_id",
    "ip",
    "ipAddress",
    "ip_address",
    "eacGuid",
    "auth_ticket",
    "password",
    "macAddress",
    "hardware_id",
)
# The open bags of a `finding` record, and how to inject a key into each.
EVIDENCE_BAGS = ("context", "expected", "actual", "observations")


def load_pairs() -> list[tuple[str, Json, list[Json]]]:
    out = []
    for schema_path, data_path in dc.SCHEMA_DATA_PAIRS:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        text = data_path.read_text(encoding="utf-8")
        if data_path.suffix == ".jsonl":
            instances = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
        else:
            instances = [json.loads(text)]
        name = f"{schema_path.name} vs {data_path.name}"
        for inst in instances:
            errs = dc._schema_validate(inst, schema)
            if errs:
                raise InvariantBroken(f"pristine shipped pair {name} reports errors: {errs}")
        out.append((name, schema, instances))
    return out


def check_totality(schema: Json, instance: Json) -> list[str]:
    # The list-ness of the result is now statically guaranteed; the element types
    # are not, because the validator builds messages from mutated content.
    errs = dc._schema_validate(instance, schema)
    if not all(isinstance(e, str) for e in errs):
        raise InvariantBroken(f"non-list-of-str result: {errs!r}")
    again = dc._schema_validate(instance, schema)
    if again != errs:
        raise InvariantBroken(f"nondeterministic: {errs!r} vs {again!r}")
    return errs


def check_sensitivity(rng: random.Random, name: str, schema: Json, instance: Json) -> bool:
    """Deleting a required top-level key from a valid instance must be caught."""
    required = schema.get("required") or []
    if not required or not isinstance(instance, dict):
        return False
    bad = dict(instance)
    del bad[required[rng.randrange(len(required))]]
    if not dc._schema_validate(bad, schema):
        raise InvariantBroken(f"{name}: deleting required key was accepted")
    return True


def check_deep_nesting() -> None:
    """Deeply nested / self-referential schemas must yield errors, never RecursionError."""
    # Self-referential (aliased) schema: validator recursion tracks instance depth.
    cyclic: dict[str, Any] = {"type": "array"}
    cyclic["items"] = cyclic
    # Deep linear schema walked by a matching deep instance.
    deep: dict[str, Any] = {"type": "object"}
    node = deep
    for _ in range(4 * dc.MAX_SCHEMA_DEPTH):
        child = {"type": "object"}
        node["properties"] = {"a": child}
        node = child
    deep_inst: dict[str, Any] = {}
    cur = deep_inst
    for _ in range(4 * dc.MAX_SCHEMA_DEPTH):
        cur["a"] = {}
        cur = cur["a"]
    cases = [
        ("cyclic schema", cyclic, nested(4 * dc.MAX_SCHEMA_DEPTH)),
        ("deep schema", deep, deep_inst),
        (
            "shallow schema",
            {"type": "array", "items": {"type": "integer"}},
            nested(dc.MAX_SCHEMA_DEPTH + 1),
        ),
        ("at the bound", cyclic, nested(dc.MAX_SCHEMA_DEPTH)),
    ]
    for name, schema, inst in cases:
        try:
            errs = dc._schema_validate(inst, schema)
        except Exception as exc:
            raise InvariantBroken(f"{name} raised {type(exc).__name__}") from exc
        if not isinstance(errs, list):
            raise InvariantBroken(f"{name}: non-list result {errs!r}")
        again = dc._schema_validate(inst, schema)
        if again != errs:
            raise InvariantBroken(f"{name}: nondeterministic")
        if name in ("cyclic schema", "deep schema"):
            if len(errs) != 1 or "nesting deeper" not in errs[0]:
                raise InvariantBroken(f"{name}: unexpected errors {errs!r}")
        elif name == "shallow schema":
            if not errs:
                raise InvariantBroken(f"{name}: pathological document accepted silently")
        elif errs:  # at the bound: depth MAX_SCHEMA_DEPTH must still validate clean
            raise InvariantBroken(f"{name}: rejected at the legal bound: {errs!r}")


def check_datetime_format() -> None:
    """Timestamp fields must be offset-qualified instants, not local-time strings.

    A value like `2026-07-21T12:34:56` names no instant: each reader resolves it
    against its own zone, so the same record reads as a different moment in
    different deployments. An impossible calendar date is rejected by the same
    path, since `format` is asserted by the platform parser.
    """
    schema = json.loads((ROOT / "config" / "schemas" / "evidence.v1.schema.json").read_text())
    text = (ROOT / "config" / "schemas" / "evidence.v1.sample.jsonl").read_text()
    records = {
        rec["type"]: rec for rec in (json.loads(ln) for ln in text.splitlines() if ln.strip())
    }
    field_of = {"finding": "utc", "audit": "utc", "reconciliation": "savedAt"}
    good = "2026-07-21T12:34:56.789Z"
    bad_values = {
        "2026-07-21T12:34:56.789": "no offset: resolved against the reader's zone",
        "2026-07-21 12:34:56Z": "space separator instead of the RFC 3339 T",
        "2026-07-21T12:34:56": "local wall time with no offset at all",
        "2026-02-30T00:00:00Z": "impossible calendar date",
        "1753098896": "epoch seconds in a string field",
        "yesterday": "not a date at all",
    }
    for rec_type, field in field_of.items():
        pristine = records[rec_type]
        if dc._schema_validate({**pristine, field: good}, schema):
            raise InvariantBroken(f"{rec_type}.{field}: valid instant rejected")
        for value, why in bad_values.items():
            if not dc._schema_validate({**pristine, field: value}, schema):
                raise InvariantBroken(f"{rec_type}.{field}={value!r} accepted: {why}")


def _with_key(record: Json, bag: str, key: str) -> Json:
    """A copy of `record` carrying `key` inside the open bag `bag`."""
    bad = json.loads(json.dumps(record))
    if bag == "observations":
        bad["observations"][0][key] = "x"
    else:
        bad[bag][key] = "x"
    return bad


def check_personal_data_denylist() -> int:
    """Every personal-data spelling must be rejected in every open evidence bag.

    doccheck.py keeps every open object carrying the deny-list; this pins that
    the deny-list it carries actually fires, in each bag a finding writes to.
    """
    schema_path = ROOT / "config" / "schemas" / "evidence.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    sample = ROOT / "config" / "schemas" / "evidence.v1.sample.jsonl"
    findings = [
        json.loads(ln)
        for ln in sample.read_text(encoding="utf-8").splitlines()
        if ln.strip() and json.loads(ln)["type"] == "finding"
    ]
    if not findings:
        raise InvariantBroken("no finding record in the shipped evidence sample")
    record = findings[0]
    checks = 0
    for key in PERSONAL_DATA_KEYS:
        for bag in EVIDENCE_BAGS:
            if not dc._schema_validate(_with_key(record, bag, key), schema):
                raise InvariantBroken(f"{bag}.{key} accepted by the evidence schema")
            checks += 1
    # The deny-list must not reject the keys the sample itself writes.
    if dc._schema_validate(record, schema):
        raise InvariantBroken("shipped finding record rejected by its own schema")
    return checks


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iterations", type=int, default=1500)
    ap.add_argument("--seed", type=int, default=0x5EED)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    mut = Mutator(rng)

    try:
        pairs = load_pairs()
        denylist_checks = check_personal_data_denylist()
        stats = {"runs": 0, "sensitivity": 0, "rejected": 0}
        for _ in range(args.iterations):
            name, schema, instances = rng.choice(pairs)
            instance = rng.choice(instances)
            mutant = mut.mutate(mut.mutate(instance))
            try:
                errs = check_totality(schema, mutant)
            except InvariantBroken as exc:
                print(f"fuzz-schema-validate: FAIL target1 ({name}): {exc}", file=sys.stderr)
                print("input:", json.dumps(mutant)[:400], file=sys.stderr)
                return 1
            stats["runs"] += 1
            if errs:
                stats["rejected"] += 1
            if check_sensitivity(rng, name, schema, instance):
                stats["sensitivity"] += 1

        check_deep_nesting()
        check_datetime_format()
    except InvariantBroken as exc:
        print(f"fuzz-schema-validate: FAIL: {exc}", file=sys.stderr)
        return 1

    print(
        f"fuzz-schema-validate: ok seed={args.seed} iterations={args.iterations} "
        f"validator_runs={stats['runs']} rejected_mutants={stats['rejected']} "
        f"sensitivity_checks={stats['sensitivity']} denylist_checks={denylist_checks} "
        f"deep_probe=ok datetime_probe=ok"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
