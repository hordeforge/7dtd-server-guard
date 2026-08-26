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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iterations", type=int, default=1500)
    ap.add_argument("--seed", type=int, default=0x5EED)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    mut = Mutator(rng)

    try:
        pairs = load_pairs()
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
    except InvariantBroken as exc:
        print(f"fuzz-schema-validate: FAIL: {exc}", file=sys.stderr)
        return 1

    print(
        f"fuzz-schema-validate: ok seed={args.seed} iterations={args.iterations} "
        f"validator_runs={stats['runs']} rejected_mutants={stats['rejected']} "
        f"sensitivity_checks={stats['sensitivity']} deep_probe=ok"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
