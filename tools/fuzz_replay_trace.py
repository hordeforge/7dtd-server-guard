#!/usr/bin/env python3
"""Fuzz the replay-trace contract checker (tools/replay_contract_check.py).

Replay traces (config/schemas/replay-trace.v1.schema.json) are the interchange
format for shipped regression fixtures; the Phase 4 replay harness consumes them
and this checker is their design-time gate. Hand-edited or generated traces can
drift from the schema in every possible way, so this harness throws structure-
aware mutations at the contract checker:

  target 1  contract_errors over mutated copies of the shipped vertical-slice trace

Invariants asserted per iteration:
  - contract_errors never raises on any mutated content.
  - The result is a list of str.
  - Determinism: two consecutive runs on the same trace return equal results.
  - Pristine shipped sample reports zero errors.
  - Sensitivity pair assertions: dropping detectorId or cases must be caught.

Deterministic (seeded PRNG), stdlib only, no external fuzzer required.

Usage:
  python3 tools/fuzz_replay_trace.py [--iterations N] [--seed S]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import random
import string
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import replay_contract_check as rcc  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "tools" / "fixtures" / "traces" / "inventory" / "stack.v1.sample.json"
DETECTOR_IDS = {"inventory.stack"}

WEIRD_STRINGS = ["", " ", "\x00", "\n", "0" * 300, "Ünïcödé", "%s%n", "-1",
                 "inventory.stack", "normal", "violation", "observe"]
NUMBERS = [0, 1, -1, 2**31, -(2**31), 2**63, 10**400, 3.14, -0.0]


class InvariantBroken(AssertionError):
    pass


def scalar(rng: random.Random, v):
    roll = rng.random()
    if roll < 0.25:
        return rng.choice([None, True, False, [], {}, rng.choice(NUMBERS)])
    if roll < 0.50:
        return rng.choice(WEIRD_STRINGS)
    if roll < 0.62:
        return rng.choice(NUMBERS)
    if roll < 0.74 and isinstance(v, str) and v:
        i = rng.randrange(len(v))
        return v[:i]  # truncation
    if roll < 0.84:
        return [{"nested": [{"deeper": v}]}]
    if roll < 0.92:
        return "".join(rng.choice(string.printable) for _ in range(rng.randrange(1, 32)))
    return v


def mutate(rng: random.Random, v, depth: int = 0):
    """Structure-aware mutation of a JSON value; recurses into containers."""
    if depth < 4 and isinstance(v, dict) and v:
        roll = rng.random()
        if roll < 0.15:
            out = dict(v)
            del out[rng.choice(sorted(out))]  # drop required field
            return out
        if roll < 0.25:
            return {**v, rng.choice(["extra", "", "\x00", "a" * 200]): scalar(rng, None)}
        key = rng.choice(sorted(v))
        return {**v, key: mutate(rng, v[key], depth + 1)}
    if depth < 4 and isinstance(v, list) and v:
        out = list(v)
        i = rng.randrange(len(out))
        if rng.random() < 0.7:
            out[i] = mutate(rng, out[i], depth + 1)
        elif len(out) > 1:
            del out[i]
        else:
            out[i] = scalar(rng, None)
        return out
    return scalar(rng, v)


def check(trace, where: str) -> list[str]:
    try:
        errs = rcc.contract_errors(trace, DETECTOR_IDS)
    except Exception as exc:  # noqa: BLE001
        raise InvariantBroken(f"{where}: contract_errors raised {type(exc).__name__}: {exc}") from exc
    if not isinstance(errs, list) or not all(isinstance(e, str) for e in errs):
        raise InvariantBroken(f"{where}: non-list-of-str result: {errs!r}")
    again = rcc.contract_errors(trace, DETECTOR_IDS)
    if again != errs:
        raise InvariantBroken(f"{where}: nondeterministic: {errs!r} vs {again!r}")
    return errs


def nested(depth: int):
    node = []
    inner = node
    for _ in range(depth):
        nxt = []
        inner.append(nxt)
        inner = nxt
    return node


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iterations", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0x5EED)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    pristine = json.loads(SAMPLE.read_text(encoding="utf-8"))
    current = pristine
    try:
        if check(pristine, "pristine sample"):
            raise InvariantBroken("pristine shipped sample reported errors")
        for drop in ("detectorId", "cases", "workBudget"):
            bad = dict(pristine)
            del bad[drop]
            if not check(bad, f"sample without {drop}"):
                raise InvariantBroken(f"dropping {drop} was accepted")

        stats = {"rejected": 0}
        for _ in range(args.iterations):
            current = mutate(rng, mutate(rng, pristine))
            errs = check(current, "mutant")
            if errs:
                stats["rejected"] += 1

        deep = mutate(rng, mutate(rng, pristine))
        deep["cases"][0]["events"][0]["values"] = {"claimedDestinationQuantity": nested(64)}
        check(deep, "deep-nested value")
    except InvariantBroken as exc:
        print(f"fuzz-replay-trace: FAIL: {exc}", file=sys.stderr)
        print("input:", json.dumps(current)[:400], file=sys.stderr)
        return 1

    print(
        f"fuzz-replay-trace: ok seed={args.seed} iterations={args.iterations} "
        f"rejected_mutants={stats['rejected']} sensitivity=ok"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
