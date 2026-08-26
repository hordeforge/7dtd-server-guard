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
  uv run python tools/fuzz_replay_trace.py [--iterations N] [--seed S]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import replay_contract_check as rcc
from fuzz_common import InvariantBroken, Mutator, nested

ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "tools" / "fixtures" / "traces" / "inventory" / "stack.v1.sample.json"
DETECTOR_IDS = {"inventory.stack"}

# Strings the contract checker branches on, so mutants land on both sides of its rules.
DOMAIN_STRINGS = ["inventory.stack", "normal", "violation", "observe"]


def check(trace: object, where: str) -> list[str]:
    try:
        errs = rcc.contract_errors(trace, DETECTOR_IDS)
    except Exception as exc:
        raise InvariantBroken(
            f"{where}: contract_errors raised {type(exc).__name__}: {exc}"
        ) from exc
    # The list-ness of the result is statically guaranteed; the element types are
    # not, because the checker builds messages from mutated content.
    if not all(isinstance(e, str) for e in errs):
        raise InvariantBroken(f"{where}: non-list-of-str result: {errs!r}")
    again = rcc.contract_errors(trace, DETECTOR_IDS)
    if again != errs:
        raise InvariantBroken(f"{where}: nondeterministic: {errs!r} vs {again!r}")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iterations", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0x5EED)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    mut = Mutator(rng, weird_strings=DOMAIN_STRINGS, max_depth=4)

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
            current = mut.mutate(mut.mutate(pristine))
            errs = check(current, "mutant")
            if errs:
                stats["rejected"] += 1

        deep = mut.mutate(mut.mutate(pristine))
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
