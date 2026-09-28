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

Exit codes: 0 every invariant held, 1 an invariant broke, 2 usage error. The
replay of a reported failure is `uv run python tools/fuzz_replay_trace.py
--seed <seed>`; the failure and its input go to stderr.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import replay_contract_check as rcc
from fuzz_common import InvariantBrokenError, Mutator, add_fuzz_args, fuzz_args, nested

DETECTOR_IDS = {"inventory.stack"}

# Strings the contract checker branches on, so mutants land on both sides of its rules.
DOMAIN_STRINGS = ["inventory.stack", "normal", "violation", "observe"]


def clone(trace: Any) -> Any:
    """Independent copy of a parsed trace, by the same JSON round trip the file uses."""
    return json.loads(json.dumps(trace))


def check(trace: object, where: str) -> list[str]:
    try:
        errs = rcc.contract_errors(trace, DETECTOR_IDS)
    except Exception as exc:
        raise InvariantBrokenError(
            f"{where}: contract_errors raised {type(exc).__name__}: {exc}"
        ) from exc
    # The list-ness of the result is statically guaranteed; the element types are
    # not, because the checker builds messages from mutated content.
    if not all(isinstance(e, str) for e in errs):
        raise InvariantBrokenError(f"{where}: non-list-of-str result: {errs!r}")
    again = rcc.contract_errors(trace, DETECTOR_IDS)
    if again != errs:
        raise InvariantBrokenError(f"{where}: nondeterministic: {errs!r} vs {again!r}")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_fuzz_args(ap, default_iterations=2000)
    args = fuzz_args(ap)
    rng = random.Random(args.seed)  # noqa: S311 - seeded corpus fuzzing, not a secret
    mut = Mutator(rng, weird_strings=DOMAIN_STRINGS, max_depth=4)

    try:
        pristine = json.loads(rcc.TRACE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"fuzz-replay-trace: FAIL: shipped sample {rcc.TRACE.name}: {exc}", file=sys.stderr)
        return 1
    current = pristine
    try:
        if check(pristine, "pristine sample"):
            raise InvariantBrokenError("pristine shipped sample reported errors")
        for drop in ("detectorId", "cases", "workBudget", "determinism", "seed"):
            bad = dict(pristine)
            del bad[drop]
            if not check(bad, f"sample without {drop}"):
                raise InvariantBrokenError(f"dropping {drop} was accepted")

        tampered = clone(pristine)
        tampered["determinism"]["fingerprint"] = "0" * 64
        if not check(tampered, "sample with a tampered fingerprint"):
            raise InvariantBrokenError(
                "a fingerprint that does not match the projection was accepted"
            )

        skewed = clone(pristine)
        skewed["determinism"]["startUtc"] = "not-an-instant"
        if not check(skewed, "sample with an unparseable clock origin"):
            raise InvariantBrokenError("an unparseable determinism.startUtc was accepted")

        backwards = clone(pristine)
        first = backwards["cases"][0]["events"][0]
        backwards["cases"][0]["events"].append(dict(first, sequence=2, tick=first["tick"] - 1))
        # Re-seal so the tick rule is the only thing left to catch.
        backwards["determinism"]["fingerprint"] = rcc.outcome_fingerprint(backwards)
        backwards_errs = check(backwards, "case whose tick steps backwards")
        if not any("tick must not decrease" in e for e in backwards_errs):
            raise InvariantBrokenError("a backwards tick was accepted")

        stats = {"rejected": 0}
        for _ in range(args.iterations):
            current = mut.mutate(mut.mutate(pristine))
            errs = check(current, "mutant")
            if errs:
                stats["rejected"] += 1

        # Built from the pristine trace, not a mutant: the probe indexes cases ->
        # events, and a mutant may have dropped or replaced either (that is the
        # path under test above, not this one).
        deep = clone(pristine)
        deep["cases"][0]["events"][0]["values"] = {"claimedDestinationQuantity": nested(64)}
        check(deep, "deep-nested value")
    except InvariantBrokenError as exc:
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
