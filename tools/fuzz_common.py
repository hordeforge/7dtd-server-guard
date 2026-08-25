"""Shared machinery for the seeded stdlib fuzzers in tools/fuzz_*.py.

Each harness owns its targets and asserted invariants; this module owns the
structure-aware mutation engine they all use, so the mutation policies cannot
drift apart silently.
"""
from __future__ import annotations

import random
import string

WEIRD_STRINGS = [
    "", " ", "\x00", "\n", "\r\n", "0" * 64, "Z" * 65, "g" * 64,
    "0" * 63, "ffff", "Ünïcödé", "‮rtl", "\udcff", "%s%s%n", "../../etc/passwd",
    "-" * 4096, "\\u0000", "\"'", "𝟘" * 70, "0" * 300, "-1",
]
NUMBERS = [0, 1, -1, 2**31, -(2**31), 2**63, 10**400, 3.14, float("inf"), -0.0]


class InvariantBroken(AssertionError):
    """A fuzzer invariant failed."""


def nested(depth: int) -> list:
    """Right-nested list chain of the given depth."""
    node: list = []
    inner = node
    for _ in range(depth):
        nxt: list = []
        inner.append(nxt)
        inner = nxt
    return node


class Mutator:
    """Structure-aware JSON-value mutator driven by a seeded PRNG.

    weird_strings biases mutations toward domain strings a harness's target
    branches on (e.g. detector IDs); max_depth bounds recursion into containers
    (use 1 to mutate only the top level of a record).
    """

    def __init__(
        self,
        rng: random.Random,
        *,
        weird_strings: list[str] | None = None,
        max_depth: int = 3,
    ):
        self.rng = rng
        self.weird_strings = WEIRD_STRINGS if weird_strings is None else WEIRD_STRINGS + weird_strings
        self.max_depth = max_depth

    def value(self, v):
        """Replace a scalar (or whole subtree) with a mutated value."""
        roll = self.rng.random()
        if roll < 0.25:
            return self.rng.choice([None, True, False, [], {}, self.rng.choice(NUMBERS)])
        if roll < 0.45:
            return self.rng.choice(self.weird_strings)
        if roll < 0.60 and isinstance(v, str) and v:
            return v[: self.rng.randrange(len(v))]  # truncation
        if roll < 0.72:
            return self.rng.choice(NUMBERS)
        if roll < 0.84:
            return {"nested": [{"deeper": v}]}
        if roll < 0.92:
            return "".join(
                self.rng.choice(string.printable)
                for _ in range(self.rng.randrange(1, 48))
            )
        return v

    def mutate(self, v, depth: int = 0):
        """Return a mutated copy of a JSON value; recurses into containers."""
        if depth < self.max_depth and isinstance(v, dict) and v:
            roll = self.rng.random()
            if roll < 0.15:
                out = dict(v)
                del out[self.rng.choice(sorted(out))]  # drop required field
                return out
            if roll < 0.25:
                extra = self.rng.choice(["extra", "", "\x00", "a" * 200])
                return {**v, extra: self.value(None)}
            key = self.rng.choice(sorted(v))
            return {**v, key: self.mutate(v[key], depth + 1)}
        if depth < self.max_depth and isinstance(v, list) and v:
            out = list(v)
            i = self.rng.randrange(len(out))
            if self.rng.random() < 0.7:
                out[i] = self.mutate(out[i], depth + 1)
            elif len(out) > 1:
                del out[i]
            else:
                out[i] = self.value(None)
            return out
        return self.value(v)
