"""Shared machinery for the seeded stdlib fuzzers in tools/fuzz_*.py.

Each harness owns its targets and asserted invariants; this module owns the
structure-aware mutation engine they all use, so the mutation policies cannot
drift apart silently.

Mutated values are typed `Any`: the engine exists to produce values that violate
the targets' declared types, so a narrower annotation would describe the input
corpus rather than what the mutators emit.
"""

from __future__ import annotations

import random
import string
from typing import Any

WEIRD_STRINGS = [
    "",
    " ",
    "\x00",
    "\n",
    "\r\n",
    "0" * 64,
    "Z" * 65,
    "g" * 64,
    "0" * 63,
    "ffff",
    "Ünïcödé",
    # Bidi override and a homoglyph digit: both belong in the corpus because a
    # target that echoes them into a report must not be fooled by them.
    "‮rtl",  # noqa: PLE2502
    "𝟘" * 70,  # noqa: RUF001
    "\udcff",
    "%s%s%n",
    "../../etc/passwd",
    "-" * 4096,
    "\\u0000",
    "\"'",
    "0" * 300,
    "-1",
]
NUMBERS = [0, 1, -1, 2**31, -(2**31), 2**63, 10**400, 3.14, float("inf"), -0.0]

# Relative frequency of each scalar-replacement kind. Tuning knob: raise a weight
# to spend more of a run's budget on that shape of malformed value.
VALUE_KIND_WEIGHTS = {
    "degenerate": 25,  # None/bool/empty container/number
    "weird_string": 20,
    "truncate": 15,  # prefix of the original string
    "number": 12,
    "nest": 12,  # wrap the original in an extra object layer
    "random_text": 8,
    "keep": 8,  # leave the value alone, mutating only its container
}
# Relative frequency of each container mutation.
DICT_KIND_WEIGHTS = {"drop_key": 15, "add_key": 10, "mutate_value": 75}
LIST_KIND_WEIGHTS = {"mutate_item": 70, "drop_item": 15, "replace_item": 15}
RANDOM_TEXT_MAX_LEN = 48
ADDED_KEYS = ["extra", "", "\x00", "a" * 200]


class InvariantBroken(AssertionError):
    """A fuzzer invariant failed."""


def nested(depth: int) -> list[Any]:
    """Right-nested list chain of the given depth."""
    node: list[Any] = []
    inner = node
    for _ in range(depth):
        nxt: list[Any] = []
        inner.append(nxt)
        inner = nxt
    return node


def weighted_choice(rng: random.Random, weights: dict[str, int]) -> str:
    """Pick one key from a name -> relative-weight table."""
    return rng.choices(list(weights), weights=list(weights.values()))[0]


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
    ) -> None:
        self.rng = rng
        self.weird_strings = (
            WEIRD_STRINGS if weird_strings is None else WEIRD_STRINGS + weird_strings
        )
        self.max_depth = max_depth

    def value(self, v: Any) -> Any:  # noqa: PLR0911 - one return per mutation kind
        """Replace a scalar (or whole subtree) with a mutated value."""
        kind = weighted_choice(self.rng, VALUE_KIND_WEIGHTS)
        if kind == "truncate" and not (isinstance(v, str) and v):
            kind = "keep"  # nothing to truncate
        if kind == "degenerate":
            return self.rng.choice([None, True, False, [], {}, self.rng.choice(NUMBERS)])
        if kind == "weird_string":
            return self.rng.choice(self.weird_strings)
        if kind == "truncate":
            return v[: self.rng.randrange(len(v))]
        if kind == "number":
            return self.rng.choice(NUMBERS)
        if kind == "nest":
            return {"nested": [{"deeper": v}]}
        if kind == "random_text":
            return "".join(
                self.rng.choice(string.printable)
                for _ in range(self.rng.randrange(1, RANDOM_TEXT_MAX_LEN))
            )
        return v

    def mutate(self, v: Any, depth: int = 0) -> Any:
        """Return a mutated copy of a JSON value; recurses into containers."""
        if depth < self.max_depth and isinstance(v, dict) and v:
            return self._mutate_dict(v, depth)
        if depth < self.max_depth and isinstance(v, list) and v:
            return self._mutate_list(v, depth)
        return self.value(v)

    def _mutate_dict(self, v: dict[str, Any], depth: int) -> dict[str, Any]:
        kind = weighted_choice(self.rng, DICT_KIND_WEIGHTS)
        if kind == "drop_key":
            out = dict(v)
            del out[self.rng.choice(sorted(out))]  # drop required field
            return out
        if kind == "add_key":
            return {**v, self.rng.choice(ADDED_KEYS): self.value(None)}
        key = self.rng.choice(sorted(v))
        return {**v, key: self.mutate(v[key], depth + 1)}

    def _mutate_list(self, v: list[Any], depth: int) -> list[Any]:
        out = list(v)
        i = self.rng.randrange(len(out))
        kind = weighted_choice(self.rng, LIST_KIND_WEIGHTS)
        if kind == "drop_item" and len(out) > 1:
            del out[i]
        elif kind == "mutate_item":
            out[i] = self.mutate(out[i], depth + 1)
        else:
            out[i] = self.value(None)
        return out
