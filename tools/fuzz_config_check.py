"""Fuzz the operator config validator (tools/config_check.py).

An operator's runtime config is a hand-edited file that no other gate sees before
it starts a server: a misspelled detector id, a threshold outside its declared
range, or a webhook enabled with its environment variable unset produces a server
that looks configured and is not. The validator is the only thing standing
between that file and the loader, and every check it runs indexes content the
schema pass has not narrowed (registry ids, manifest thresholds, env var names),
so this harness throws structure-aware mutations at it:

  target 1  check                                         (schema, registry,
                                                         manifest, and secret-env
                                                         passes end to end)
  target 2  registry_errors / threshold_errors /           (the cross-file
           secret_env_errors / unlisted_detectors          consumers on content
                                                         that never passed the
                                                         schema gate)
  target 3  load                                          (the file entry point:
                                                         raw bytes to parsed
                                                         config or a reported
                                                         parse error)
  target 4  effective_config / config_hash                (the defaults walk and
                                                         the digest stamped on
                                                         findings)

Invariants asserted per iteration:
  - check never raises on any config shape, including a non-object, and returns
    a list of str; two consecutive runs return equal results.
  - Every cross-file consumer returns a list of str (unlisted_detectors an int)
    and never raises, whatever the types of the keys it looks up.
  - load returns either a parsed config with no error or (None, str), never
    raises, whatever bytes the file holds: truncated, mis-encoded, or not JSON.
  - effective_config never raises on a self-referential defaults tree, and
    config_hash is stable under key order and 64 lowercase hex characters.
  - Pair assertions across the file boundary: a valid config written to disk
    reads back equal to the in-memory config and yields the same config hash;
    the shipped example validates clean, and an enabled sink whose named
    environment variable is unset is refused.

Deterministic (seeded PRNG), stdlib only, no external fuzzer required.

Usage:
  uv run python tools/fuzz_config_check.py [--iterations N] [--seed S]

Exit codes: 0 every invariant held, 1 an invariant broke, 2 usage error. The
replay of a reported failure is `uv run python tools/fuzz_config_check.py
--seed <seed>`; the failure and its input go to stderr.
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import random
import re
import string
import sys
import tempfile
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import config_check as cc
import doccheck as dc
from fuzz_common import InvariantBrokenError, Mutator, add_fuzz_args, fuzz_args, nested

# Config JSON, mutated past its declared types on purpose: the shape is what the
# validator checks, so the harness cannot narrow it either.
Json = Any

# Temporary config files go to the repo's gitignored scratch dir, not the system
# temp dir: /tmp is tmpfs here, so every iteration would be charged to RAM.
SCRATCH = cc.ROOT / ".scratch"

# A config hash is a 64-character lowercase hex digest; anything else is a
# digest the evidence chain and the health report cannot read back.
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")

# Relative probability that a schema-clean config candidate keeps a legal value
# rather than a mutated one, and that an environment answers a named variable.
# Tuning knob: lower P_KEEP_LEGAL to spend more of a run on illegal content, and
# raise it to reach more of the passes that only run on schema-clean input.
P_KEEP_LEGAL = 0.5
P_MUTATED_VALUE = 0.2
P_MOVED = 0.5
P_UNNAMED = 0.2
# Nesting depth of the structurally valid but absurdly deep JSON a config file
# can hold, as a range the fuzzer samples from.
MIN_DEEP_NESTING = 20
MAX_DEEP_NESTING = 200

# Strings the validator branches on: detector ids and the enum of modes, plus
# shapes an operator's editor produces (a name mangled by case folding, a
# path-like value, a non-string key name that JSON cannot carry).
DOMAIN_STRINGS = [
    "movement.displacement",
    "movement.fligth",
    "inventory.stack",
    "observe",
    "correct",
    "enforce",
    "protocol.malformed",
    "",
    "SERVERGUARD_WEBHOOK_URL",
    "../../etc/passwd",
]

# Relative frequency of each raw-file corruption. Tuning knob: raise a weight to
# spend more of a run on that shape of malformed config file.
FILE_KIND_WEIGHTS = {
    "truncate": 20,
    "encode": 20,  # bytes that are not UTF-8 at all
    "splice": 15,  # arbitrary printable bytes, valid or not
    "deep": 10,  # structurally valid JSON, nested past any sane depth
    "bom": 10,
    "keep": 25,
}
HEX_DIGITS = "0123456789abcdef"


def mutate_file_bytes(rng: random.Random, raw: bytes) -> bytes:
    """Corrupt config file bytes the way a bad editor or a wrong encoding would."""
    kind = rng.choices(list(FILE_KIND_WEIGHTS), weights=list(FILE_KIND_WEIGHTS.values()))[0]
    if kind == "truncate" and raw:
        return raw[: rng.randrange(len(raw))]
    if kind == "encode" and raw:
        return raw[: rng.randrange(len(raw))] + bytes([0xFF, 0xFE, 0x80]) + raw[:8]
    if kind == "splice":
        return "".join(rng.choice(string.printable) for _ in range(rng.randrange(0, 200))).encode(
            "utf-8", "surrogatepass"
        )
    if kind == "deep":
        return json.dumps(nested(rng.randrange(MIN_DEEP_NESTING, MAX_DEEP_NESTING))).encode("utf-8")
    if kind == "bom":
        return b"\xef\xbb\xbf" + raw
    return raw


def check_list(call: Any, *args: Any) -> list[str]:
    """Run a validator entry point that must return a list of str, twice.

    Determinism is part of the contract: the same config twice must produce the
    same report, or a deploy gate disagrees with itself between runs.
    """
    try:
        out = call(*args)
    except Exception as exc:
        raise InvariantBrokenError(
            f"{getattr(call, '__name__', call)} raised {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(out, list) or not all(isinstance(e, str) for e in out):
        raise InvariantBrokenError(
            f"{getattr(call, '__name__', call)}: non-list-of-str result: {out!r}"
        )
    again = call(*args)
    if again != out:
        raise InvariantBrokenError(
            f"{getattr(call, '__name__', call)}: nondeterministic: {out!r} vs {again!r}"
        )
    return out


def semantic_ish(rng: random.Random, example: Json, mut: Mutator) -> Json:
    """A config that stays close enough to the shipped example to reach the
    cross-file passes.

    Plain mutations are mostly rejected by the schema pass, which is the correct
    answer but leaves registry_errors, threshold_errors, and secret_env_errors
    untested: check() returns before it calls them. This keeps the top-level
    shape and moves the values, so those three passes run on varied content.
    """
    config = copy.deepcopy(example)
    _move_modes(rng, config, mut)
    _move_thresholds(rng, config, mut)
    _move_secret_sections(rng, config)
    return config


def _move_modes(rng: random.Random, config: Json, mut: Mutator) -> None:
    """Rewrite one detector's mode, or add a well-formed key naming no detector."""
    modes = config.get("modes")
    if not isinstance(modes, dict) or not modes:
        return
    key = rng.choice(sorted(modes))
    roll = rng.random()
    if roll < P_KEEP_LEGAL:
        modes[key] = rng.choice(["observe", "correct", "enforce"])
    elif roll < P_KEEP_LEGAL + P_MUTATED_VALUE:
        modes[key] = mut.value(modes[key])
    else:
        # A key that matches the schema's pattern but names no detector: the case
        # the registry pass exists for.
        modes[f"{rng.choice(['zzz', 'MOVEMENT', ''])}.nope"] = rng.choice(["observe", "correct"])


def _move_thresholds(rng: random.Random, config: Json, mut: Mutator) -> None:
    """Put a legal-typed number, a mistyped value, or an undeclared key in a
    detector's threshold block."""
    thresholds = config.get("thresholds")
    if not isinstance(thresholds, dict) or not thresholds:
        return
    block = thresholds[rng.choice(sorted(thresholds))]
    if not isinstance(block, dict) or not block:
        return
    key = rng.choice(sorted(block))
    roll = rng.random()
    if roll < P_KEEP_LEGAL:
        block[key] = rng.choice([0, 1, -1, 10.0, 10**400, 0.5])
    elif roll < P_KEEP_LEGAL + P_MUTATED_VALUE:
        block[key] = mut.value(block[key])
    else:
        block["nope"] = mut.value(None)


def _move_secret_sections(rng: random.Random, config: Json) -> None:
    """Toggle the webhook and dashboard, and rename the variables they depend on."""
    for section, env_key in cc.SECRET_ENV_SECTIONS:
        block = config.get(section)
        if not isinstance(block, dict):
            continue
        if rng.random() < P_MOVED:
            block[cc.ENABLED_KEY] = rng.choice([True, False, "true", 1, None])
        if rng.random() < P_MOVED:
            block[env_key] = rng.choice(
                [f"SERVERGUARD_{section.upper()}", "", None, 7, "../../etc/passwd"]
            )


def mutated_env(rng: random.Random) -> dict[str, str]:
    """An environment that answers some names and not others."""
    env: dict[str, str] = {}
    for section, _env_key in cc.SECRET_ENV_SECTIONS:
        if rng.random() < P_MOVED:
            env[f"SERVERGUARD_{section.upper()}"] = rng.choice(["", "value", "u" * 200])
    if rng.random() < P_UNNAMED:
        env[""] = "unnamed"
    return env


def check_load(tmp: pathlib.Path, raw: bytes) -> tuple[Json | None, str | None]:
    """Write raw bytes to a file and read them back through the real entry point."""
    path = tmp / "config.json"
    path.write_bytes(raw)
    try:
        config, error = cc.load(path)
    except Exception as exc:
        raise InvariantBrokenError(f"load raised {type(exc).__name__}: {exc}") from exc
    if error is not None and (config is not None or not isinstance(error, str)):
        raise InvariantBrokenError(f"load: expected (None, str), got {(config, error)!r}")
    if error is None and config is None:
        raise InvariantBrokenError("load: reported neither a config nor an error")
    again_config, again_error = cc.load(path)
    if (again_config, again_error) != (config, error):
        raise InvariantBrokenError("load: nondeterministic on the same bytes")
    return config, error


def file_boundary_pair(tmp: pathlib.Path, example: Json, digest: str) -> None:
    """A config that validated in memory must survive the round trip through the
    file the operator actually deploys, byte for byte and digest for digest.

    The seed config is re-hashed first: a mutator that reached into the seed
    corpus in place would otherwise show up here as a round-trip failure with no
    cause, when the real defect is that the fuzz run stopped being a comparison.
    """
    schema = json.loads(cc.SCHEMA_PATH.read_text(encoding="utf-8"))
    if cc.config_hash(cc.effective_config(example, schema)) != digest:
        raise InvariantBrokenError("the seed config changed during the run")
    raw = json.dumps(example, indent=2).encode("utf-8")
    config, error = check_load(tmp, raw)
    if error is not None or config != example:
        raise InvariantBrokenError(f"pair assertion: valid config did not round trip: {error!r}")
    if errs := check_list(cc.check, config, {}, True):
        raise InvariantBrokenError(
            f"pair assertion: the round-tripped config did not validate: {errs}"
        )
    if cc.config_hash(cc.effective_config(config, schema)) != digest:
        raise InvariantBrokenError("pair assertion: the file round trip changed the config hash")


def shipped_example() -> Json:
    """The seed corpus, or the harness stops: without it there is nothing to fuzz.

    A missing or unparseable example is a broken corpus, not a fuzzing finding,
    so it is reported on stderr and main exits instead of fuzzing a substitute.
    """
    try:
        example = json.loads(cc.EXAMPLE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InvariantBrokenError(f"shipped example {cc.EXAMPLE_PATH.name}: {exc}") from exc
    if not isinstance(example, dict):
        raise InvariantBrokenError("shipped example is not a JSON object")
    return example


def sensitivity(example: Json) -> str:
    """Assert the pairs a fuzzer alone cannot see, and return the config digest.

    Each case is a way an operator's file departs from the shipped example, and
    each has one verdict the validator owes the operator.
    """
    registered = len(dc.spec_ids())
    if errs := check_list(cc.check, example, {}, True):
        raise InvariantBrokenError(f"shipped example reported errors: {errs}")
    # A config with no schema version is not one this loader understands.
    unversioned = dict(example)
    del unversioned["schemaVersion"]
    if not check_list(cc.check, unversioned, {}, True):
        raise InvariantBrokenError("a config without schemaVersion was accepted")
    # Every other section is optional by design: an absent section loads at its
    # declared default, so the check stays quiet about it and the unlisted-detector
    # count rises instead.
    modest = dict(example)
    del modest["modes"]
    if check_list(cc.check, modest, {}, True):
        raise InvariantBrokenError("a config with no modes block was refused")
    if cc.unlisted_detectors(modest) != registered:
        raise InvariantBrokenError("a config with no modes block is not reported as unlisted")
    if cc.unlisted_detectors({}) != registered:
        raise InvariantBrokenError("an empty config does not list every detector as unlisted")
    if cc.unlisted_detectors(example) != 0:
        raise InvariantBrokenError("the shipped example leaves a detector unlisted")
    secret_env_pairs(example)
    return digest_of(example)


def digest_of(config: Json) -> str:
    """The config hash a finding is stamped with, from the schema's defaults.

    It must be a digest, and it must not depend on the order the operator's
    editor wrote the keys in, or two identical configs read back as two findings.
    """
    schema = json.loads(cc.SCHEMA_PATH.read_text(encoding="utf-8"))
    digest = cc.config_hash(cc.effective_config(config, schema))
    if not HEX64.match(digest):
        raise InvariantBrokenError(f"config hash is not 64 lowercase hex characters: {digest}")
    reordered = dict(reversed(list(config.items())))
    if cc.config_hash(cc.effective_config(reordered, schema)) != digest:
        raise InvariantBrokenError("the config hash depends on key order")
    return digest


def secret_env_pairs(example: Json) -> None:
    """The secret-env pass is the one whose verdict depends on a value that is not
    in the file, so its four verdicts are pinned here."""
    for section, env_key in cc.SECRET_ENV_SECTIONS:
        enabled = copy.deepcopy(example)
        enabled[section][cc.ENABLED_KEY] = True
        name = enabled[section][env_key]
        if not any(name in e for e in check_list(cc.check, enabled, {}, True)):
            raise InvariantBrokenError(f"{section} enabled with no env var was accepted")
        if any(name in e for e in check_list(cc.check, enabled, {name: "set"}, True)):
            raise InvariantBrokenError(f"{section} enabled with {name} set was refused")
        # An exported but empty variable is the same misconfiguration as one that
        # was never exported, so it must be refused too.
        if not any(name in e for e in check_list(cc.check, enabled, {name: ""}, True)):
            raise InvariantBrokenError(f"{section} with an empty {name} was accepted")
        if any(name in e for e in check_list(cc.check, enabled, {name: "set"}, False)):
            raise InvariantBrokenError(f"--skip-env: reported a missing {name} anyway")


def run_configs(rng: random.Random, mut: Mutator, example: Json, iterations: int) -> dict[str, int]:
    """Targets 1 and 1b: the whole validator, on arbitrary and on schema-clean configs."""
    stats = {"runs": 0, "rejected": 0, "deep_runs": 0, "deep_rejected": 0}
    for _ in range(iterations):
        candidate = mut.mutate(mut.mutate(example))
        if check_list(cc.check, candidate, mutated_env(rng), True):
            stats["runs"] += 1
        else:
            stats["rejected"] += 1
    for _ in range(iterations):
        # Shaped to survive the schema pass, so the registry, manifest, and
        # secret-env passes are the ones under test.
        candidate = semantic_ish(rng, example, mut)
        if check_list(cc.check, candidate, mutated_env(rng), True):
            stats["deep_runs"] += 1
        else:
            stats["deep_rejected"] += 1
    return stats


def run_consumers(rng: random.Random, mut: Mutator, example: Json, iterations: int) -> int:
    """Target 2: the cross-file consumers on content the schema gate never narrows,
    each called directly, plus the bound on the count they report."""
    registered = len(dc.spec_ids())
    for _ in range(iterations):
        candidate = mut.mutate(mut.mutate(example))
        check_list(cc.registry_errors, candidate)
        check_list(cc.threshold_errors, candidate)
        check_list(cc.secret_env_errors, candidate, mutated_env(rng))
        unlisted = cc.unlisted_detectors(candidate)
        if not 0 <= unlisted <= registered:
            raise InvariantBrokenError(
                f"unlisted_detectors: expected a count in 0..{registered}, got {unlisted!r}"
            )
    return iterations


def run_files(
    rng: random.Random, mut: Mutator, tmp: pathlib.Path, example: Json, iterations: int
) -> dict[str, int]:
    """Target 3: the file entry point, on corrupted bytes."""
    stats = {"files": 0, "rejected": 0}
    for _ in range(iterations):
        raw = mutate_file_bytes(rng, json.dumps(mut.mutate(example)).encode("utf-8"))
        _config, error = check_load(tmp, raw)
        if error is None:
            stats["files"] += 1
        else:
            stats["rejected"] += 1
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_fuzz_args(ap, default_iterations=2000)
    args = fuzz_args(ap)
    rng = random.Random(args.seed)  # noqa: S311 - seeded corpus fuzzing, not a secret
    mut = Mutator(rng, weird_strings=DOMAIN_STRINGS, max_depth=4)

    current: Json = {}
    try:
        example = shipped_example()
        current = example
        digest = sensitivity(example)
        SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="fuzz-config-", dir=SCRATCH) as td:
            tmp = pathlib.Path(td)
            configs = run_configs(rng, mut, example, args.iterations)
            current = semantic_ish(rng, example, mut)
            consumers = run_consumers(rng, mut, example, args.iterations)
            files = run_files(rng, mut, tmp, example, args.iterations)
            file_boundary_pair(tmp, example, digest)
    except InvariantBrokenError as exc:
        print(f"fuzz-config-check: FAIL: {exc}", file=sys.stderr)
        print("input:", json.dumps(current)[:400], file=sys.stderr)
        return 1

    print(
        f"fuzz-config-check: ok seed={args.seed} iterations={args.iterations} "
        f"rejected={configs['rejected']}/{configs['runs'] + configs['rejected']} "
        f"deep_rejected={configs['deep_rejected']}/"
        f"{configs['deep_runs'] + configs['deep_rejected']} "
        f"consumer_runs={consumers} "
        f"file_rejected={files['rejected']}/{files['files'] + files['rejected']} "
        f"sensitivity=ok"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
