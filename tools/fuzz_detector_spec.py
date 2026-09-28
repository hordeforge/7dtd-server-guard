"""Fuzz the canonical detector spec and every consumer of it.

tools/detector_spec.yaml is the single source of truth for detector identity,
input authority, thresholds, contexts, and fixtures. Two tools consume it:
doccheck validates it and cross-references it, and render_detectors renders
docs/DETECTORS.md and the config manifest from it. A hand-edited spec is
untrusted input to both, and every check in doccheck's gate runs
unconditionally in one pass, so an unhandled record crashes the gate that is
supposed to report it. This harness throws structure-aware mutations at both
consumers:

  target 1  load_spec                                     (YAML parse, mutated and
                                                           corrupted document text)
  target 2  check_spec / spec_ids / _manifest_errors /    (the doccheck spec
           _example_mode_errors                            cross-references)
  target 3  validate / validated / render_tables /         (the render and
           render_fixture_matrix / render_seam_map /       manifest path)
           render_manifest

Invariants asserted per iteration:
  - load_spec either returns a list or raises render_detectors.SpecError; no
    KeyError, TypeError, or AttributeError escapes a parse.
  - Every doccheck spec consumer returns a list of str (or a set of str) and
    never raises, on any spec content.
  - Renderers never raise on a structurally valid record, whatever the types of
    the fields validate() does not cover (inputs, fixtures, contexts, seam).
  - Determinism: two consecutive runs on the same content return equal results.
  - Pair assertions across the spec trust boundary: the pristine spec validates
    clean, and each required field is caught when dropped or mistyped.

Deterministic (seeded PRNG), stdlib only, no external fuzzer required.

Usage:
  uv run python tools/fuzz_detector_spec.py [--iterations N] [--seed S]
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import random
import sys
import tempfile
from collections.abc import Callable
from typing import Any, cast

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import doccheck as dc
import render_detectors as rd
from fuzz_common import InvariantBrokenError, Mutator, add_fuzz_args, fuzz_args

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = rd.SPEC
# Temporary spec files go to the repo's gitignored scratch dir, not the system
# temp dir: /tmp is tmpfs here, so thousands of iterations would be charged to RAM.
SCRATCH = ROOT / ".scratch"
EXAMPLE = json.loads((ROOT / "config" / "server-guard.example.json").read_text(encoding="utf-8"))

# Vocabulary the spec validators branch on, so mutants land on both sides of
# every rule rather than on the reject path alone.
DOMAIN_STRINGS = [
    "protocol.stage_order",
    "inventory.stack",
    "observe",
    "enforce",
    "Hard",
    "Advisory",
    "protocol",
    "server-derived",
    "client-declared",
    "decision",
    "normal",
    "violation",
    "int",
    "float",
    "string",
]
# Corpus size: three detectors from three different families carry every field
# shape the spec uses, and keep the YAML round-trip cheap enough for thousands of
# iterations. Fields that only some detectors declare are normalized below.
CORPUS_FAMILIES = ("protocol", "inventory", "world")
CORPUS_SIZE = 3
# A callback that validates a spec document and returns the gate's error list.
SpecReader = Callable[[list[Any]], list[str]]
# Result type of the callbacks with_spec runs against a temporarily swapped spec.

# Optional fields: validate() does not constrain them, so the render path has to
# survive any value at all. These are exactly the ones the renderers subscript.
OPTIONAL_FIELDS = ("inputs", "fixtures", "contexts", "seam", "algorithm", "state", "hard_condition")

# Probability that a spec-file iteration corrupts the document text after dumping
# the mutated structure, exercising the YAML parser rather than only the loaders.
P_CORRUPT_TEXT = 0.15
# Probability that a mutant is rewritten into a multi-detector document, and that a
# record keeps an optional field it did not declare.
P_MULTI_DETECTOR = 0.5
P_KEEP_OPTIONAL_FIELD = 0.5


def load_pristine() -> list[Any]:
    """The shipped spec, reduced to a mutation-sized corpus."""
    detectors = rd.load_spec()
    by_family: dict[str, Any] = {}
    for d in detectors:
        if isinstance(d, dict) and isinstance(d.get("family"), str):
            by_family.setdefault(d["family"], d)
    corpus = [copy.deepcopy(by_family[f]) for f in CORPUS_FAMILIES if f in by_family]
    if len(corpus) != CORPUS_SIZE:
        raise InvariantBrokenError(
            f"corpus wants {CORPUS_SIZE} detectors from {CORPUS_FAMILIES}, got {len(corpus)}"
        )
    return corpus


def spec_text(detectors: list[Any]) -> str | None:
    """The spec document for these records, or None when the dump is unwritable."""
    try:
        return yaml.safe_dump({"schema_version": 1, "detectors": detectors}, sort_keys=False)
    except yaml.YAMLError:
        return None


def with_spec[T](path: pathlib.Path, text: str, run: Callable[[], T]) -> T:
    """Run `run` with the spec consumers pointed at `path`, then restore them."""
    original = rd.SPEC
    path.write_text(text, encoding="utf-8")
    rd.SPEC = path
    rd.load_spec.cache_clear()
    try:
        return run()
    finally:
        rd.SPEC = original
        rd.load_spec.cache_clear()


def check_load_spec(path: pathlib.Path, text: str, where: str) -> int:
    """target 1: the parser returns a list or raises SpecError, nothing else."""
    try:
        detectors = with_spec(path, text, rd.load_spec)
    except rd.SpecError:
        return 0
    except Exception as exc:
        raise InvariantBrokenError(
            f"{where}: load_spec raised {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(detectors, list):
        raise InvariantBrokenError(
            f"{where}: load_spec returned {type(detectors).__name__}, not a list"
        )
    return len(detectors)


def check_consumers(path: pathlib.Path, text: str, where: str) -> list[str]:
    """target 2: the doccheck spec pass reports problems, it never crashes on them."""

    def run() -> list[str]:
        errs = dc.check_spec()
        if not all(isinstance(e, str) for e in errs):
            raise InvariantBrokenError(f"{where}: check_spec returned non-str elements: {errs!r}")
        # Determinism: the pass must repeat identically on the same bytes.
        if dc.check_spec() != errs:
            raise InvariantBrokenError(f"{where}: check_spec is nondeterministic")
        ids = dc.spec_ids()
        if not all(isinstance(i, str) for i in ids):
            raise InvariantBrokenError(f"{where}: spec_ids returned non-str elements: {ids!r}")
        mode_errs = dc._example_mode_errors(EXAMPLE)
        if dc._example_mode_errors(EXAMPLE) != mode_errs:
            raise InvariantBrokenError(f"{where}: _example_mode_errors is nondeterministic")
        collected = [*errs, *mode_errs]
        dc._manifest_errors(EXAMPLE, collected)
        if not all(isinstance(e, str) for e in collected):
            raise InvariantBrokenError(f"{where}: cross-references returned non-str elements")
        return collected

    try:
        return list(with_spec(path, text, run))
    except InvariantBrokenError:
        raise
    except Exception as exc:
        raise InvariantBrokenError(
            f"{where}: doccheck spec consumers raised {type(exc).__name__}: {exc}"
        ) from exc


def check_renderers(detectors: list[Any], where: str) -> int:
    """target 3: the render path survives any value in an unconstrained field."""
    try:
        validated = rd.validated(detectors)
    except rd.SpecError:
        return 0
    try:
        for render in (rd.render_tables, rd.render_fixture_matrix, rd.render_seam_map):
            out = render(validated)
            if not isinstance(out, str):
                raise InvariantBrokenError(
                    f"{where}: {render.__name__} returned {type(out).__name__}"
                )
        manifest = rd.render_manifest(validated)
        if set(manifest) != {"manifestVersion", "detectors"}:
            raise InvariantBrokenError(f"{where}: manifest keys are {sorted(manifest)}")
        json.dumps(manifest)
    except InvariantBrokenError:
        raise
    except Exception as exc:
        raise InvariantBrokenError(
            f"{where}: render path raised {type(exc).__name__}: {exc}"
        ) from exc
    if rd.validate(detectors) != rd.validate(detectors):
        raise InvariantBrokenError(f"{where}: validate is nondeterministic")
    return len(validated)


def check_pairs(path: pathlib.Path) -> str:
    """Every required field is caught when dropped or mistyped, on the real spec."""
    pristine = rd.load_spec()
    record = cast("dict[str, Any]", pristine[0])
    if rd.validate(pristine):
        raise InvariantBrokenError(
            f"pristine spec fails structural validation: {rd.validate(pristine)}"
        )
    if dc.check_spec():
        raise InvariantBrokenError(f"pristine spec reported errors: {dc.check_spec()[:3]}")
    if len(rd.identified(pristine)) != len(pristine):
        raise InvariantBrokenError("the pristine spec has records without a usable id")

    def reported(detectors: list[Any]) -> list[str]:
        text = spec_text(detectors)
        if text is None:
            raise InvariantBrokenError(
                "a corpus record does not round-trip through the YAML dumper"
            )
        return list(with_spec(path, text, dc.check_spec))

    report = []
    for field, typ in sorted(rd.REQUIRED_FIELDS.items()):
        for label, broken in (
            ("missing", {k: v for k, v in record.items() if k != field}),
            ("mistyped", {**record, field: ["not", "a", typ.__name__]}),
        ):
            report.extend(field_sensitivity(field, label, broken, reported))
    report.extend(threshold_sensitivity(record))
    report.extend(record_sensitivity(reported))
    if report:
        raise InvariantBrokenError("; ".join(report))
    return f"{len(rd.REQUIRED_FIELDS)} fields + {len(rd.REQUIRED_THRESHOLD_FIELDS)} thresholds"


def field_sensitivity(
    field: str, label: str, broken: dict[str, Any], reported: SpecReader
) -> list[str]:
    """A required field is caught by both validators when the record loses it."""
    out = []
    if not rd.validate([broken]):
        out.append(f"validate accepted a {label} {field}")
    if not any(field in e for e in reported([broken])):
        out.append(f"check_spec accepted a {label} {field}")
    return out


def threshold_sensitivity(record: dict[str, Any]) -> list[str]:
    """A threshold is caught when it loses one of the fields the manifest projects."""
    out = []
    for field in rd.REQUIRED_THRESHOLD_FIELDS:
        broken = copy.deepcopy(record)
        broken["thresholds"] = [{"key": "k", "type": "int", "range": [0, 1], "default": 0}]
        del broken["thresholds"][0][field]
        if not rd.validate([broken]):
            out.append(f"validate accepted a threshold missing {field}")
    return out


def record_sensitivity(reported: SpecReader) -> list[str]:
    """A record that is not a usable mapping is reported, not subscripted."""
    out = []
    for label, broken in (("a bare record", {"id": "x"}), ("a non-mapping record", [["nope"]])):
        if not rd.validate([broken]):
            out.append(f"validate accepted {label}")
    if not any("string id" in e for e in reported([["nope"]])):
        out.append("check_spec accepted a non-mapping record")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    add_fuzz_args(ap, default_iterations=400)
    args = fuzz_args(ap)
    rng = random.Random(args.seed)  # noqa: S311 - seeded corpus fuzzing, not a secret
    mut = Mutator(rng, weird_strings=DOMAIN_STRINGS, max_depth=4)

    corpus = load_pristine()
    stats = {"parsed": 0, "rejected_specs": 0, "consumer_errors": 0, "rendered": 0, "skipped": 0}
    SCRATCH.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fuzz-detector-spec-", dir=SCRATCH) as td:
        tmp = pathlib.Path(td) / "detector_spec.yaml"

        for _ in range(args.iterations):
            # target 1 and 2 share a mutant: the YAML text is the input to both.
            mutant = mut.mutate(copy.deepcopy(rng.choice(corpus)))
            if rng.random() < P_MULTI_DETECTOR:
                mutant = (
                    [mutant]
                    if rng.random() < P_KEEP_OPTIONAL_FIELD
                    else [mutant, rng.choice(corpus)]
                )
            text = spec_text(mutant)
            if text is None:
                stats["skipped"] += 1
                continue
            if rng.random() < P_CORRUPT_TEXT:
                text = text[: max(1, int(len(text) * rng.random()))]
            try:
                stats["parsed"] += check_load_spec(tmp, text, "mutant spec")
                found = check_consumers(tmp, text, "mutant spec")
                stats["consumer_errors"] += len(found)
                if found:
                    stats["rejected_specs"] += 1
            except InvariantBrokenError as exc:
                print(f"fuzz-detector-spec: FAIL: {exc}", file=sys.stderr)
                print("input:", text[:400], file=sys.stderr)
                return 1

        # target 3: keep the structural fields intact so the render path is what
        # is under test, and corrupt only the fields validate() leaves free.
        for _ in range(args.iterations):
            mutant = copy.deepcopy(rng.choice(corpus))
            for field in OPTIONAL_FIELDS:
                if field in mutant or rng.random() < P_KEEP_OPTIONAL_FIELD:
                    mutant[field] = mut.value(mutant.get(field))
            try:
                stats["rendered"] += check_renderers([mutant], "mutant record")
            except InvariantBrokenError as exc:
                print(f"fuzz-detector-spec: FAIL: {exc}", file=sys.stderr)
                print("input:", yaml.safe_dump(mutant, sort_keys=False)[:400], file=sys.stderr)
                return 1

        pairs = check_pairs(tmp)

    print(
        f"fuzz-detector-spec: ok seed={args.seed} iterations={args.iterations} "
        f"specs_parsed={stats['parsed']} specs_rejected={stats['rejected_specs']} "
        f"consumer_errors={stats['consumer_errors']} records_rendered={stats['rendered']} "
        f"undumpable={stats['skipped']} sensitivity={pairs}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
