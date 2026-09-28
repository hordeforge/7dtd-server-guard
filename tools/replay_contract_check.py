"""Exercise design-time replay contracts before the Phase 4 replay harness exists.

Usage:
  uv run python tools/replay_contract_check.py [--self-test | --fix-fingerprint]

Exit codes: 0 the vector satisfies the contract, 1 the contract failed or a
fixture could not be read, 2 usage error. The summary goes to stdout and
contract failures to stderr.
"""

from __future__ import annotations

import argparse
import datetime
import json
import math
import pathlib
import re
import sys
from collections.abc import Callable
from typing import Any, NamedTuple, TypeGuard

from evidence_check import record_hash

try:
    import yaml
except ModuleNotFoundError:
    sys.exit("replay-contract: missing dependency PyYAML; run `make setup`")

ROOT = pathlib.Path(__file__).resolve().parent.parent
TRACE = ROOT / "tools/fixtures/traces/inventory/stack.v1.sample.json"
SPEC = ROOT / "tools/detector_spec.yaml"

UTC_INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
# The recorded digest, with its quotes and value, for resealing a fixture in place.
FINGERPRINT_FIELD = re.compile(r'("fingerprint":\s*")[0-9a-f]{64}(")')

# Reported non-finite paths before the count collapses into a summary line.
MAX_REPORTED_NON_FINITE = 5


def _is_int(v: object) -> TypeGuard[int]:
    return isinstance(v, int) and not isinstance(v, bool)


def non_finite_paths(value: object, path: str = "trace") -> list[str]:
    """JSON paths of every NaN/Infinity in the trace, in document order.

    Bare NaN and Infinity are not JSON, and the fingerprint and per-record
    hashes are computed by json.dumps with allow_nan=False, so a trace carrying
    one cannot be canonicalized, sealed, or replayed. The walk is iterative so
    a deeply nested trace cannot turn this check into a RecursionError, and each
    node's children are pushed in reverse so the visit order is the document's
    own: the reported cap names the earliest occurrences, not whichever paths
    happen to sort first.
    """
    found: list[str] = []
    stack: list[tuple[object, str]] = [(value, path)]
    while stack:
        node, node_path = stack.pop()
        if isinstance(node, float) and not math.isfinite(node):
            found.append(node_path)
        elif isinstance(node, dict):
            stack.extend((v, f"{node_path}.{k}") for k, v in reversed(list(node.items())))
        elif isinstance(node, list):
            stack.extend((v, f"{node_path}[{i}]") for i, v in reversed(list(enumerate(node))))
    return found


def non_finite_errors(value: object) -> list[str]:
    """Contract errors for non-finite numbers, capped so one bad trace cannot
    bury the rest of the report under thousands of paths."""
    paths = non_finite_paths(value)
    errors = [
        f"trace: non-finite number at {p}: JSON has no NaN or Infinity literal"
        for p in paths[:MAX_REPORTED_NON_FINITE]
    ]
    hidden = len(paths) - MAX_REPORTED_NON_FINITE
    if hidden > 0:
        errors.append(f"trace: {hidden} further non-finite value(s)")
    return errors


def _expect(case: dict[str, Any]) -> dict[str, Any]:
    """The case expectation block, or empty when a mutant removed or replaced it."""
    expect = case.get("expect")
    return expect if isinstance(expect, dict) else {}


def outcome_fingerprint(trace: dict[str, Any]) -> str:
    """SHA-256 over the canonical replay outcome projection (docs/SCHEMAS.md).

    The projection pins what a replay must reproduce: the run header the trace
    declares, the virtual clock origin, and, per case in file order, the class,
    expected findings and actions, and the work-unit charge. The Phase 4 harness
    recomputes it from what its detectors actually produced and compares, so a
    diverging replay is one digest apart rather than a hand-read diff.
    """
    determinism = trace.get("determinism")
    origin = determinism if isinstance(determinism, dict) else {}
    projection = {
        "build": trace.get("build"),
        "cases": [
            {
                "actions": _expect(case).get("actions"),
                "class": case.get("class"),
                "findingDetectorIds": _expect(case).get("findingDetectorIds"),
                "maxWorkUnits": _expect(case).get("maxWorkUnits"),
                "name": case.get("name"),
            }
            for case in trace["cases"]
        ],
        "detectorId": trace.get("detectorId"),
        "mode": trace.get("mode"),
        "seed": trace.get("seed"),
        "startMonotonicMs": origin.get("startMonotonicMs"),
        "startUtc": origin.get("startUtc"),
        "workBudget": trace.get("workBudget"),
    }
    return record_hash(projection)


def _determinism_errors(trace: dict[str, Any]) -> list[str]:
    """The trace must declare the virtual clock it replays against.

    Without an origin the harness has nothing to fill the evidence stream's
    required `utc` and `monotonicMs` from except the host wall clock, and the
    replay stops being reproducible on another machine.
    """
    determinism = trace.get("determinism")
    if not isinstance(determinism, dict):
        return [
            "trace: missing or non-object determinism block "
            "(virtual clock origin and replay fingerprint)"
        ]
    errors: list[str] = []

    start_utc = determinism.get("startUtc")
    if not isinstance(start_utc, str) or not UTC_INSTANT.match(start_utc):
        errors.append(
            "trace: determinism.startUtc must be an ISO-8601 UTC instant with milliseconds"
        )
    else:
        try:
            datetime.datetime.fromisoformat(start_utc)
        except ValueError:
            errors.append(f"trace: determinism.startUtc {start_utc!r} is not a valid instant")

    start_ms = determinism.get("startMonotonicMs")
    if not _is_int(start_ms) or start_ms < 0:
        errors.append("trace: determinism.startMonotonicMs must be a non-negative integer")

    fingerprint = determinism.get("fingerprint")
    if not isinstance(fingerprint, str) or not SHA256_HEX.match(fingerprint):
        errors.append(
            "trace: determinism.fingerprint must be a 64-character lowercase SHA-256 hex digest"
        )
    elif not errors:
        # The projection is serialized with allow_nan=False, so a NaN or Infinity
        # anywhere in it (a seed, a work budget) has no canonical JSON form and no
        # digest to compare against. That is a defect in the trace and is reported,
        # not raised: this function's contract is to return an error list for any
        # input rather than fail the run with a traceback.
        try:
            expected = outcome_fingerprint(trace)
        except ValueError as exc:
            errors.append(f"trace: outcome projection is not canonical JSON: {exc}")
        else:
            if fingerprint != expected:
                errors.append(
                    f"trace: determinism.fingerprint {fingerprint[:16]}... does not match the "
                    f"replay outcome projection {expected[:16]}..."
                )
    return errors


class CaseResult(NamedTuple):
    """What one case contributes: its errors, how many events it declares, and how many
    work units its expectation charges against the trace's budget."""

    errors: list[str]
    event_count: int
    work_units: int


def _case_errors(case: dict[str, Any], detector_id: str) -> CaseResult:
    """Contract checks for one case."""
    raw_name = case.get("name")
    name = raw_name if isinstance(raw_name, str) else "<unnamed>"
    events = case.get("events")
    expect = case.get("expect")
    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        return CaseResult([f"{name}: events must be an array of objects"], 0, 0)
    if not isinstance(expect, dict):
        return CaseResult([f"{name}: expect must be an object"], 0, 0)

    errors: list[str] = []
    sequences = [event.get("sequence") for event in events]
    if not all(_is_int(s) for s in sequences):
        errors.append(f"{name}: sequence must be an integer")
    elif sequences != sorted(set(sequences)):
        errors.append(f"{name}: sequence values must be unique and increasing")

    max_work = expect.get("maxWorkUnits")
    if not _is_int(max_work):
        errors.append(f"{name}: maxWorkUnits must be an integer")
        max_work = 0

    # A case that steps time backwards makes the run order-dependent, so the same
    # seed on the same trace stops reproducing the same result.
    ticks = [event.get("tick") for event in events]
    if not all(_is_int(t) for t in ticks):
        errors.append(f"{name}: tick must be an integer")
    elif ticks != sorted(ticks):
        errors.append(f"{name}: tick must not decrease as sequence increases")

    findings = expect.get("findingDetectorIds")
    if not isinstance(findings, list):
        findings = []
        errors.append(f"{name}: findingDetectorIds must be an array")
    if case.get("class") == "normal" and findings:
        errors.append(f"{name}: normal case must expect no findings")
    if case.get("class") == "violation" and findings != [detector_id]:
        errors.append(f"{name}: violation must expect exactly {detector_id}")
    if expect.get("actions"):
        errors.append(f"{name}: observe-mode contract must expect no actions")

    errors += _stack_invariant_errors(events, name, expected_findings=bool(findings))
    return CaseResult(errors, len(events), max_work)


def _stack_invariant_errors(
    events: list[dict[str, Any]], name: str, *, expected_findings: bool
) -> list[str]:
    """The declared expectation must agree with the stack invariant each event encodes."""
    errors: list[str] = []
    for event in events:
        values = event.get("values")
        authoritative = event.get("authoritative")
        claimed = values.get("claimedDestinationQuantity") if isinstance(values, dict) else None
        limit = authoritative.get("itemStackLimit") if isinstance(authoritative, dict) else None
        if not _is_int(claimed) or not _is_int(limit):
            errors.append(
                f"{name}: event needs integer values.claimedDestinationQuantity "
                "and authoritative.itemStackLimit"
            )
            continue
        if (claimed > limit) != expected_findings:
            errors.append(f"{name}: expectation disagrees with stack invariant")
    return errors


def _budget_errors(budget: object, total_events: int, total_work: int) -> list[str]:
    """The trace's declared work budget must cover what its cases actually spend."""
    if not isinstance(budget, dict):
        return ["trace: workBudget must be an object"]
    errors: list[str] = []
    max_events = budget.get("maxEvents")
    if not _is_int(max_events):
        errors.append("trace: workBudget.maxEvents must be an integer")
    elif total_events > max_events:
        errors.append("trace exceeds maxEvents")
    max_work_units = budget.get("maxWorkUnits")
    if not _is_int(max_work_units):
        errors.append("trace: workBudget.maxWorkUnits must be an integer")
    elif total_work > max_work_units:
        errors.append("trace exceeds maxWorkUnits")
    return errors


def contract_errors(trace: object, detector_ids: set[str]) -> list[str]:
    """Semantic contract checks over one parsed replay trace.

    Returns human-readable errors; never raises on malformed content, so callers
    get an error report instead of a traceback for hand-edited or generated
    traces that drift from config/schemas/replay-trace.v1.schema.json.
    """
    if not isinstance(trace, dict):
        return ["trace must be a JSON object"]
    non_finite = non_finite_errors(trace)
    if non_finite:
        return non_finite
    detector_id = trace.get("detectorId")
    if not isinstance(detector_id, str):
        return ["trace: missing or non-string detectorId"]

    errors: list[str] = []
    if detector_id not in detector_ids:
        errors.append(f"unknown detector: {detector_id}")
    cases = trace.get("cases")
    if not isinstance(cases, list) or not all(isinstance(c, dict) for c in cases):
        return [*errors, "trace: cases must be an array of objects"]

    classes = {c for c in (case.get("class") for case in cases) if isinstance(c, str)}
    if classes != {"normal", "violation"}:
        errors.append("sample must exercise normal and violation classes")
    seed = trace.get("seed")
    if not _is_int(seed) or seed < 0:
        errors.append("trace: seed must be a non-negative integer")
    total_events = 0
    total_work = 0
    for case in cases:
        result = _case_errors(case, detector_id)
        errors += result.errors
        total_events += result.event_count
        total_work += result.work_units
    errors += _determinism_errors(trace)
    return errors + _budget_errors(trace.get("workBudget"), total_events, total_work)


def seal_fingerprint(trace: dict[str, Any], text: str) -> str | None:
    """The trace text with its recorded digest replaced by the current projection.

    Only the digest is touched, so re-sealing a fixture does not reflow its
    hand-written layout. Returns None when the file holds no digest to replace
    or holds more than one, where picking one would guess.
    """
    digest = outcome_fingerprint(trace)
    if len(FINGERPRINT_FIELD.findall(text)) != 1:
        return None
    return FINGERPRINT_FIELD.sub(rf"\g<1>{digest}\g<2>", text, count=1)


def _pristine() -> tuple[dict[str, Any], str]:
    """The shipped fixture, parsed and as text, the two forms every case starts from."""
    text = TRACE.read_text(encoding="utf-8")
    return json.loads(text), text


def _put(trace: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    """Assign at a path of dict keys and list indices, so a case reads as the edit it makes."""
    node: Any = trace
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def _reseal(trace: dict[str, Any]) -> None:
    trace["determinism"]["fingerprint"] = outcome_fingerprint(trace)


def self_test() -> list[str]:
    """Negative cases: every rejection rule, fired once from a mutation of the fixture.

    The default run verifies the shipped fixture, so it proves only that one trace
    satisfies the contract. A checker that returned no errors for every input would
    pass it, and so would one whose comparison is inverted. Each case here mutates
    the real fixture and names the message its rule must produce.

    `reseal` is False for the cases that edit the determinism block or the shape
    of the trace, where a reseal would raise or mask the message. Everywhere else
    the mutant is resealed first, so a fingerprint mismatch cannot stand in for
    the rule under test.
    """
    failures: list[str] = []
    try:
        trace, text = _pristine()
    except (OSError, ValueError) as exc:
        return [f"self-test: shipped fixture unreadable: {exc}"]
    if errs := contract_errors(trace, {"inventory.stack"}):
        failures.append(f"self-test: shipped fixture reported errors: {errs}")

    normal_findings = ("cases", 0, "expect", "findingDetectorIds")
    violation_findings = ("cases", 1, "expect", "findingDetectorIds")
    cases: tuple[tuple[str, Callable[[dict[str, Any]], None], str, bool], ...] = (
        (
            "an unknown detector id",
            lambda t: _put(t, ("detectorId",), "inventory.stak"),
            "unknown detector: inventory.stak",
            True,
        ),
        (
            "a class the sample does not exercise both ways",
            lambda t: t.__setitem__("cases", [c for c in t["cases"] if c["class"] != "violation"]),
            "sample must exercise normal and violation classes",
            True,
        ),
        (
            "an event sequence that repeats",
            lambda t: t["cases"][0]["events"].append(dict(t["cases"][0]["events"][0], tick=101)),
            "sequence values must be unique and increasing",
            True,
        ),
        (
            "a normal case claiming over the stack limit but expecting no finding",
            lambda t: _put(
                t, ("cases", 0, "events", 0, "values", "claimedDestinationQuantity"), 51
            ),
            "expectation disagrees with stack invariant",
            True,
        ),
        (
            "a normal case expecting a finding",
            lambda t: _put(t, normal_findings, ["inventory.stack"]),
            "normal case must expect no findings",
            True,
        ),
        (
            "a violation case expecting nothing",
            lambda t: _put(t, violation_findings, []),
            "violation must expect exactly inventory.stack",
            True,
        ),
        (
            "an expectation of operator actions in observe mode",
            lambda t: _put(t, ("cases", 0, "expect", "actions"), ["warn"]),
            "observe-mode contract must expect no actions",
            True,
        ),
        (
            "a work budget one event short",
            lambda t: _put(t, ("workBudget", "maxEvents"), 1),
            "trace exceeds maxEvents",
            True,
        ),
        (
            "a work budget one unit short",
            lambda t: _put(t, ("workBudget", "maxWorkUnits"), 15),
            "trace exceeds maxWorkUnits",
            True,
        ),
        (
            "a work budget of the wrong shape",
            lambda t: _put(t, ("workBudget",), 32),
            "trace: workBudget must be an object",
            True,
        ),
        (
            "a seed that is a bool, not an integer",
            lambda t: _put(t, ("seed",), True),
            "trace: seed must be a non-negative integer",
            True,
        ),
        (
            "a non-finite number in the trace",
            lambda t: _put(t, ("build",), float("nan")),
            "non-finite number at trace.build",
            False,
        ),
        (
            "a trace with no cases",
            lambda t: t.pop("cases"),
            "trace: cases must be an array of objects",
            False,
        ),
        (
            "a case whose events are not objects",
            lambda t: _put(t, ("cases", 0, "events"), ["not-an-event"]),
            "events must be an array of objects",
            True,
        ),
        (
            "a clock origin that matches the instant shape but is not a date",
            lambda t: _put(t, ("determinism", "startUtc"), "2026-13-45T12:00:00.000Z"),
            "is not a valid instant",
            False,
        ),
        (
            "a clock origin without milliseconds",
            lambda t: _put(t, ("determinism", "startUtc"), "2026-07-21T12:00:00Z"),
            "must be an ISO-8601 UTC instant with milliseconds",
            False,
        ),
        (
            "a negative monotonic origin",
            lambda t: _put(t, ("determinism", "startMonotonicMs"), -1),
            "determinism.startMonotonicMs must be a non-negative integer",
            False,
        ),
        (
            "a fingerprint that is not a SHA-256 digest",
            lambda t: _put(t, ("determinism", "fingerprint"), "not-a-digest"),
            "64-character lowercase SHA-256 hex digest",
            False,
        ),
        (
            "a fingerprint that does not match the projection",
            lambda t: _put(t, ("determinism", "fingerprint"), "0" * 64),
            "does not match the replay outcome projection",
            False,
        ),
    )
    for what, mutate, fragment, reseal in cases:
        mutant = json.loads(json.dumps(trace))
        mutate(mutant)
        if reseal:
            _reseal(mutant)
        found = contract_errors(mutant, {"inventory.stack"})
        if not any(fragment in e for e in found):
            failures.append(f"self-test: {what} went unreported: {found}")

    # The boundary itself: a budget met exactly is a budget that covers the run.
    exact = json.loads(json.dumps(trace))
    exact["workBudget"]["maxEvents"] = sum(len(c["events"]) for c in exact["cases"])
    exact["workBudget"]["maxWorkUnits"] = sum(c["expect"]["maxWorkUnits"] for c in exact["cases"])
    _reseal(exact)
    if errs := contract_errors(exact, {"inventory.stack"}):
        failures.append(f"self-test: a work budget met exactly was rejected: {errs}")

    failures += _non_finite_self_test()
    failures += _seal_self_test(trace, text)
    return failures


def _non_finite_self_test() -> list[str]:
    """The non-finite report is capped, and says how many it did not print."""
    failures: list[str] = []
    trace: dict[str, Any] = {"cases": [float("nan"), float("inf"), float("-inf")]}
    for i in range(6):
        trace[f"k{i}"] = float("nan")
    found = non_finite_errors(trace)
    if len([e for e in found if "non-finite number" in e]) != MAX_REPORTED_NON_FINITE:
        failures.append(f"self-test: non-finite report was not capped: {found}")
    if not any("4 further non-finite value(s)" in e for e in found):
        failures.append(f"self-test: the hidden non-finite count was not reported: {found}")
    if non_finite_errors({}) or non_finite_errors({"a": [1, {"b": 2.0}]}):
        failures.append("self-test: a finite trace reported non-finite numbers")
    return failures


def _seal_self_test(trace: dict[str, Any], text: str) -> list[str]:
    """`--fix-fingerprint` replaces the recorded digest and nothing else."""
    failures: list[str] = []
    digest = outcome_fingerprint(trace)
    sealed = seal_fingerprint(trace, text)
    if sealed is None:
        return ["self-test: the shipped fixture could not be resealed"]
    if sealed != text:
        failures.append("self-test: resealing an up-to-date fixture changed its bytes")
    # A stale digest is the case the flag exists for: it is replaced in place, and
    # the result records the current projection.
    stale = FINGERPRINT_FIELD.sub(r"\g<1>" + "0" * 64 + r"\g<2>", text, count=1)
    fixed = seal_fingerprint(trace, stale)
    if fixed is None or fixed != sealed:
        failures.append("self-test: a stale fingerprint was not resealed to the projection")
    if fixed is not None and digest not in fixed:
        failures.append("self-test: the resealed fixture records no digest")
    if fixed is not None and FINGERPRINT_FIELD.sub("digest", fixed) != FINGERPRINT_FIELD.sub(
        "digest", text
    ):
        failures.append("self-test: resealing changed more than the recorded digest")
    # A file holding no digest, or more than one, leaves the choice to a human.
    for body, what in (
        (FINGERPRINT_FIELD.sub("", text), "a fixture with no fingerprint field"),
        (text + text, "a fixture with two fingerprint fields"),
    ):
        if seal_fingerprint(trace, body) is not None:
            failures.append(f"self-test: {what} was resealed anyway")
    return failures


def _run_self_test() -> int:
    """Report the self-test the way a plain run reports a contract failure."""
    failures = self_test()
    stream = sys.stdout if not failures else sys.stderr
    print(f"replay-contract self-test: {len(failures)} issue(s)", file=stream)
    for failure in failures:
        print("  " + failure, file=stream)
    return 1 if failures else 0


def _fix_fingerprint(trace: dict[str, Any], text: str) -> int:
    """`--fix-fingerprint`: reseal the fixture in place, touching only the digest."""
    if not isinstance(trace.get("determinism"), dict):
        print("replay-contract: trace has no determinism block to seal", file=sys.stderr)
        return 1
    sealed = seal_fingerprint(trace, text)
    if sealed is None:
        print(
            f"replay-contract: {TRACE.relative_to(ROOT)} must hold exactly one "
            f"fingerprint field to reseal",
            file=sys.stderr,
        )
        return 1
    # newline="\n": the fixture is tracked with the repo's LF policy
    # (.gitattributes), so a text-mode write must not re-terminate every line
    # on a host whose default differs.
    TRACE.write_text(sealed, encoding="utf-8", newline="\n")
    print(f"replay-contract: resealed {TRACE.relative_to(ROOT)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--self-test", action="store_true", help="run the contract self-tests and exit")
    ap.add_argument(
        "--fix-fingerprint",
        action="store_true",
        help="reseal the fixture's determinism.fingerprint from its current projection",
    )
    args = ap.parse_args()

    if args.self_test:
        return _run_self_test()

    try:
        text = TRACE.read_text(encoding="utf-8")
        trace = json.loads(text)
        detector_ids = {
            d["id"] for d in yaml.safe_load(SPEC.read_text(encoding="utf-8"))["detectors"]
        }
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        print(f"replay-contract: unreadable fixture or spec: {exc}", file=sys.stderr)
        return 1

    if args.fix_fingerprint:
        return _fix_fingerprint(trace, text)

    errors = contract_errors(trace, detector_ids)
    if errors:
        for error in errors:
            print(f"replay-contract: {error}", file=sys.stderr)
        return 1
    cases = trace["cases"]
    total_events = sum(len(case["events"]) for case in cases)
    total_work = sum(case["expect"]["maxWorkUnits"] for case in cases)
    print(
        f"replay-contract: exercised {len(cases)} cases, "
        f"{total_events} events, {total_work} work units"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
