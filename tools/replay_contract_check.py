"""Exercise design-time replay contracts before the Phase 4 replay harness exists.

Usage:
  uv run python tools/replay_contract_check.py [--fix-fingerprint]

Exit codes: 0 the vector satisfies the contract, 1 the contract failed or a
fixture could not be read, 2 usage error. The summary goes to stdout and
contract failures to stderr.
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import re
import sys
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


def _is_int(v: object) -> TypeGuard[int]:
    return isinstance(v, int) and not isinstance(v, bool)


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
        expected = outcome_fingerprint(trace)
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--fix-fingerprint",
        action="store_true",
        help="reseal the fixture's determinism.fingerprint from its current projection",
    )
    args = ap.parse_args()

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
        if not isinstance(trace.get("determinism"), dict):
            print("replay-contract: trace has no determinism block to seal", file=sys.stderr)
            return 1
        sealed = seal_fingerprint(trace, text)
        if sealed is None:
            print(
                f"replay-contract: {TRACE.relative_to(ROOT)} must hold exactly one "
                "fingerprint field to reseal",
                file=sys.stderr,
            )
            return 1
        TRACE.write_text(sealed, encoding="utf-8")
        print(f"replay-contract: resealed {TRACE.relative_to(ROOT)}")
        return 0

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
