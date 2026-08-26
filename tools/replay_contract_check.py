"""Exercise design-time replay contracts before the Phase 4 replay harness exists."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, TypeGuard

try:
    import yaml
except ModuleNotFoundError:
    sys.exit("replay-contract: missing dependency PyYAML; run `make setup`")

ROOT = pathlib.Path(__file__).resolve().parent.parent
TRACE = ROOT / "tools/fixtures/traces/inventory/stack.v1.sample.json"
SPEC = ROOT / "tools/detector_spec.yaml"


def _is_int(v: object) -> TypeGuard[int]:
    return isinstance(v, int) and not isinstance(v, bool)


def _case_errors(case: dict[str, Any], detector_id: str) -> tuple[list[str], int, int]:
    """Contract checks for one case. Returns (errors, events counted, work units counted)."""
    raw_name = case.get("name")
    name = raw_name if isinstance(raw_name, str) else "<unnamed>"
    events = case.get("events")
    expect = case.get("expect")
    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        return ([f"{name}: events must be an array of objects"], 0, 0)
    if not isinstance(expect, dict):
        return ([f"{name}: expect must be an object"], 0, 0)

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
    return (errors, len(events), max_work)


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
    total_events = 0
    total_work = 0
    for case in cases:
        case_errors, events, work = _case_errors(case, detector_id)
        errors += case_errors
        total_events += events
        total_work += work
    return errors + _budget_errors(trace.get("workBudget"), total_events, total_work)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()

    try:
        trace = json.loads(TRACE.read_text(encoding="utf-8"))
        detector_ids = {
            d["id"] for d in yaml.safe_load(SPEC.read_text(encoding="utf-8"))["detectors"]
        }
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        print(f"replay-contract: unreadable fixture or spec: {exc}", file=sys.stderr)
        return 1
    errors = contract_errors(trace, detector_ids)
    if errors:
        for error in errors:
            print(f"replay-contract: {error}")
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
