#!/usr/bin/env python3
"""Exercise design-time replay contracts before the Phase 4 replay harness exists."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

try:
    import yaml
except ModuleNotFoundError:
    sys.exit("replay-contract: missing dependency PyYAML; run `make setup` (or pip install -r requirements.txt)")

ROOT = pathlib.Path(__file__).resolve().parent.parent
TRACE = ROOT / "tools/fixtures/traces/inventory/stack.v1.sample.json"
SPEC = ROOT / "tools/detector_spec.yaml"


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def contract_errors(trace, detector_ids: set[str]) -> list[str]:
    """Semantic contract checks over one parsed replay trace.

    Returns human-readable errors; never raises on malformed content, so callers
    get an error report instead of a traceback for hand-edited or generated
    traces that drift from config/schemas/replay-trace.v1.schema.json.
    """
    errors: list[str] = []
    if not isinstance(trace, dict):
        return ["trace must be a JSON object"]
    detector_id = trace.get("detectorId")
    if not isinstance(detector_id, str):
        return ["trace: missing or non-string detectorId"]
    if detector_id not in detector_ids:
        errors.append(f"unknown detector: {detector_id}")
    cases = trace.get("cases")
    if not isinstance(cases, list) or not all(isinstance(c, dict) for c in cases):
        return errors + ["trace: cases must be an array of objects"]

    classes = {c for c in (case.get("class") for case in cases) if isinstance(c, str)}
    if classes != {"normal", "violation"}:
        errors.append("sample must exercise normal and violation classes")
    total_events = 0
    total_work = 0
    for case in cases:
        name = case.get("name") if isinstance(case.get("name"), str) else "<unnamed>"
        events = case.get("events")
        expect = case.get("expect")
        if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
            errors.append(f"{name}: events must be an array of objects")
            continue
        if not isinstance(expect, dict):
            errors.append(f"{name}: expect must be an object")
            continue
        sequences = [event.get("sequence") for event in events]
        if not all(_is_int(s) for s in sequences):
            errors.append(f"{name}: sequence must be an integer")
        elif sequences != sorted(set(sequences)):
            errors.append(f"{name}: sequence values must be unique and increasing")
        total_events += len(events)
        max_work = expect.get("maxWorkUnits")
        if _is_int(max_work):
            total_work += max_work
        else:
            errors.append(f"{name}: maxWorkUnits must be an integer")
        findings = expect.get("findingDetectorIds")
        if not isinstance(findings, list):
            findings = []
            errors.append(f"{name}: findingDetectorIds must be an array")
        if case.get("class") == "normal" and findings:
            errors.append(f"{name}: normal case expects findings")
        if case.get("class") == "violation" and findings != [detector_id]:
            errors.append(f"{name}: violation must expect exactly {detector_id}")
        if expect.get("actions"):
            errors.append(f"{name}: observe-mode contract must expect no actions")
        for event in events:
            values = event.get("values")
            authoritative = event.get("authoritative")
            claimed = values.get("claimedDestinationQuantity") if isinstance(values, dict) else None
            limit = authoritative.get("itemStackLimit") if isinstance(authoritative, dict) else None
            if not _is_int(claimed) or not _is_int(limit):
                errors.append(
                    f"{name}: event needs integer values.claimedDestinationQuantity "
                    "and authoritative.itemStackLimit")
                continue
            if (claimed > limit) != bool(findings):
                errors.append(f"{name}: expectation disagrees with stack invariant")

    budget = trace.get("workBudget")
    if not isinstance(budget, dict):
        errors.append("trace: workBudget must be an object")
        return errors
    max_events = budget.get("maxEvents")
    if _is_int(max_events):
        if total_events > max_events:
            errors.append("trace exceeds maxEvents")
    else:
        errors.append("trace: workBudget.maxEvents must be an integer")
    max_work_units = budget.get("maxWorkUnits")
    if _is_int(max_work_units):
        if total_work > max_work_units:
            errors.append("trace exceeds maxWorkUnits")
    else:
        errors.append("trace: workBudget.maxWorkUnits must be an integer")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()

    try:
        trace = json.loads(TRACE.read_text(encoding="utf-8"))
        detector_ids = {d["id"] for d in yaml.safe_load(SPEC.read_text(encoding="utf-8"))["detectors"]}
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
    print(f"replay-contract: exercised {len(cases)} cases, {total_events} events, {total_work} work units")
    return 0


if __name__ == "__main__":
    sys.exit(main())
