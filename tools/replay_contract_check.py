#!/usr/bin/env python3
"""Exercise design-time replay contracts before the Phase 4 replay harness exists."""
from __future__ import annotations

import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
TRACE = ROOT / "tools/fixtures/traces/inventory/stack.v1.sample.json"
SPEC = ROOT / "tools/detector_spec.yaml"


def main() -> int:
    trace = json.loads(TRACE.read_text(encoding="utf-8"))
    detector_ids = {d["id"] for d in yaml.safe_load(SPEC.read_text(encoding="utf-8"))["detectors"]}
    errors: list[str] = []
    if trace["detectorId"] not in detector_ids:
        errors.append(f"unknown detector: {trace['detectorId']}")
    classes = {case["class"] for case in trace["cases"]}
    if classes != {"normal", "violation"}:
        errors.append("sample must exercise normal and violation classes")
    total_events = 0
    total_work = 0
    for case in trace["cases"]:
        sequences = [event["sequence"] for event in case["events"]]
        if sequences != sorted(set(sequences)):
            errors.append(f"{case['name']}: sequence values must be unique and increasing")
        total_events += len(case["events"])
        total_work += case["expect"]["maxWorkUnits"]
        findings = case["expect"]["findingDetectorIds"]
        if case["class"] == "normal" and findings:
            errors.append(f"{case['name']}: normal case expects findings")
        if case["class"] == "violation" and findings != [trace["detectorId"]]:
            errors.append(f"{case['name']}: violation must expect exactly {trace['detectorId']}")
        if case["expect"]["actions"]:
            errors.append(f"{case['name']}: observe-mode contract must expect no actions")
        for event in case["events"]:
            claimed = event["values"]["claimedDestinationQuantity"]
            limit = event["authoritative"]["itemStackLimit"]
            should_find = claimed > limit
            if should_find != bool(findings):
                errors.append(f"{case['name']}: expectation disagrees with stack invariant")
    budget = trace["workBudget"]
    if total_events > budget["maxEvents"]:
        errors.append("trace exceeds maxEvents")
    if total_work > budget["maxWorkUnits"]:
        errors.append("trace exceeds maxWorkUnits")
    if errors:
        for error in errors:
            print(f"replay-contract: {error}")
        return 1
    print(f"replay-contract: exercised {len(trace['cases'])} cases, {total_events} events, {total_work} work units")
    return 0


if __name__ == "__main__":
    sys.exit(main())
