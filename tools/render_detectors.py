#!/usr/bin/env python3
"""Render the detector registry (docs/DETECTORS.md) and the per-detector config manifest
from the canonical spec (tools/detector_spec.yaml).

Usage (from repo root):
  python3 tools/render_detectors.py            regenerate docs/DETECTORS.md in place
  python3 tools/render_detectors.py --check    exit 1 if docs/DETECTORS.md is stale
  python3 tools/render_detectors.py --manifest emit config/detector-config-manifest.json
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = ROOT / "tools" / "detector_spec.yaml"
REGISTRY = ROOT / "docs" / "DETECTORS.md"
MANIFEST = ROOT / "config" / "detector-config-manifest.json"

FAMILY_TITLES = {
    "protocol": "Protocol and identity (Phase 4)",
    "movement": "Movement (Phase 5)",
    "combat": "Combat (Phase 6)",
    "progression": "Progression (Phase 8)",
    "inventory": "Inventory and economy (Phase 7)",
    "world": "World and entity (Phase 8)",
    "availability": "Availability (Phases 4 and 8)",
}
FAMILY_ORDER = ["protocol", "movement", "combat", "progression", "inventory", "world", "availability"]
AVAILABILITY_CEILING_SUFFIX = {"protocol.flood", "world.budget", "availability.cost", "availability.churn"}
FIXTURE_FAMILIES = ["normal", "violation", "latency-stall", "reconnect-duplicate-session",
                    "teleport-vehicle-death", "admin-mod-origin", "rollback", "induced-finding"]


def load_spec() -> list[dict]:
    data = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    return data["detectors"]


def authority_note(d: dict) -> str:
    decision = [i for i in d.get("inputs", []) if i.get("role") == "decision"]
    client = sorted(i["name"] for i in decision if i.get("authority") == "client-declared")
    parts = []
    if client:
        parts.append("decision inputs include client-declared " + ", ".join(client) + "; capped below Hard unless the hard condition holds")
    else:
        parts.append("all decision inputs server-derived")
    if d.get("hard_condition"):
        parts.append("hard condition: " + d["hard_condition"])
    return "; ".join(parts)


def ceiling_cell(d: dict) -> str:
    c = d["ceiling"]
    if d["id"] in AVAILABILITY_CEILING_SUFFIX:
        c += " (availability)"
    if d.get("hard_condition"):
        c += " (conditional)"
    return c


def render_tables(detectors: list[dict]) -> str:
    out = []
    for family in FAMILY_ORDER:
        rows = [d for d in detectors if d["family"] == family]
        out.append(f"## {FAMILY_TITLES[family]}\n")
        out.append("| ID | What it validates | Authority note | Ceiling | Contexts |")
        out.append("|---|---|---|---|---|")
        for d in rows:
            contexts = ", ".join(d.get("contexts", [])) or "none"
            out.append(
                f"| `{d['id']}` | {d['summary']} | {authority_note(d)} | {ceiling_cell(d)} | {contexts} |"
            )
        out.append("")
    return "\n".join(out)


def render_fixture_matrix(detectors: list[dict]) -> str:
    out = ["## Fixture coverage\n", "X marks the fixture families a detector must ship in TEST_PLAN.md Layer 4;",
           "declared per detector in `tools/detector_spec.yaml`. A detector is not considered for a mode",
           "raise until its declared fixture set is green in observe mode.\n",
           "| ID | " + " | ".join(FIXTURE_FAMILIES) + " |", "|---|" + "---|" * len(FIXTURE_FAMILIES)]
    for d in detectors:
        have = set(d.get("fixtures", []))
        cells = " | ".join("X" if f in have else "" for f in FIXTURE_FAMILIES)
        out.append(f"| `{d['id']}` | {cells} |")
    return "\n".join(out) + "\n"


def render_seam_map(detectors: list[dict]) -> str:
    out = ["## Seam map (V3.1.0 census candidates)\n",
           "Candidate authoritative seams from `7dtd-engine-research/il/netpackages-v3.1.0/INDEX.md`",
           "(193 types) and the protocol narratives; every seam is verified in Phase 1 before",
           "a hook is written. Declared per detector in `tools/detector_spec.yaml`.\n",
           "| Detector | Candidate seam |", "|---|---|"]
    for d in detectors:
        out.append(f"| `{d['id']}` | {d.get('seam', 'TBD (Phase 1 inventory)')} |")
    return "\n".join(out) + "\n"


def render_registry(detectors: list[dict]) -> str:
    txt = REGISTRY.read_text(encoding="utf-8")
    start = txt.find("<!-- REGISTRY:START -->")
    end = txt.find("<!-- REGISTRY:END -->")
    if start == -1 or end == -1:
        sys.exit("DETECTORS.md is missing REGISTRY:START/END markers; re-add them before rendering")
    tables = render_tables(detectors)
    matrix = render_fixture_matrix(detectors)
    seam_map = render_seam_map(detectors)
    body = tables + "\n" + matrix + "\n" + seam_map
    return txt[: start + len("<!-- REGISTRY:START -->")] + "\n\n" + body + "\n" + txt[end:]


def render_manifest(detectors: list[dict]) -> dict:
    manifest = {"manifestVersion": 1, "detectors": []}
    for d in detectors:
        entry = {"detectorId": d["id"], "phase": d["phase"], "ceiling": d["ceiling"],
                 "defaultMode": d["default_mode"], "seam": d.get("seam", "TBD (Phase 1 inventory)"),
                 **({"hardCondition": d["hard_condition"]} if d.get("hard_condition") else {})}
        if d.get("thresholds"):
            entry["thresholds"] = [
                {
                    "key": t["key"],
                    "type": t["type"],
                    "range": t["range"],
                    "default": t["default"],
                    **({"unit": t["unit"]} if t.get("unit") else {}),
                    **({"note": t["note"]} if t.get("note") else {}),
                }
                for t in d["thresholds"]
            ]
        manifest["detectors"].append(entry)
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="exit 1 if docs/DETECTORS.md is stale")
    ap.add_argument("--manifest", action="store_true", help="emit config/detector-config-manifest.json")
    args = ap.parse_args()

    detectors = load_spec()
    if args.manifest:
        manifest = render_manifest(detectors)
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {MANIFEST.relative_to(ROOT)} ({len(manifest['detectors'])} detectors)")
        return 0

    fresh = render_registry(detectors)
    current = REGISTRY.read_text(encoding="utf-8")
    if fresh != current:
        if args.check:
            print("docs/DETECTORS.md is stale; run python3 tools/render_detectors.py", file=sys.stderr)
            return 1
        REGISTRY.write_text(fresh, encoding="utf-8")
        print(f"regenerated {REGISTRY.relative_to(ROOT)}")
    else:
        print(f"{REGISTRY.relative_to(ROOT)} is current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
