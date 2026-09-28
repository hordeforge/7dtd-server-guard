"""Render the detector registry (docs/DETECTORS.md) and the per-detector config manifest
from the canonical spec (tools/detector_spec.yaml).

Usage (from repo root):
  uv run python tools/render_detectors.py            regenerate docs/DETECTORS.md in place
  uv run python tools/render_detectors.py --check    exit 1 if docs/DETECTORS.md is stale
  uv run python tools/render_detectors.py --manifest emit config/detector-config-manifest.json

Exit codes: 0 the generated files are current, 1 --check found a stale or missing
docs/DETECTORS.md (or the spec is unusable), 2 usage error.
"""

from __future__ import annotations

import argparse
import functools
import json
import pathlib
import sys
from typing import Any

try:
    import yaml
except ModuleNotFoundError:
    sys.exit("render-detectors: missing dependency PyYAML; run `make setup`")

# A detector entry as it appears in the spec. The spec is YAML from disk, so its
# value types are only guaranteed by the doccheck spec validator, not statically.
Detector = dict[str, Any]

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
FAMILY_ORDER = [
    "protocol",
    "movement",
    "combat",
    "progression",
    "inventory",
    "world",
    "availability",
]
AVAILABILITY_CEILING_SUFFIX = {
    "protocol.flood",
    "world.budget",
    "availability.cost",
    "availability.churn",
}
FIXTURE_FAMILIES = [
    "normal",
    "violation",
    "latency-stall",
    "reconnect-duplicate-session",
    "teleport-vehicle-death",
    "admin-mod-origin",
    "rollback",
    "induced-finding",
]


class SpecError(ValueError):
    """tools/detector_spec.yaml is missing, unparseable, or not shaped like a spec."""


@functools.cache
def load_spec() -> list[Detector]:
    """The detector entries from the canonical spec. Cached: YAML parsing costs ~90ms
    and every consumer in one process (the registry render, the doccheck spec,
    manifest, and coverage checks) wants the same read. Callers must treat the result
    as read-only.

    Every way the spec can fail to be one (absent, unparseable YAML, no detector
    list) is a SpecError naming the file, so a caller reports the broken spec
    instead of propagating a bare OSError or KeyError.
    """
    try:
        data: Any = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SpecError(f"{SPEC.name} unreadable: {exc}") from exc
    except yaml.YAMLError as exc:
        raise SpecError(f"{SPEC.name} unparseable: {exc}") from exc
    if not isinstance(data, dict) or "detectors" not in data:
        raise SpecError(f"{SPEC.name}: expected a mapping with a top-level 'detectors' list")
    detectors = data["detectors"]
    if not isinstance(detectors, list):
        raise SpecError(f"{SPEC.name}: 'detectors' must be a list, got {type(detectors).__name__}")
    return detectors


def authority_note(d: Detector) -> str:
    decision = [i for i in d.get("inputs", []) if i.get("role") == "decision"]
    client = sorted(i["name"] for i in decision if i.get("authority") == "client-declared")
    parts = []
    if client:
        parts.append(
            "decision inputs include client-declared "
            + ", ".join(client)
            + "; capped below Hard unless the hard condition holds"
        )
    else:
        parts.append("all decision inputs server-derived")
    if d.get("hard_condition"):
        parts.append("hard condition: " + d["hard_condition"])
    return "; ".join(parts)


def ceiling_cell(d: Detector) -> str:
    c: str = d["ceiling"]
    if d["id"] in AVAILABILITY_CEILING_SUFFIX:
        c += " (availability)"
    if d.get("hard_condition"):
        c += " (conditional)"
    return c


def render_tables(detectors: list[Detector]) -> str:
    out = []
    for family in FAMILY_ORDER:
        rows = [d for d in detectors if d["family"] == family]
        out.append(f"## {FAMILY_TITLES[family]}\n")
        out.append("| ID | What it validates | Authority note | Ceiling | Contexts |")
        out.append("|---|---|---|---|---|")
        for d in rows:
            contexts = ", ".join(d.get("contexts", [])) or "none"
            out.append(
                f"| `{d['id']}` | {d['summary']} | {authority_note(d)} "
                f"| {ceiling_cell(d)} | {contexts} |"
            )
        out.append("")
    return "\n".join(out)


def render_fixture_matrix(detectors: list[Detector]) -> str:
    out = [
        "## Fixture coverage\n",
        "X marks the fixture families a detector must ship in TEST_PLAN.md Layer 4;",
        "declared per detector in `tools/detector_spec.yaml`. A detector is not considered",
        "for a mode raise until its declared fixture set is green in observe mode.\n",
        "| ID | " + " | ".join(FIXTURE_FAMILIES) + " |",
        "|---|" + "---|" * len(FIXTURE_FAMILIES),
    ]
    for d in detectors:
        have = set(d.get("fixtures", []))
        cells = " | ".join("X" if f in have else "" for f in FIXTURE_FAMILIES)
        out.append(f"| `{d['id']}` | {cells} |")
    return "\n".join(out) + "\n"


def render_seam_map(detectors: list[Detector]) -> str:
    out = [
        "## Seam map (V3.2.0 census candidates)\n",
        "Candidate authoritative seams from `7dtd-engine-research/il/netpackages-v3.2.0/INDEX.md`",
        "(195 types) and the protocol narratives; every seam is verified in Phase 1 before",
        "a hook is written. Declared per detector in `tools/detector_spec.yaml`.\n",
        "| Detector | Candidate seam |",
        "|---|---|",
    ]
    out.extend(f"| `{d['id']}` | {d.get('seam', 'TBD (Phase 1 inventory)')} |" for d in detectors)
    return "\n".join(out) + "\n"


def render_registry(detectors: list[Detector]) -> str:
    txt = REGISTRY.read_text(encoding="utf-8")
    start = txt.find("<!-- REGISTRY:START -->")
    end = txt.find("<!-- REGISTRY:END -->")
    if start == -1 or end == -1:
        sys.exit("DETECTORS.md is missing REGISTRY:START/END markers; re-add them before render")
    tables = render_tables(detectors)
    matrix = render_fixture_matrix(detectors)
    seam_map = render_seam_map(detectors)
    body = tables + "\n" + matrix + "\n" + seam_map
    return txt[: start + len("<!-- REGISTRY:START -->")] + "\n\n" + body + "\n" + txt[end:]


def render_manifest(detectors: list[Detector]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for d in detectors:
        entry: dict[str, Any] = {
            "detectorId": d["id"],
            "phase": d["phase"],
            "ceiling": d["ceiling"],
            "defaultMode": d["default_mode"],
            "seam": d.get("seam", "TBD (Phase 1 inventory)"),
            **({"hardCondition": d["hard_condition"]} if d.get("hard_condition") else {}),
        }
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
        entries.append(entry)
    return {"manifestVersion": 1, "detectors": entries}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--check", action="store_true", help="exit 1 if docs/DETECTORS.md is stale or missing"
    )
    mode.add_argument(
        "--manifest", action="store_true", help="emit config/detector-config-manifest.json"
    )
    args = ap.parse_args()

    try:
        detectors = load_spec()
    except SpecError as exc:
        print(f"render-detectors: {exc}", file=sys.stderr)
        return 1
    if args.manifest:
        manifest = render_manifest(detectors)
        # allow_nan=False: a non-finite threshold in the spec would otherwise be
        # written as a bare Infinity/NaN literal, which no JSON reader accepts.
        MANIFEST.write_text(
            json.dumps(manifest, indent=2, allow_nan=False) + "\n", encoding="utf-8"
        )
        print(f"wrote {MANIFEST.relative_to(ROOT)} ({len(manifest['detectors'])} detectors)")
        return 0

    fresh = render_registry(detectors)
    current = REGISTRY.read_text(encoding="utf-8") if REGISTRY.exists() else None
    if fresh != current:
        if args.check:
            state = "stale" if current is not None else "missing"
            print(f"docs/DETECTORS.md is {state}; run `make detectors`", file=sys.stderr)
            return 1
        REGISTRY.write_text(fresh, encoding="utf-8")
        print(f"regenerated {REGISTRY.relative_to(ROOT)}")
    else:
        print(f"{REGISTRY.relative_to(ROOT)} is current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
