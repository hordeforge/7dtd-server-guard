"""Render the detector registry (docs/DETECTORS.md) and the per-detector config manifest
from the canonical spec (tools/detector_spec.yaml).

Usage (from repo root):
  uv run python tools/render_detectors.py            regenerate docs/DETECTORS.md in place
  uv run python tools/render_detectors.py --check    exit 1 if docs/DETECTORS.md is stale
  uv run python tools/render_detectors.py --manifest emit config/detector-config-manifest.json
  uv run python tools/render_detectors.py --manifest --check  exit 1 if the manifest is stale

Exit codes: 0 the generated files are current, 1 --check found a stale or missing
target file (or the spec is unusable), 2 usage error.
"""

from __future__ import annotations

import argparse
import functools
import json
import pathlib
import sys
from collections.abc import Sequence
from typing import Any, cast

try:
    import yaml
except ModuleNotFoundError:
    sys.exit("render-detectors: missing dependency PyYAML; run `make setup`")

# A detector entry as it appears in the spec. The spec is YAML from disk, so its
# value types are only guaranteed by the doccheck spec validator, not statically.
Detector = dict[str, Any]


class SpecError(ValueError):
    """tools/detector_spec.yaml is not a readable detector document.

    Raised instead of a bare KeyError or TypeError so every consumer can report a
    gate failure rather than crash on an unparseable spec.
    """


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = ROOT / "tools" / "detector_spec.yaml"
REGISTRY = ROOT / "docs" / "DETECTORS.md"
MANIFEST = ROOT / "config" / "detector-config-manifest.json"

# Section order and titles for the registry matrix. One mapping, not a list beside
# a dict: a family added to one and not the other silently lost its section.
FAMILY_TITLES = {
    "protocol": "Protocol and identity (Phase 4)",
    "movement": "Movement (Phase 5)",
    "combat": "Combat (Phase 6)",
    "progression": "Progression (Phase 8)",
    "inventory": "Inventory and economy (Phase 7)",
    "world": "World and entity (Phase 8)",
    "availability": "Availability (Phases 4 and 8)",
}
FAMILY_ORDER = list(FAMILY_TITLES)
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


@functools.cache
def load_spec() -> list[object]:
    """The detector records from the canonical spec. Cached: YAML parsing costs ~90ms
    and every consumer in one process (the registry render, the doccheck spec,
    manifest, and coverage checks) wants the same read. Callers must treat the result
    as read-only.

    Every way the spec can fail to be one (absent, unparseable YAML, no detector
    list) is a SpecError naming the file, so a caller reports the broken spec
    instead of propagating a bare OSError or KeyError. The records stay `object`
    because the file is YAML: only validate() decides which of them are actually
    detector mappings.
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
    return cast("list[object]", detectors)


# Structural requirement per required field: the renderer and manifest subscript
# these directly, so a record missing one must fail the render loudly rather than
# raise a KeyError halfway through writing docs/DETECTORS.md. Type meaning beyond
# these is doccheck's spec validator, which owns the vocabularies and the D-07 rule.
REQUIRED_FIELDS = {
    "id": str,
    "family": str,
    "ceiling": str,
    "phase": int,
    "default_mode": str,
    "summary": str,
}
# Threshold fields render_manifest projects into the generated config manifest.
REQUIRED_THRESHOLD_FIELDS = ("key", "type", "range", "default")


def record_errors(index: int, d: object) -> list[str]:
    """Structural problems in one spec record, prefixed with its position.

    Position rather than id because a record whose id is missing or not a string
    has no other stable label, and a spec that lost one is exactly what this
    reports.
    """
    where = f"detectors[{index}]"
    if not isinstance(d, dict):
        return [f"{where}: record must be a mapping, got {type(d).__name__}"]
    out = [
        f"{where}: {field} must be a {typ.__name__}, got {d.get(field)!r}"
        for field, typ in sorted(REQUIRED_FIELDS.items())
        if not isinstance(d.get(field), typ) or isinstance(d.get(field), bool)
    ]
    thresholds = d.get("thresholds", [])
    if not isinstance(thresholds, list):
        return [*out, f"{where}: thresholds must be a list, got {type(thresholds).__name__}"]
    for i, t in enumerate(thresholds):
        at = f"{where}.thresholds[{i}]"
        if not isinstance(t, dict):
            out.append(f"{at}: threshold must be a mapping, got {type(t).__name__}")
            continue
        out.extend(
            f"{at}: missing {field}" for field in REQUIRED_THRESHOLD_FIELDS if field not in t
        )
    return out


def validate(detectors: Sequence[object]) -> list[str]:
    """Every structural problem in the spec, so a bad spec fails the render loudly."""
    return [msg for i, d in enumerate(detectors) for msg in record_errors(i, d)]


def validated(detectors: Sequence[object]) -> list[Detector]:
    """The spec, or SpecError naming every structural problem in it."""
    errors = validate(detectors)
    if errors:
        raise SpecError("; ".join(errors))
    return cast("list[Detector]", list(detectors))


def identified(detectors: Sequence[object]) -> list[tuple[str, Detector]]:
    """(id, record) pairs for the records that carry a usable id.

    doccheck runs every spec cross-reference in the same pass as the spec
    validator, which reports the records skipped here. Filtering them keeps a
    broken spec a list of gate failures instead of a traceback from whichever
    cross-reference happens to run next.
    """
    return [(d["id"], d) for d in detectors if isinstance(d, dict) and isinstance(d.get("id"), str)]


def _string_list(value: object) -> list[str]:
    """The string members of a spec list field, or none when it is not a list.

    The renderer only ever formats these, so an unusable value renders as absent
    rather than failing a render over a field that carries no table content.
    """
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def authority_note(d: Detector) -> str:
    raw_inputs = d.get("inputs")
    inputs = [i for i in raw_inputs if isinstance(i, dict)] if isinstance(raw_inputs, list) else []
    decision = [i for i in inputs if i.get("role") == "decision"]
    client = sorted(
        i["name"]
        for i in decision
        if i.get("authority") == "client-declared" and isinstance(i.get("name"), str)
    )
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
        parts.append(f"hard condition: {d['hard_condition']}")
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
            contexts = ", ".join(_string_list(d.get("contexts"))) or "none"
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
        have = set(_string_list(d.get("fixtures")))
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
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--check", action="store_true", help="exit 1 if the target file is stale or missing"
    )
    ap.add_argument(
        "--manifest", action="store_true", help="target config/detector-config-manifest.json"
    )
    args = ap.parse_args()

    try:
        detectors = validated(load_spec())
    except SpecError as exc:
        print(
            f"render-detectors: {SPEC.relative_to(ROOT)} is not renderable: {exc}", file=sys.stderr
        )
        print("run `make check` for the full spec report", file=sys.stderr)
        return 1
    if args.manifest:
        manifest = render_manifest(detectors)
        # allow_nan=False: a non-finite threshold in the spec would otherwise be
        # written as a bare Infinity/NaN literal, which no JSON reader accepts.
        rendered = json.dumps(manifest, indent=2, allow_nan=False) + "\n"
        current_manifest = MANIFEST.read_text(encoding="utf-8") if MANIFEST.is_file() else ""
        if rendered == current_manifest:
            print(f"{MANIFEST.relative_to(ROOT)} is current")
            return 0
        if args.check:
            print(f"{MANIFEST.relative_to(ROOT)} is stale")
            print("run `make detectors`", file=sys.stderr)
            return 1
        # newline="\n": the file is tracked with the repo's LF policy (.gitattributes),
        # and a text-mode write would translate to CRLF on a Windows host, rewriting
        # a file that was already current.
        MANIFEST.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"wrote {MANIFEST.relative_to(ROOT)} ({len(manifest['detectors'])} detectors)")
        return 0

    fresh = render_registry(detectors)
    current = REGISTRY.read_text(encoding="utf-8") if REGISTRY.exists() else None
    if fresh != current:
        if args.check:
            state = "stale" if current is not None else "missing"
            print(f"docs/DETECTORS.md is {state}")
            print("run `make detectors`", file=sys.stderr)
            return 1
        REGISTRY.write_text(fresh, encoding="utf-8", newline="\n")
        print(f"regenerated {REGISTRY.relative_to(ROOT)}")
    else:
        print(f"{REGISTRY.relative_to(ROOT)} is current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
