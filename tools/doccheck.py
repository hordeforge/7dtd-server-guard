#!/usr/bin/env python3
"""Docs quality gate for 7dtd-server-guard.

Run from the repo root:  python3 tools/doccheck.py   (or `make check`)

Checks:
  1. No em dashes (U+2014) in any markdown file (workspace rule).
  2. Every internal markdown link resolves to an existing file or anchor.
  3. TODO.md checkboxes use the canonical `- [ ]` / `- [x]` format.
  4. Every backticked detector ID token (`family.subject`) used across docs is present in
     the detector registry (docs/DETECTORS.md). Unknown IDs are a registry miss.
  5. config/server-guard.example.json top-level keys all appear in the config-schema table
     of docs/SCHEMAS.md.
  6. Required contract documents exist.

Exit code 0 when clean; 1 otherwise. Prints a summary and any failures.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
MD_FILES = sorted(p for p in (ROOT / "docs").rglob("*.md")) + sorted(
    p for p in ROOT.glob("*.md")
)

REQUIRED_DOCS = [
    "docs/INDEX.md",
    "docs/DETECTORS.md",
    "docs/POLICY.md",
    "docs/THREAT_MODEL.md",
    "docs/ARCHITECTURE.md",
    "docs/SCHEMAS.md",
    "docs/SIGNALS.md",
    "docs/RESEARCH.md",
    "docs/TEST_PLAN.md",
    "docs/DECISIONS.md",
    "docs/OPERATIONS.md",
    "TODO.md",
    "PRIVACY.md",
    "SECURITY.md",
    "README.md",
    "AGENTS.md",
]

SPEC_PATH = ROOT / "tools" / "detector_spec.yaml"
SPEC_FAMILIES = {"protocol", "movement", "combat", "progression", "inventory", "world", "availability"}
SPEC_CEILINGS = {"Hard", "Strong", "Weak"}
SPEC_ROLES = {"observed", "decision"}
SPEC_AUTHORITIES = {"server-derived", "client-declared"}
SPEC_THRESHOLD_TYPES = {"int", "float", "string"}
ALLOWED_FIXTURES = {
    "normal", "violation", "latency-stall", "reconnect-duplicate-session",
    "teleport-vehicle-death", "admin-mod-origin", "rollback", "induced-finding",
}

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
DETECTOR_ID_RE = re.compile(r"(?<![\w-])([a-z]+\.[a-z_]+)(?![\w-])")

# Families that own detectors; tokens from these families must be in the registry.
# Config key paths (actions.correct, evidence.dir, webhook.enabled, ...) are not
# detector IDs and are checked against the schema instead.
DETECTOR_FAMILIES = SPEC_FAMILIES

# Config key paths declared in the SCHEMAS.md config table; they share the dotted
# family.subject shape with detector IDs but are schema keys, not detectors.
CONFIG_SCHEMA_KEYS: frozenset[str] = frozenset(
    m.group(1)
    for m in re.finditer(
        r"^\| `([a-z][a-z0-9.]+)` \| (?:int|bool|string|number|number/string) \|",
        (ROOT / "docs" / "SCHEMAS.md").read_text(encoding="utf-8"),
        re.M,
    )
)
CHECKBOX_RE = re.compile(r"^\s*[-*] \[[ xX]\] .+", re.M)


def detector_ids_in(text: str) -> set[str]:
    """Collect backticked `family.subject` tokens from a doc for detector families."""
    ids: set[str] = set()
    for m in re.finditer(r"`([a-z]+\.[a-z_]+)`", text):
        family = m.group(1).split(".", 1)[0]
        if family in DETECTOR_FAMILIES and m.group(1) not in CONFIG_SCHEMA_KEYS:
            ids.add(m.group(1))
    return ids


def check_em_dashes() -> list[str]:
    out = []
    for p in MD_FILES:
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if "\u2014" in line:
                out.append(f"{p.relative_to(ROOT)}:{i}: em dash: {line.strip()[:80]}")
    return out


def check_links() -> list[str]:
    out = []
    for p in MD_FILES:
        text = p.read_text(encoding="utf-8")
        for m in LINK_RE.finditer(text):
            target = m.group(1)
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            path_part, _, anchor = target.partition("#")
            if not path_part:
                continue
            resolved = (p.parent / path_part).resolve()
            if not resolved.exists():
                out.append(f"{p.relative_to(ROOT)}: broken link -> {target}")
    return out


def check_todo_format() -> list[str]:
    todo = ROOT / "TODO.md"
    out = []
    for i, line in enumerate(todo.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if re.match(r"^[-*] \[[ xX]\]", stripped):
            continue
        if stripped.startswith(("- [", "* [")):
            out.append(f"TODO.md:{i}: malformed checkbox: {stripped[:80]}")
    return out


def _load_spec() -> list[dict]:
    return yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))["detectors"]


def spec_ids() -> set[str]:
    return {d["id"] for d in _load_spec()}


def check_spec() -> list[str]:
    """Validate tools/detector_spec.yaml and the D-07 ceiling rule."""
    try:
        detectors = _load_spec()
    except Exception as exc:  # noqa: BLE001
        return [f"tools/detector_spec.yaml unparseable: {exc}"]

    out = []
    ids = [d["id"] for d in detectors]
    if len(ids) != len(set(ids)):
        dups = sorted({i for i in ids if ids.count(i) > 1})
        out.append(f"duplicate detector ids in spec: {dups}")
    for d in detectors:
        did = d["id"]
        if d.get("family") not in SPEC_FAMILIES:
            out.append(f"{did}: bad family {d.get('family')}")
        if d.get("ceiling") not in SPEC_CEILINGS:
            out.append(f"{did}: bad ceiling {d.get('ceiling')}")
        if d.get("default_mode") not in {"observe", "correct", "enforce"}:
            out.append(f"{did}: bad default_mode {d.get('default_mode')}")
        if not d.get("summary"):
            out.append(f"{did}: missing summary")
        inputs = d.get("inputs", [])
        if not inputs:
            out.append(f"{did}: no inputs")
        for i in inputs:
            if i.get("authority") not in SPEC_AUTHORITIES:
                out.append(f"{did}: input {i.get('name')} bad authority {i.get('authority')}")
            if i.get("role") not in SPEC_ROLES:
                out.append(f"{did}: input {i.get('name')} bad role {i.get('role')}")
        if not d.get("algorithm"):
            out.append(f"{did}: missing algorithm")
        if not d.get("state"):
            out.append(f"{did}: missing state")
        for f in d.get("fixtures", []):
            if f not in ALLOWED_FIXTURES:
                out.append(f"{did}: fixture {f} outside TEST_PLAN families")
        # D-07 rule: Hard requires all decision inputs server-derived, or a hard_condition.
        decision_client = [
            i["name"] for i in inputs
            if i.get("role") == "decision" and i.get("authority") == "client-declared"
        ]
        if d.get("ceiling") == "Hard" and decision_client and not d.get("hard_condition"):
            out.append(
                f"{did}: ceiling Hard with client-declared decision inputs "
                f"({', '.join(decision_client)}) and no hard_condition (POLICY.md D-07/D-15)"
            )
        # Thresholds: unique keys, valid type, sane range, default within range.
        keys = [t["key"] for t in d.get("thresholds", [])]
        if len(keys) != len(set(keys)):
            out.append(f"{did}: duplicate threshold keys")
        for t in d.get("thresholds", []):
            if t.get("type") not in SPEC_THRESHOLD_TYPES:
                out.append(f"{did}: threshold {t.get('key')} bad type {t.get('type')}")
            rng = t.get("range")
            if t["type"] in {"int", "float"} and isinstance(rng, list):
                if len(rng) != 2 or rng[0] > rng[1]:
                    out.append(f"{did}: threshold {t.get('key')} bad range {rng}")
                elif isinstance(t.get("default"), (int, float)) and not (rng[0] <= t["default"] <= rng[1]):
                    out.append(f"{did}: threshold {t.get('key')} default {t.get('default')} outside range {rng}")
    return out


def check_registry_sync() -> list[str]:
    """docs/DETECTORS.md tables must match the rendered output from the spec."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "render_detectors.py"), "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )
    if proc.returncode != 0:
        return [proc.stdout.strip() or proc.stderr.strip() or "registry is stale"]
    return []


def check_detector_ids() -> list[str]:
    registered = spec_ids()
    out = []
    for p in MD_FILES:
        text = p.read_text(encoding="utf-8")
        for tid in sorted(detector_ids_in(text)):
            if tid not in registered:
                out.append(f"{p.relative_to(ROOT)}: detector ID not in registry: {tid}")

    # Every mode key in the example config must exist in the spec.
    example = json.loads((ROOT / "config" / "server-guard.example.json").read_text())
    for mode_id in sorted(example.get("modes", {}).keys()):
        if mode_id not in registered:
            out.append(f"config example mode key not in registry: {mode_id}")
    # Every threshold key in the generated config manifest must be declared in the spec,
    # and every example-config threshold key must exist in the generated manifest.
    manifest = json.loads((ROOT / "config" / "detector-config-manifest.json").read_text())
    spec_by_id = {d["id"]: d for d in _load_spec()}
    manifest_keys: dict[str, set[str]] = {}
    for entry in manifest["detectors"]:
        spec_entry = spec_by_id.get(entry["detectorId"])
        if spec_entry is None:
            out.append(f"manifest detector {entry.get('detectorId')} not in spec")
            continue
        if entry.get("phase") != spec_entry["phase"] or entry.get("ceiling") != spec_entry["ceiling"]                 or entry.get("defaultMode") != spec_entry["default_mode"]:
            out.append(f"manifest metadata drift for {entry['detectorId']}; re-run make detectors")
        declared = {t["key"] for t in spec_entry.get("thresholds", [])}
        manifest_keys[entry["detectorId"]] = {t["key"] for t in entry.get("thresholds", [])}
        for t in entry.get("thresholds", []):
            if t["key"] not in declared:
                out.append(f"manifest threshold {entry['detectorId']}.{t['key']} not declared in spec")
    example = json.loads((ROOT / "config" / "server-guard.example.json").read_text())
    for did, keys in example.get("thresholds", {}).items():
        for key in keys:
            if key not in manifest_keys.get(did, set()):
                out.append(f"example config threshold {did}.{key} not in generated manifest")
    return out


def _flatten(obj: dict, prefix: str = "") -> list[str]:
    """Dotted paths for every leaf in a nested dict."""
    out = []
    for k, v in obj.items():
        path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.extend(_flatten(v, path))
        else:
            out.append(path)
    return out


def _schema_key_patterns() -> list[str]:
    schemas = (ROOT / "docs" / "SCHEMAS.md").read_text(encoding="utf-8")
    return [
        m.group(1)
        for line in schemas.splitlines()
        if line.startswith("| `")
        for m in [re.match(r"\| `([^`]+)` \| (?:int|bool|string|number|number/string) \|", line)]
        if m
    ]


def _matches_schema(path: str, patterns: list[str]) -> bool:
    """Match an example dotted path against schema key patterns.

    A placeholder segment like <detectorId> consumes one or more path segments
    (detector IDs are family.subject), so modes.<detectorId> matches
    modes.protocol.stage_order but not modes.protocol.
    """
    segs = path.split(".")
    for pat in patterns:
        psegs = pat.split(".")
        fixed = []
        placeholders = 0
        for ps in psegs:
            if ps.startswith("<") and ps.endswith(">"):
                placeholders += 1
            else:
                fixed.append(ps)
        if segs[: len(fixed)] != fixed:
            continue
        remaining = len(segs) - len(fixed)
        if placeholders == 0:
            if remaining == 0:
                return True
        elif remaining >= placeholders:
            return True
    return False


def check_config_example_keys() -> list[str]:
    patterns = _schema_key_patterns()
    example = json.loads((ROOT / "config" / "server-guard.example.json").read_text())
    out = []
    for path in _flatten(example):
        if path == "schemaVersion":
            continue
        if not _matches_schema(path, patterns):
            out.append(f"config key '{path}' not declared in SCHEMAS.md config table")
    return out


def check_required_docs() -> list[str]:
    return [d for d in REQUIRED_DOCS if not (ROOT / d).exists()]


def main() -> int:
    failures: dict[str, list[str]] = {
        "em dashes": check_em_dashes(),
        "links": check_links(),
        "TODO checkboxes": check_todo_format(),
        "detector spec": check_spec(),
        "registry sync": check_registry_sync(),
        "detector registry coverage": check_detector_ids(),
        "config example vs schema": check_config_example_keys(),
        "required docs": check_required_docs(),
    }
    total = sum(len(v) for v in failures.values())
    print(f"doccheck: {total} issue(s) across {len(MD_FILES)} markdown files")
    for name, items in failures.items():
        if items:
            print(f"\n[{name}]")
            for item in items[:40]:
                print("  " + item)
            if len(items) > 40:
                print(f"  ... and {len(items) - 40} more")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
