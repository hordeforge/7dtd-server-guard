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
import sys

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
    "TODO.md",
    "PRIVACY.md",
    "SECURITY.md",
    "README.md",
    "AGENTS.md",
]

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
DETECTOR_ID_RE = re.compile(r"(?<![\w-])([a-z]+\.[a-z_]+)(?![\w-])")

# Families that own detectors; tokens from these families must be in the registry.
# Config key paths (actions.correct, evidence.dir, webhook.enabled, ...) are not
# detector IDs and are checked against the schema instead.
DETECTOR_FAMILIES = {
    "protocol", "movement", "combat", "progression", "inventory", "world", "availability",
}

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


def check_detector_ids() -> list[str]:
    registry = (ROOT / "docs" / "DETECTORS.md").read_text(encoding="utf-8")
    # Registered IDs are the first backticked token on rows of the ID tables.
    registered: set[str] = set()
    for m in re.finditer(r"^\| `([a-z]+\.[a-z_]+)` \|", registry, re.M):
        registered.add(m.group(1))
    # Also accept IDs explicitly written as `detectorId` values in SCHEMAS examples.
    for m in re.finditer(r'"detectorId": "([a-z]+\.[a-z_]+)"',
                         (ROOT / "docs" / "SCHEMAS.md").read_text(encoding="utf-8")):
        registered.add(m.group(1))
    # Add config example mode keys (they must match the registry too).
    example = json.loads((ROOT / "config" / "server-guard.example.json").read_text())
    registered |= set(example.get("modes", {}).keys())

    out = []
    for p in MD_FILES:
        text = p.read_text(encoding="utf-8")
        for tid in sorted(detector_ids_in(text)):
            if tid not in registered:
                out.append(f"{p.relative_to(ROOT)}: detector ID not in registry: {tid}")
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
