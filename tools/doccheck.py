"""Docs quality gate for 7dtd-server-guard.

Run from the repo root:  uv run python tools/doccheck.py   (or `make check`)

Checks:
   1. No em dashes (U+2014) in any markdown file or shipped source file (workspace rule).
   2. Every internal markdown link resolves to an existing file or anchor.
   3. TODO.md checkboxes use the canonical `- [ ]` / `- [x]` format.
   4. tools/detector_spec.yaml is well-formed and satisfies the D-07/D-15 ceiling
      rule plus the normal+violation fixture requirement per detector.
   5. docs/DETECTORS.md and config/detector-config-manifest.json match the rendered
      output of render_detectors.py.
   6. Every backticked detector ID token (`family.subject`) used across docs is present in
      the spec; example-config mode keys match the registry both ways and never exceed the
      spec's default mode for a detector.
   7. The generated config manifest matches the spec's phase/ceiling/mode metadata and
      declares exactly the spec's threshold keys; every example-config threshold key
      exists in the manifest and its value satisfies the manifest's type and range.
   8. Every key path in config/server-guard.example.json is declared in the config-schema
      table of docs/SCHEMAS.md, and every key the config schema declares is documented
      there and either defaulted or shown in the example.
   9. The shipped JSON Schemas parse, and the example config, generated manifest,
      evidence sample JSONL, and replay-trace fixture conform to them.
  10. The shipped evidence sample verifies as a hash chain (tools/evidence_check.py).
  11. The design-time replay contract vector passes its semantic checks.
  12. Documented folder structure holds: required docs exist and every planned directory
      under src/, tests/, tools/, config/ carries a README.
  13. Every open object in the evidence schema carries the property-name deny-list,
      so no raw identity, contact, network address, or credential can ride along in
      a detector-supplied value bag.
  14. The backup and restore path stays wired: the archive targets exist in the Makefile,
      run under test-tools, and docs/OPERATIONS.md states RPO/RTO and a restore drill.

Exit code 0 when clean; 1 otherwise. The one-line summary goes to stdout and the
per-check failure detail to stderr, so a redirected run keeps the verdict on one
stream and the diagnostics on the other.
"""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import re
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime
from typing import Any

# Spec loading (and its PyYAML dependency guard) lives in render_detectors.
import render_detectors

# A parsed JSON Schema or instance: shape is what the validator below checks, so
# it cannot be narrowed statically.
Json = Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Directories that hold nothing this repo ships: version control, the local
# environment, tool caches, and the scratch tree the workspace rules tell
# contributors to work in. Their contents are not docs and must not fail the gate.
SKIP_DIRS = frozenset({".git", ".venv", ".mypy_cache", ".ruff_cache", ".scratch"})
MD_FILES = sorted(
    p for p in ROOT.rglob("*.md") if not (SKIP_DIRS & set(p.parts)) and "third-party" not in p.parts
)
# The em-dash ban covers code comments and CI files, not just prose, so the gate
# reads every text file this repo ships.
SOURCE_FILES = sorted(
    p
    for p in [
        ROOT / "Makefile",
        *ROOT.glob("*.toml"),
        *ROOT.glob("*.ini"),
        *(ROOT / "tools").glob("*.py"),
        *(ROOT / "tools").glob("*.yaml"),
        *(ROOT / "tools").rglob("*.json"),
        *(ROOT / "tools").rglob("*.jsonl"),
        *(ROOT / "config").rglob("*.json"),
        *(ROOT / "config").rglob("*.jsonl"),
        *(ROOT / ".github").rglob("*.yml"),
        *(ROOT / ".github").rglob("*.yaml"),
    ]
    if p.is_file() and "__pycache__" not in p.parts
)

REQUIRED_DOCS = [
    "docs/INDEX.md",
    "docs/DETECTORS.md",
    "docs/POLICY.md",
    "docs/THREAT_MODEL.md",
    "docs/ARCHITECTURE.md",
    "docs/SCHEMAS.md",
    "docs/SIGNALS.md",
    "docs/PROPOSALS.md",
    "docs/EXECUTION.md",
    "docs/RESEARCH.md",
    "docs/TEST_PLAN.md",
    "docs/DECISIONS.md",
    "docs/OPERATIONS.md",
    "docs/METHODOLOGY.md",
    "TODO.md",
    "PRIVACY.md",
    "SECURITY.md",
    "README.md",
    "AGENTS.md",
]

SPEC_FAMILIES = frozenset(render_detectors.FAMILY_ORDER)
SPEC_CEILINGS = {"Hard", "Strong", "Weak"}
SPEC_ROLES = {"observed", "decision"}
SPEC_AUTHORITIES = {"server-derived", "client-declared"}
SPEC_THRESHOLD_TYPES = {"int", "float", "string"}
SPEC_MODES = {"observe", "correct", "enforce"}
NUMERIC_THRESHOLD_TYPES = {"int", "float"}


def in_vocab(value: Json, vocab: frozenset[str] | set[str]) -> bool:
    """Whether a spec value is a member of a string vocabulary.

    Every value reaching these checks comes from YAML, where a nested list or
    mapping can land in any field. `x in vocab` raises on an unhashable x, so a
    malformed spec would crash the gate instead of being reported by it.
    """
    return isinstance(value, str) and value in vocab


# Fixture families are owned by render_detectors.py (they head the registry matrix);
# importing keeps this validator from drifting from the rendered table.
ALLOWED_FIXTURES = frozenset(render_detectors.FIXTURE_FAMILIES)

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

# Key patterns declared in the SCHEMAS.md config table. They share the dotted
# family.subject shape with detector IDs, but rows like actions.correct or
# availability.burst are schema keys, not detectors; placeholder segments such
# as <detectorId> stand in for per-detector subtrees.
SCHEMA_TABLE_RE = re.compile(
    r"^\| `([^`]+)` \| (?:int|bool|string|number|number/string) \|", re.MULTILINE
)


def _schema_table_keys() -> list[str]:
    return SCHEMA_TABLE_RE.findall((ROOT / "docs" / "SCHEMAS.md").read_text(encoding="utf-8"))


CONFIG_SCHEMA_KEYS: frozenset[str] = frozenset(_schema_table_keys())

# Validator recursion bound. Shipped schemas nest at most ~6 levels; the cap only
# bites on pathological documents (deeply nested or self-referential schemas), where
# unbounded recursion would end in RecursionError instead of a reported error.
MAX_SCHEMA_DEPTH = 100

# `format` values the validator asserts. A schema declaring anything else is
# reported rather than silently accepted as unchecked.
SUPPORTED_FORMATS = frozenset({"date-time"})

# A numeric threshold range in the spec is a [min, max] pair.
RANGE_BOUNDS = 2
# Per-check cap on printed failures; the rest are summarized as a count.
MAX_REPORTED = 40


def _is_finite_number(v: Json) -> bool:
    """True for a real number, excluding bool, NaN, and the infinities.

    YAML parses `.nan` and `.inf` into Python floats, and a range bound or
    default carrying one compares false against everything downstream, so the
    spec gate has to name it instead of letting it through.
    """
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, float) and math.isfinite(v)


def _is_int_value(v: Json) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


# Every shipped (JSON Schema, data) pair: gated by check_config_schemas and fuzzed
# by tools/fuzz_schema_validate.py, which imports this list to stay in sync.
SCHEMA_DATA_PAIRS = [
    (
        ROOT / "config" / "schemas" / "config.v1.schema.json",
        ROOT / "config" / "server-guard.example.json",
    ),
    (
        ROOT / "config" / "schemas" / "config-manifest.v1.schema.json",
        ROOT / "config" / "detector-config-manifest.json",
    ),
    (
        ROOT / "config" / "schemas" / "evidence.v1.schema.json",
        ROOT / "config" / "schemas" / "evidence.v1.sample.jsonl",
    ),
    (
        ROOT / "config" / "schemas" / "replay-trace.v1.schema.json",
        ROOT / "tools" / "fixtures" / "traces" / "inventory" / "stack.v1.sample.json",
    ),
]

EVIDENCE_SCHEMA = ROOT / "config" / "schemas" / "evidence.v1.schema.json"
# The one property-name deny-list every open evidence value bag $refs.
PERSONAL_DATA_DENY_LIST = "personalDataDenyList"
DENY_LIST_REF = f"#/definitions/{PERSONAL_DATA_DENY_LIST}"


def detector_ids_in(text: str) -> set[str]:
    """Collect backticked `family.subject` tokens from a doc for detector families."""
    ids: set[str] = set()
    for m in re.finditer(r"`([a-z]+\.[a-z_]+)`", text):
        family = m.group(1).split(".", 1)[0]
        if family in SPEC_FAMILIES and m.group(1) not in CONFIG_SCHEMA_KEYS:
            ids.add(m.group(1))
    return ids


def check_em_dashes() -> list[str]:
    out = []
    for p in MD_FILES + SOURCE_FILES:
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
            if target.startswith(("http://", "https://", "#", "mailto:", "../")):
                # "../" links point at sibling repos (7dtd-engine-research etc.), which
                # do not exist in a single-repo checkout; they are audited by
                # the cross-repo link pass, not by this per-repo gate.
                continue
            path_part = target.partition("#")[0]
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


def parsed_spec() -> list[object]:
    """The spec records, or none when the file does not parse.

    check_spec reports an unparseable spec. The cross-reference checks run in the
    same pass as check_spec, so they read the spec through this accessor rather
    than each raising a traceback on the same file.
    """
    try:
        return render_detectors.load_spec()
    except render_detectors.SpecError:
        return []


def spec_ids() -> set[str]:
    """Registry ids, or an empty set when the spec does not parse (check_spec reports that)."""
    return {did for did, _ in render_detectors.identified(parsed_spec())}


def _range_default_errors(did: str, t: Json, ttype: str) -> list[str]:
    """The numeric checks on one threshold: its [min, max] pair and its default.

    Both must be finite and the default must sit inside the range, because
    render_manifest copies every threshold's default into the shipped manifest
    unconditionally, so a missing or non-numeric one has to be rejected here. A
    YAML `true` is an int in Python, hence the bool exclusion, and a fractional
    value on an `int` threshold is truncated on load, so the value in the spec is
    not the value that runs.
    """
    if ttype not in {"int", "float"}:
        return []
    rng = t.get("range")
    if not isinstance(rng, list):
        return []
    out: list[str] = []
    key = t.get("key")
    default = t.get("default")
    if len(rng) != RANGE_BOUNDS or not all(_is_finite_number(b) for b in rng):
        out.append(f"{did}: threshold {key} bad range {rng}")
    elif not rng[0] <= rng[1]:
        out.append(f"{did}: threshold {key} bad range {rng}")
    elif ttype == "int" and not all(_is_int_value(b) for b in rng):
        out.append(f"{did}: threshold {key} int type with fractional range")
    elif not _is_finite_number(default):
        out.append(f"{did}: threshold {key} default {default!r} is not a number")
    elif ttype == "int" and not _is_int_value(default):
        out.append(f"{did}: threshold {key} int type with fractional default")
    elif not rng[0] <= default <= rng[1]:
        out.append(f"{did}: threshold {key} default {default} outside range {rng}")
    return out


def _threshold_errors(did: str, thresholds: Json) -> list[str]:
    """Threshold keys are unique, typed, and carry a sane range and default.

    Every field is read with .get: a hand-edited spec missing a key must be
    reported, not raise out of the gate, and an entry that is not a mapping at
    all is reported the same way instead of being indexed.
    """
    if not isinstance(thresholds, list):
        return [f"{did}: thresholds must be a list, got {type(thresholds).__name__}"]
    out: list[str] = []
    entries = [t if isinstance(t, dict) else {} for t in thresholds]
    if any(not isinstance(t, dict) for t in thresholds):
        out.append(f"{did}: threshold entries must all be mappings")
    keys: list[str] = []
    for t in entries:
        key = t.get("key")
        if not isinstance(key, str) or not key:
            out.append(f"{did}: threshold missing key {key!r}")
            continue
        keys.append(key)
    if len(keys) != len(set(keys)):
        out.append(f"{did}: duplicate threshold keys")
    for t in entries:
        ttype = t.get("type")
        if not isinstance(ttype, str) or not in_vocab(ttype, SPEC_THRESHOLD_TYPES):
            out.append(f"{did}: threshold {t.get('key')} bad type {ttype}")
            continue
        out.extend(_range_default_errors(did, t, ttype))
    return out


def _input_errors(did: str, inputs: object) -> list[str]:
    """Every declared input carries a known authority and role."""
    if not isinstance(inputs, list):
        return [f"{did}: inputs must be a list, got {type(inputs).__name__}"]
    out = [] if inputs else [f"{did}: no inputs"]
    for i in inputs:
        if not isinstance(i, dict):
            out.append(f"{did}: input must be a mapping, got {i!r}")
            continue
        if not in_vocab(i.get("authority"), SPEC_AUTHORITIES):
            out.append(f"{did}: input {i.get('name')} bad authority {i.get('authority')}")
        if not in_vocab(i.get("role"), SPEC_ROLES):
            out.append(f"{did}: input {i.get('name')} bad role {i.get('role')}")
    return out


def _fixture_errors(did: str, fixtures: object) -> list[str]:
    """Fixture names are TEST_PLAN families, and normal and violation are both declared."""
    if not isinstance(fixtures, list):
        return [f"{did}: fixtures must be a list, got {type(fixtures).__name__}"]
    names = {f for f in fixtures if isinstance(f, str)}
    out = [
        f"{did}: fixture {f} outside TEST_PLAN families" for f in sorted(names - ALLOWED_FIXTURES)
    ]
    # TEST_PLAN.md Layer 4: every detector ships normal and violation traces.
    if "normal" not in names or "violation" not in names:
        out.append(f"{did}: must declare normal and violation fixtures (TEST_PLAN Layer 4)")
    return out


def _detector_errors(d: Json) -> list[str]:
    """Required fields, input authority/role vocabulary, fixtures, and the D-07 rule."""
    if not isinstance(d, dict) or not isinstance(d.get("id"), str):
        # Without a usable id nothing below can be attributed to a detector;
        # check_spec reports the record through the structural validator.
        return [f"detector record must be a mapping with a string id, got {d!r}"]
    did = d["id"]
    out = []
    if not in_vocab(d.get("family"), SPEC_FAMILIES):
        out.append(f"{did}: bad family {d.get('family')}")
    if not in_vocab(d.get("ceiling"), SPEC_CEILINGS):
        out.append(f"{did}: bad ceiling {d.get('ceiling')}")
    if not in_vocab(d.get("default_mode"), SPEC_MODES):
        out.append(f"{did}: bad default_mode {d.get('default_mode')}")
    for field, note in (
        ("summary", ""),
        ("algorithm", ""),
        ("seam", " (Phase 1 probe target)"),
        ("state", ""),
    ):
        if not d.get(field):
            out.append(f"{did}: missing {field}{note}")
    inputs = d.get("inputs", [])
    out.extend(_input_errors(did, inputs))
    out.extend(_fixture_errors(did, d.get("fixtures", [])))
    # D-07 rule: Hard requires all decision inputs server-derived, or a hard_condition.
    decision_client = [
        i.get("name")
        for i in inputs
        if isinstance(i, dict)
        and i.get("role") == "decision"
        and i.get("authority") == "client-declared"
        and isinstance(i.get("name"), str)
    ]
    if d.get("ceiling") == "Hard" and decision_client and not d.get("hard_condition"):
        out.append(
            f"{did}: ceiling Hard with client-declared decision inputs "
            f"({', '.join(decision_client)}) and no hard_condition (POLICY.md D-07/D-15)"
        )
    return out + _threshold_errors(did, d.get("thresholds", []))


def check_spec() -> list[str]:
    """Validate tools/detector_spec.yaml and the D-07 ceiling rule."""
    try:
        detectors = render_detectors.load_spec()
    except render_detectors.SpecError as exc:
        return [f"tools/detector_spec.yaml {exc}"]

    out = [msg for i, d in enumerate(detectors) for msg in render_detectors.record_errors(i, d)]
    # Entries with no usable id are reported by the structural validator and by
    # _detector_errors; they cannot take part in the duplicate-id comparison.
    ids: list[str] = [
        d["id"] for d in detectors if isinstance(d, dict) and isinstance(d.get("id"), str)
    ]
    if len(ids) != len(set(ids)):
        dups = sorted({i for i in ids if ids.count(i) > 1})
        out.append(f"duplicate detector ids in spec: {dups}")
    for d in detectors:
        out += _detector_errors(d)
    return out


# A gated tool reads and parses files off disk; a run that has not finished in this
# many seconds is stuck, and a gate that waits forever is indistinguishable from a
# gate that passes.
TOOL_TIMEOUT_S = 120


def _run_tool(script: str, *args: str, on_failure: str) -> list[str]:
    """Run a sibling tool as a gate. Returns its output as errors when it exits nonzero.

    A separate process keeps each tool's argparse and exit-code contract as the gated
    surface, instead of importing internals the CLI does not expose. Both streams are
    reported: a tool that prints findings and then dies on an exception writes the
    traceback to stderr, and dropping it hides the crash behind the findings.

    The child's output is decoded as UTF-8 like every other text boundary here: the
    child echoes file names and record content back, and a host whose locale is
    POSIX would otherwise decode that as ASCII and raise out of the gate.
    """
    try:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools" / script), *args],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            cwd=ROOT,
            check=False,
            timeout=TOOL_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return [f"{' '.join([script, *args])}: no result after {TOOL_TIMEOUT_S}s"]
    except OSError as exc:
        return [f"{script}: could not be run: {exc}"]
    if proc.returncode != 0:
        return [e for e in (proc.stdout.strip(), proc.stderr.strip()) if e] or [on_failure]
    return []


def check_registry_sync() -> list[str]:
    """Both generated files must match a fresh render of the spec: docs/DETECTORS.md
    and the config manifest operators copy thresholds out of."""
    return [
        *_run_tool("render_detectors.py", "--check", on_failure="registry is stale"),
        *_run_tool(
            "render_detectors.py",
            "--manifest",
            "--check",
            on_failure="config manifest is stale",
        ),
    ]


def _threshold_keys(thresholds: object) -> set[str]:
    """Declared threshold keys, ignoring entries the spec validator already reported.

    The cross-references read a spec that may be malformed, and check_spec owns
    the report on the entries that are; this pass only needs the keys.
    """
    if not isinstance(thresholds, list):
        return set()
    return {t["key"] for t in thresholds if isinstance(t, dict) and isinstance(t.get("key"), str)}


def _thresholds_by_key(thresholds: object) -> dict[str, Json]:
    """Threshold entries keyed by their declared key, skipping unusable entries."""
    if not isinstance(thresholds, list):
        return {}
    return {
        t["key"]: t for t in thresholds if isinstance(t, dict) and isinstance(t.get("key"), str)
    }


def _manifest_errors(example: Json, out: list[str]) -> None:
    """Manifest metadata must track the spec, and both must cover the example config.

    Like every check here, a hand-edited manifest or spec is reported into the
    caller's error list; nothing is read with [] on a field that may be absent.
    """
    manifest = json.loads((ROOT / "config" / "detector-config-manifest.json").read_text())
    entries = manifest.get("detectors")
    if not isinstance(entries, list):
        out.append("config/detector-config-manifest.json: detectors must be an array")
        return
    spec_by_id = dict(render_detectors.identified(parsed_spec()))
    # detector id -> that manifest entry's thresholds, keyed by threshold key.
    manifest_keys: dict[str, dict[str, Json]] = {}
    manifest_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("detectorId"), str):
            out.append(f"manifest detector entry without a detectorId: {entry!r}")
            continue
        detector_id = entry["detectorId"]
        manifest_ids.add(detector_id)
        spec_entry = spec_by_id.get(detector_id)
        if spec_entry is None:
            out.append(f"manifest detector {detector_id} not in spec")
            continue
        if (
            entry.get("phase") != spec_entry.get("phase")
            or entry.get("ceiling") != spec_entry.get("ceiling")
            or entry.get("defaultMode") != spec_entry.get("default_mode")
        ):
            out.append(f"manifest metadata drift for {detector_id}; re-run make detectors")
        declared = _threshold_keys(spec_entry.get("thresholds"))
        entry_keys = _thresholds_by_key(entry.get("thresholds"))
        manifest_keys[detector_id] = entry_keys
        out.extend(
            f"manifest threshold {detector_id}.{key} not declared in spec"
            for key in sorted(entry_keys)
            if key not in declared
        )
        out.extend(
            f"manifest is missing threshold {entry['detectorId']}.{key} declared in spec; "
            "re-run make detectors"
            for key in sorted(set(declared) - set(manifest_keys[entry["detectorId"]]))
        )
    out.extend(
        f"manifest is missing detector {d} declared in spec; re-run make detectors"
        for d in sorted(set(spec_by_id) - manifest_ids)
    )
    for did, keys in example.get("thresholds", {}).items():
        known = manifest_keys.get(did, {})
        out.extend(
            f"example config threshold {did}.{key} not in generated manifest"
            for key in keys
            if key not in known
        )
        out.extend(
            error
            for key, value in keys.items()
            if (threshold := known.get(key)) is not None
            for error in _threshold_value_errors(did, key, value, threshold)
        )


def _threshold_value_errors(did: str, key: str, value: Json, threshold: Json) -> list[str]:
    """A threshold in the example config must satisfy the type and range its manifest entry
    declares.

    The strict Phase 2 loader enforces exactly this rule (SCHEMAS.md -> Per-detector config
    manifest); the gate enforces it now, so an out-of-range value never ships in the example
    an operator copies.
    """
    path = f"example config threshold {did}.{key}"
    ttype = threshold.get("type")
    if ttype == "int" and (not isinstance(value, int) or isinstance(value, bool)):
        return [f"{path}: {value!r} is not an int"]
    if ttype == "float" and (isinstance(value, bool) or not isinstance(value, (int, float))):
        return [f"{path}: {value!r} is not a number"]
    if ttype == "string" and not isinstance(value, str):
        return [f"{path}: {value!r} is not a string"]
    rng = threshold.get("range")
    if (
        not in_vocab(ttype, NUMERIC_THRESHOLD_TYPES)
        or not isinstance(rng, list)
        or len(rng) != RANGE_BOUNDS
    ):
        return []
    numeric = isinstance(value, (int, float)) and not isinstance(value, bool)
    if not numeric or not rng[0] <= value <= rng[1]:
        return [f"{path}: {value!r} outside declared range {rng}"]
    return []


def check_detector_ids() -> list[str]:
    registered = spec_ids()
    out: list[str] = []
    if not registered:
        # Reporting every doc token and example-config mode as unknown would bury
        # the real cause; the detector spec check reports why the registry is empty.
        return ["tools/detector_spec.yaml yields no detector ids; see the detector spec check"]
    for p in MD_FILES:
        text = p.read_text(encoding="utf-8")
        out.extend(
            f"{p.relative_to(ROOT)}: detector ID not in registry: {tid}"
            for tid in sorted(detector_ids_in(text))
            if tid not in registered
        )

    # Every mode key in the example config must exist in the spec, and every
    # registered detector must have one.
    example = json.loads(
        (ROOT / "config" / "server-guard.example.json").read_text(encoding="utf-8")
    )
    example_modes = set(example.get("modes", {}).keys())
    out.extend(
        f"config example mode key not in registry: {mode_id}"
        for mode_id in sorted(example_modes - registered)
    )
    out.extend(
        f"config example missing mode key for registered detector: {mode_id}"
        for mode_id in sorted(registered - example_modes)
    )
    out.extend(_example_mode_errors(example))
    _manifest_errors(example, out)
    return out


# Detector modes in increasing severity. Raising one is a phase-gated operator decision
# (SCHEMAS.md -> Config schema, POLICY.md -> Enforcement gates), so the shipped example may
# never carry a mode above the one the spec declares as that detector's default.
MODE_SEVERITY = ("observe", "correct", "enforce")


def _example_mode_errors(example: Json) -> list[str]:
    """The example config may not ship a mode above the spec's default for any detector."""
    defaults = {did: d.get("default_mode") for did, d in render_detectors.identified(parsed_spec())}
    out = []
    for mode_id, mode in sorted(example.get("modes", {}).items()):
        if mode not in MODE_SEVERITY:
            continue
        default = defaults.get(mode_id)
        if default in MODE_SEVERITY and MODE_SEVERITY.index(mode) > MODE_SEVERITY.index(default):
            out.append(
                f"config example raises {mode_id} to '{mode}' above its spec default "
                f"'{default}'; phases raise modes through the POLICY.md gates, not the example"
            )
    return out


def _flatten(obj: dict[str, Json], prefix: str = "") -> list[str]:
    """Dotted paths for every leaf in a nested dict."""
    out = []
    for k, v in obj.items():
        path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.extend(_flatten(v, path))
        else:
            out.append(path)
    return out


def _schema_key_patterns() -> list[re.Pattern[str]]:
    """Compiled matchers for the SCHEMAS.md config-table key patterns."""
    return [_pattern_to_regex(pat) for pat in _schema_table_keys()]


def _pattern_to_regex(pat: str) -> re.Pattern[str]:
    """Compile a dotted schema key pattern; `<placeholder>` consumes one or more
    segments (detector IDs are family.subject, so usually two)."""
    parts = (
        ".+" if seg.startswith("<") and seg.endswith(">") else re.escape(seg)
        for seg in pat.split(".")
    )
    return re.compile(r"^" + r"\.".join(parts) + r"$")


def _matches_schema(path: str, patterns: list[re.Pattern[str]]) -> bool:
    """Match an example dotted path against compiled schema key patterns.

    A placeholder segment like <detectorId> consumes one or more dotted
    segments, so modes.<detectorId> matches modes.inventory.stack but not
    modes itself, and thresholds.<detectorId>.<key> matches
    thresholds.inventory.stack.stage_order.
    """
    return any(p.match(path) for p in patterns)


def _schema_type_ok(instance: Json, t: Json) -> bool:
    if isinstance(t, list):
        return any(_schema_type_ok(instance, tt) for tt in t)
    return {
        "string": isinstance(instance, str),
        "boolean": isinstance(instance, bool),
        "integer": isinstance(instance, int) and not isinstance(instance, bool),
        # JSON has no NaN or infinity: Python's json module parses the bare
        # literals anyway, and a non-finite value is unrepresentable downstream.
        "number": (isinstance(instance, int) and not isinstance(instance, bool))
        or (isinstance(instance, float) and math.isfinite(instance)),
        "object": isinstance(instance, dict),
        "array": isinstance(instance, list),
        "null": instance is None,
    }.get(t, False)


def _format_errors(instance: str, schema: Json, path: str) -> list[str]:
    """Assert the declared `format` keyword. Only `date-time` (RFC 3339) is in use.

    An offset is required: a date-time string without one parses fine but names
    no instant, and every reader would resolve it against its own local zone.
    Calendar validity (month lengths, leap days) comes from the platform parser,
    so a schema can state the contract without hand-rolled date arithmetic here.
    """
    fmt = schema.get("format")
    if fmt is None:
        return []
    if fmt not in SUPPORTED_FORMATS:
        return [f"{path}: schema declares unsupported format {fmt!r}"]
    not_a_date_time = [f"{path}: {instance!r} is not an RFC 3339 date-time"]
    if "T" not in instance:
        return not_a_date_time
    try:
        parsed = datetime.fromisoformat(instance)
    except ValueError:
        return not_a_date_time
    if parsed.tzinfo is None:
        return [f"{path}: {instance!r} carries no UTC offset"]
    return []


def _scalar_errors(instance: Json, schema: Json, path: str) -> list[str]:
    """Range, pattern, and length keywords, which apply to numbers and strings."""
    errs = []
    numeric = isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if numeric and isinstance(instance, float) and not math.isfinite(instance):
        # NaN compares false against every bound, so a range check alone reports
        # nothing and a NaN threshold reaches the loader as a comparison that
        # never fires. Infinity and NaN also have no JSON encoding.
        errs.append(f"{path}: {instance!r} is not a finite number")
        return errs
    if "minimum" in schema and numeric and instance < schema["minimum"]:
        errs.append(f"{path}: {instance} < minimum {schema['minimum']}")
    if "maximum" in schema and numeric and instance > schema["maximum"]:
        errs.append(f"{path}: {instance} > maximum {schema['maximum']}")
    if not isinstance(instance, str):
        return errs
    errs += _format_errors(instance, schema, path)
    if "pattern" in schema and not re.match(schema["pattern"], instance):
        errs.append(f"{path}: {instance!r} does not match {schema['pattern']}")
    if "minLength" in schema and len(instance) < schema["minLength"]:
        errs.append(f"{path}: length {len(instance)} < minLength {schema['minLength']}")
    if "maxLength" in schema and len(instance) > schema["maxLength"]:
        errs.append(f"{path}: length {len(instance)} > maxLength {schema['maxLength']}")
    return errs


def _object_errors(
    instance: dict[str, Json], schema: Json, path: str, depth: int, root: Json
) -> list[str]:
    """Property count, declared properties, pattern properties, and required keys."""
    errs = []
    if "maxProperties" in schema and len(instance) > schema["maxProperties"]:
        errs.append(f"{path}: {len(instance)} properties > maxProperties {schema['maxProperties']}")
    if "minProperties" in schema and len(instance) < schema["minProperties"]:
        errs.append(f"{path}: {len(instance)} properties < minProperties {schema['minProperties']}")
    names = schema.get("propertyNames")
    if names is not None:
        errs.extend(
            f"{path}: key {k!r} rejected by propertyNames"
            for k in instance
            if _schema_validate(k, names, f"{path}.{k}", depth + 1, root)
        )
    props = schema.get("properties", {})
    pats = schema.get("patternProperties", {})
    for k, v in instance.items():
        if k in props:
            errs += _schema_validate(v, props[k], f"{path}.{k}", depth + 1, root)
            continue
        pattern_schema = next((sub for pat, sub in pats.items() if re.match(pat, k)), None)
        if pattern_schema is not None:
            errs += _schema_validate(v, pattern_schema, f"{path}.{k}", depth + 1, root)
            continue
        # additionalProperties false rejects the key; a subschema validates its value.
        additional = schema.get("additionalProperties", True)
        if additional is False:
            errs.append(f"{path}: unexpected key {k!r}")
        elif additional is not True:
            errs += _schema_validate(v, additional, f"{path}.{k}", depth + 1, root)
    errs.extend(
        f"{path}: missing required key {req!r}"
        for req in schema.get("required", [])
        if req not in instance
    )
    return errs


def _array_errors(
    instance: list[Json], schema: Json, path: str, depth: int, root: Json
) -> list[str]:
    """Item count and the per-item schema."""
    errs = []
    if "minItems" in schema and len(instance) < schema["minItems"]:
        errs.append(f"{path}: {len(instance)} items < minItems {schema['minItems']}")
    if "maxItems" in schema and len(instance) > schema["maxItems"]:
        errs.append(f"{path}: {len(instance)} items > maxItems {schema['maxItems']}")
    if "items" in schema:
        for i, v in enumerate(instance):
            errs += _schema_validate(v, schema["items"], f"{path}[{i}]", depth + 1, root)
    return errs


def _resolve_ref(root: Json, ref: str) -> Json:
    """The subschema a local JSON pointer names, or a KeyError/TypeError."""
    if not ref.startswith("#/"):
        raise ValueError(f"only local refs are supported, got {ref!r}")
    node = root
    for token in ref[2:].split("/"):
        node = node[token.replace("~1", "/").replace("~0", "~")]
    return node


def _ref_target(schema: Json, path: str, root: Json) -> tuple[Json | None, list[str]]:
    """The subschema a local `$ref` names, or (None, errors) when it names none."""
    ref = schema["$ref"]
    if not isinstance(ref, str):
        return None, [f"{path}: $ref must be a string, got {ref!r}"]
    try:
        target = _resolve_ref(root, ref)
    except (KeyError, TypeError, ValueError) as exc:
        return None, [f"{path}: unresolvable $ref {ref!r}: {exc}"]
    if not isinstance(target, dict):
        return None, [f"{path}: $ref {ref!r} does not name a schema object"]
    return target, []


def _one_of_errors(instance: Json, branches: Json, path: str, depth: int, root: Json) -> list[str]:
    """Exactly one `oneOf` branch must accept the instance."""
    if not isinstance(branches, list) or not branches:
        return [f"{path}: oneOf must be a non-empty array, got {branches!r}"]
    results = [_schema_validate(instance, sub, path, depth + 1, root) for sub in branches]
    matched = [i for i, r in enumerate(results) if not r]
    if len(matched) == 1:
        return []
    errs = [f"{path}: matches {len(matched)} of oneOf branches (expected exactly 1)"]
    if not matched:
        # With no branch matching, the count alone says nothing about why. The
        # branches are mutually exclusive by contract, so the first reports why.
        errs += results[0]
    return errs


def _fast_path(
    instance: Json, schema: Json, path: str, depth: int, root: Json
) -> tuple[list[str] | None, Json]:
    """The terminal verdict for depth overflow, `$ref`, and `const`, or None to
    continue with the ordinary keywords. Returns (errors, root).

    A `$ref` is resolved against the document root, one depth level per ref, so a
    self-referential schema is bounded here like any other recursion.
    """
    if depth > MAX_SCHEMA_DEPTH:
        return [f"{path}: nesting deeper than {MAX_SCHEMA_DEPTH} levels"], root
    if root is None:
        # The outermost call's schema is the document every $ref resolves against.
        root = schema
    if "$ref" in schema:
        target, ref_errors = _ref_target(schema, path, root)
        return ref_errors or _schema_validate(instance, target, path, depth + 1, root), root
    if "const" in schema:
        if instance != schema["const"]:
            return [f"{path}: expected const {schema['const']!r}, got {instance!r}"], root
        return [], root
    return None, root


def _schema_validate(
    instance: Json, schema: Json, path: str = "$", depth: int = 0, root: Json = None
) -> list[str]:
    """Minimal JSON Schema (draft-07 subset) validator for the schemas we ship."""
    fast, root = _fast_path(instance, schema, path, depth, root)
    if fast is not None:
        return fast
    errs = []
    if "enum" in schema and instance not in schema["enum"]:
        errs.append(f"{path}: {instance!r} not in {schema['enum']}")
    if "type" in schema and not _schema_type_ok(instance, schema["type"]):
        errs.append(f"{path}: expected type {schema['type']}, got {type(instance).__name__}")
        return errs
    errs += _scalar_errors(instance, schema, path)
    if "oneOf" in schema:
        return errs + _one_of_errors(instance, schema["oneOf"], path, depth, root)
    if isinstance(instance, dict):
        errs += _object_errors(instance, schema, path, depth, root)
    if isinstance(instance, list):
        errs += _array_errors(instance, schema, path, depth, root)
    return errs


def check_evidence_sample_chain() -> list[str]:
    """The shipped evidence sample must verify as a hash chain."""
    return _run_tool("evidence_check.py", "--sample", on_failure="evidence sample chain broken")


def check_replay_contract() -> list[str]:
    """The design-time vertical-slice vector must satisfy its semantic expectations."""
    return _run_tool("replay_contract_check.py", on_failure="replay contract failed")


def load_instances(data_path: pathlib.Path) -> list[Json]:
    """Parse a data file into validator instances: one per record for JSONL, else one."""
    text = data_path.read_text(encoding="utf-8")
    if data_path.suffix == ".jsonl":
        return [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    return [json.loads(text)]


def _load_instances(data_path: pathlib.Path) -> tuple[list[Json], str | None]:
    """Parsed data documents, with a parse failure returned instead of raised.

    Returns (instances, error); error is None on success.
    """
    try:
        return load_instances(data_path), None
    except Exception as exc:
        return [], str(exc)


def check_config_schemas() -> list[str]:
    """Validate the shipped JSON Schemas parse and the example config and generated
    manifest conform to them."""
    out = []
    for schema_path, data_path in SCHEMA_DATA_PAIRS:
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        except Exception as exc:
            out.append(f"{schema_path.relative_to(ROOT)} unparseable: {exc}")
            continue
        name = data_path.relative_to(ROOT)
        instances, error = _load_instances(data_path)
        if error is not None:
            out.append(f"{name} unparseable: {error}")
            continue
        if data_path.suffix == ".jsonl":
            out.extend(
                f"{name} line {i}: {err}"
                for i, instance in enumerate(instances, 1)
                for err in _schema_validate(instance, schema)
            )
        else:
            out.extend(
                f"{name}: {err}"
                for instance in instances
                for err in _schema_validate(instance, schema)
            )
    return out


def _open_object_schemas(node: Json, path: str = "$") -> list[tuple[str, Json]]:
    """Every subschema of `node` that accepts properties beyond a declared set."""
    out: list[tuple[str, Json]] = []
    if not isinstance(node, dict):
        return out
    node_type = node.get("type")
    types = node_type if isinstance(node_type, list) else [node_type]
    if "object" in types and node.get("additionalProperties") is not False:
        out.append((path, node))
    for key in ("properties", "patternProperties"):
        for name, sub in (node.get(key) or {}).items():
            out += _open_object_schemas(sub, f"{path}.{key}.{name}")
    for i, sub in enumerate(node.get("oneOf") or []):
        out += _open_object_schemas(sub, f"{path}.oneOf[{i}]")
    return out + _open_object_schemas(node.get("items"), f"{path}.items")


def check_evidence_personal_data() -> list[str]:
    """Every open value bag in the evidence schema carries the one deny-list.

    Detectors write their observed and expected values into `context`,
    `observations`, `expected`, and `actual`; those bags are the one place a
    detector could hand a raw platform ID, a player name, an address, or a
    credential to the exporter, the operator, and the webhook consumer. The
    deny-list is the machine form of the SCHEMAS.md rule that no schema ever
    carries one. The list is declared once, in `definitions`, and every bag must
    $ref it: a second hand-written copy is where a newly denied key would be
    added to one bag and forgotten in another, and a bag that dropped the ref
    would still pass a presence-only check.
    """
    schema = json.loads(EVIDENCE_SCHEMA.read_text(encoding="utf-8"))
    deny = (schema.get("definitions") or {}).get(PERSONAL_DATA_DENY_LIST)
    if not isinstance(deny, dict) or "pattern" not in deny:
        return [
            f"evidence schema: definitions/{PERSONAL_DATA_DENY_LIST} is missing or has no pattern"
        ]
    out = []
    for path, sub in _open_object_schemas(schema):
        if "propertyNames" not in sub:
            out.append(f"evidence schema {path}: open object has no propertyNames deny-list")
        elif sub["propertyNames"] != {"$ref": DENY_LIST_REF}:
            out.append(
                f"evidence schema {path}: propertyNames is not the shared "
                f"deny-list ref {DENY_LIST_REF}"
            )
    return out


def check_folder_structure() -> list[str]:
    """The documented layout (docs/INDEX.md -> Repo layout) must hold: every directory
    under src/, tests/, tools/, config/ carries a README (empty dirs document their
    purpose), and the planned subfolders exist."""
    out: list[str] = []
    root_dirs = ["docs", "config", "src", "tests", "tools"]
    out.extend(
        f"missing documented directory: {name}/" for name in root_dirs if not (ROOT / name).is_dir()
    )
    for base in ["src", "tests", "tools", "config"]:
        for d in sorted((ROOT / base).rglob("*")):
            if not d.is_dir() or "__pycache__" in d.parts:
                continue
            if not any(x.name == "README.md" for x in d.iterdir()):
                out.append(f"directory without README: {d.relative_to(ROOT)}/")
    planned = [
        ROOT / "config" / "schemas",
        ROOT / "tools" / "fixtures" / "traces",
        ROOT / "tools" / "fixtures" / "regression",
        ROOT / "tools" / "fixtures" / "generators",
        ROOT / "tools" / "surface_inventory",
        ROOT / "tests" / "ServerGuard.Tests",
        ROOT / "tests" / "ServerGuard.MetadataTests",
        ROOT / "tests" / "ServerGuard.Replay",
    ]
    out.extend(
        f"missing planned directory: {d.relative_to(ROOT)}/" for d in planned if not d.is_dir()
    )
    return out


def check_config_example_keys() -> list[str]:
    patterns = _schema_key_patterns()
    example = json.loads(
        (ROOT / "config" / "server-guard.example.json").read_text(encoding="utf-8")
    )
    return [
        f"config key '{path}' not declared in SCHEMAS.md config table"
        for path in _flatten(example)
        if not _matches_schema(path, patterns)
    ]


# depth cap for the config-schema walk; the shipped config schema nests four levels.
MAX_CONFIG_DEPTH = 20


def _config_schema_leaves(schema: Json, prefix: str = "", depth: int = 0) -> list[tuple[str, Json]]:
    """Dotted paths and subschemas for every declared leaf under `properties`.

    patternProperties subtrees (per-detector mode and threshold keys) are skipped: their
    keys come from the registry and the manifest, and are covered by the detector-id and
    manifest checks instead.
    """
    if depth > MAX_CONFIG_DEPTH:
        return []
    out: list[tuple[str, Json]] = []
    for key, sub in schema.get("properties", {}).items():
        path = f"{prefix}.{key}" if prefix else key
        if not isinstance(sub, dict) or sub.get("patternProperties"):
            # A pattern-keyed subtree (modes, thresholds) has no leaves of its own: its
            # keys come from the registry and the manifest, checked elsewhere.
            continue
        if sub.get("properties"):
            out.extend(_config_schema_leaves(sub, path, depth + 1))
        else:
            out.append((path, sub))
    return out


def check_config_contract() -> list[str]:
    """Every schema key is documented, and every key without a default is in the example.

    Two drift directions the other checks do not cover: a schema key nobody documented
    (an operator cannot discover it), and a key added to the schema with no default that
    the example never shows (so every operator hits a required key they were never told
    about). config/README.md states both rules; this enforces them.
    """
    schema = json.loads(
        (ROOT / "config" / "schemas" / "config.v1.schema.json").read_text(encoding="utf-8")
    )
    example = json.loads(
        (ROOT / "config" / "server-guard.example.json").read_text(encoding="utf-8")
    )
    patterns = _schema_key_patterns()
    example_keys = set(_flatten(example))
    out = []
    for path, sub in _config_schema_leaves(schema):
        if not _matches_schema(path, patterns):
            out.append(f"config schema key '{path}' not declared in SCHEMAS.md config table")
        if "default" not in sub and path not in example_keys:
            out.append(f"config schema key '{path}' has no default and is missing from the example")
    return out


def check_required_docs() -> list[str]:
    return [d for d in REQUIRED_DOCS if not (ROOT / d).exists()]


def check_backup_runbook() -> list[str]:
    """The evidence store is the one state an operator cannot regenerate, so the
    archive tooling and the recovery contract must stay in place together: a
    Makefile target with no runbook, or a runbook citing a target that no longer
    exists, is a backup nobody can run."""
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    ops = (ROOT / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")
    out = [
        f"Makefile: missing the '{target}' target"
        for target in ("export-evidence", "verify-archive")
        if f"\n{target}:" not in makefile
    ]
    if "tools/evidence_export.py --self-test" not in makefile:
        out.append("Makefile: test-tools does not run the evidence export self-test")
    if "### Restore drill" not in ops:
        out.append("docs/OPERATIONS.md: no restore drill in the backup and restore runbook")
    out.extend(
        f"docs/OPERATIONS.md: backup runbook does not mention {marker!r}"
        for marker in ("| RPO | RTO |", "make export-evidence", "make verify-archive")
        if marker not in ops
    )
    return out


def _run_check(name: str, check: Callable[[], list[str]]) -> tuple[str, list[str]]:
    """Run one check, reporting an unexpected raise as that check's failure.

    The checks read hand-edited YAML, JSON, and markdown, so a malformed one can
    raise before it can report. Without this the first such check aborts the run
    and the remaining checks never execute, turning a single broken input into a
    gate that reports nothing.
    """
    try:
        return name, check()
    except Exception as exc:
        return name, [f"{type(exc).__name__}: {exc} (check aborted; its input may be malformed)"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()

    checks = [
        ("em dashes", check_em_dashes),
        ("links", check_links),
        ("TODO checkboxes", check_todo_format),
        ("detector spec", check_spec),
        ("registry sync", check_registry_sync),
        ("detector registry coverage", check_detector_ids),
        ("config example vs schema", check_config_example_keys),
        ("config schema vs docs", check_config_contract),
        ("config JSON schemas", check_config_schemas),
        ("evidence personal data", check_evidence_personal_data),
        ("evidence sample chain", check_evidence_sample_chain),
        ("replay contract", check_replay_contract),
        ("folder structure", check_folder_structure),
        ("backup runbook", check_backup_runbook),
        ("required docs", check_required_docs),
    ]
    failures = dict(_run_check(name, check) for name, check in checks)
    total = sum(len(v) for v in failures.values())
    print(
        f"doccheck: {total} issue(s) across {len(MD_FILES)} markdown "
        f"and {len(SOURCE_FILES)} source files"
    )
    for name, items in failures.items():
        if items:
            print(f"\n[{name}]", file=sys.stderr)
            for item in items[:MAX_REPORTED]:
                print("  " + item, file=sys.stderr)
            if len(items) > MAX_REPORTED:
                print(f"  ... and {len(items) - MAX_REPORTED} more", file=sys.stderr)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
