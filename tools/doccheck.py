"""Docs quality gate for 7dtd-server-guard.

Run from the repo root:  uv run python tools/doccheck.py   (or `make check`)

Checks:
   1. No em dashes (U+2014) in any markdown file or shipped source file (workspace rule).
   2. Every internal markdown link resolves to an existing file or anchor.
   3. TODO.md checkboxes use the canonical `- [ ]` / `- [x]` format.
   4. tools/detector_spec.yaml is well-formed and satisfies the D-07/D-15 ceiling
      rule plus the normal+violation fixture requirement per detector.
   5. docs/DETECTORS.md matches the rendered output of render_detectors.py.
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
import pathlib
import re
import subprocess
import sys
from datetime import datetime
from typing import Any

# Spec loading (and its PyYAML dependency guard) lives in render_detectors.
import render_detectors

# A parsed JSON Schema or instance: shape is what the validator below checks, so
# it cannot be narrowed statically.
Json = Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
MD_FILES = sorted(
    p
    for p in ROOT.rglob("*.md")
    if ".git" not in p.parts and ".venv" not in p.parts and "third-party" not in p.parts
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


def spec_ids() -> set[str]:
    """Registry ids, or an empty set when the spec does not parse (check_spec reports that)."""
    try:
        return {d["id"] for d in render_detectors.load_spec()}
    except Exception:
        return set()


def _threshold_errors(did: str, thresholds: list[Json]) -> list[str]:
    """Threshold keys are unique, typed, and carry a sane range and default."""
    out = []
    keys = [t.get("key") for t in thresholds]
    if None in keys:
        out.append(f"{did}: threshold missing key")
    elif len(keys) != len(set(keys)):
        out.append(f"{did}: duplicate threshold keys")
    for t in thresholds:
        ttype = t.get("type")
        if ttype not in SPEC_THRESHOLD_TYPES:
            out.append(f"{did}: threshold {t.get('key')} bad type {ttype}")
            continue
        rng = t.get("range")
        if ttype not in {"int", "float"} or not isinstance(rng, list):
            continue
        if len(rng) != RANGE_BOUNDS or rng[0] > rng[1]:
            out.append(f"{did}: threshold {t.get('key')} bad range {rng}")
        elif isinstance(t.get("default"), (int, float)) and not rng[0] <= t["default"] <= rng[1]:
            out.append(
                f"{did}: threshold {t.get('key')} default {t.get('default')} "
                f"outside range {rng}"
            )
    return out


def _detector_errors(d: Json) -> list[str]:
    """Required fields, input authority/role vocabulary, fixtures, and the D-07 rule."""
    did = d.get("id")
    out = []
    if d.get("family") not in SPEC_FAMILIES:
        out.append(f"{did}: bad family {d.get('family')}")
    if d.get("ceiling") not in SPEC_CEILINGS:
        out.append(f"{did}: bad ceiling {d.get('ceiling')}")
    if d.get("default_mode") not in {"observe", "correct", "enforce"}:
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
    if not inputs:
        out.append(f"{did}: no inputs")
    for i in inputs:
        if i.get("authority") not in SPEC_AUTHORITIES:
            out.append(f"{did}: input {i.get('name')} bad authority {i.get('authority')}")
        if i.get("role") not in SPEC_ROLES:
            out.append(f"{did}: input {i.get('name')} bad role {i.get('role')}")
    fixtures = set(d.get("fixtures", []))
    out.extend(
        f"{did}: fixture {f} outside TEST_PLAN families"
        for f in sorted(fixtures - ALLOWED_FIXTURES)
    )
    # TEST_PLAN.md Layer 4: every detector ships normal and violation traces.
    if "normal" not in fixtures or "violation" not in fixtures:
        out.append(f"{did}: must declare normal and violation fixtures (TEST_PLAN Layer 4)")
    # D-07 rule: Hard requires all decision inputs server-derived, or a hard_condition.
    decision_client = [
        i["name"]
        for i in inputs
        if i.get("role") == "decision" and i.get("authority") == "client-declared"
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
    except Exception as exc:
        return [f"tools/detector_spec.yaml unparseable: {exc}"]

    out = []
    ids: list[str] = [str(d.get("id")) for d in detectors if d.get("id") is not None]
    if len(ids) != len(detectors):
        out.append("detector entry without an id in tools/detector_spec.yaml")
    if len(ids) != len(set(ids)):
        dups = sorted({i for i in ids if ids.count(i) > 1})
        out.append(f"duplicate detector ids in spec: {dups}")
    for d in detectors:
        out += _detector_errors(d)
    return out


def _run_tool(script: str, *args: str, on_failure: str) -> list[str]:
    """Run a sibling tool as a gate. Returns its output as errors when it exits nonzero.

    A separate process keeps each tool's argparse and exit-code contract as the gated
    surface, instead of importing internals the CLI does not expose.
    """
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / script), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    if proc.returncode != 0:
        return [proc.stdout.strip() or proc.stderr.strip() or on_failure]
    return []


def check_registry_sync() -> list[str]:
    """docs/DETECTORS.md tables must match the rendered output from the spec."""
    return _run_tool("render_detectors.py", "--check", on_failure="registry is stale")


def _manifest_errors(example: Json, out: list[str]) -> None:
    """Manifest metadata must track the spec, and both must cover the example config."""
    manifest = json.loads((ROOT / "config" / "detector-config-manifest.json").read_text())
    spec_by_id = {d["id"]: d for d in render_detectors.load_spec()}
    manifest_keys: dict[str, dict[str, Json]] = {}
    manifest_ids: set[str] = set()
    for entry in manifest["detectors"]:
        manifest_ids.add(entry["detectorId"])
        spec_entry = spec_by_id.get(entry["detectorId"])
        if spec_entry is None:
            out.append(f"manifest detector {entry.get('detectorId')} not in spec")
            continue
        if (
            entry.get("phase") != spec_entry["phase"]
            or entry.get("ceiling") != spec_entry["ceiling"]
            or entry.get("defaultMode") != spec_entry["default_mode"]
        ):
            out.append(f"manifest metadata drift for {entry['detectorId']}; re-run make detectors")
        declared = {t["key"] for t in spec_entry.get("thresholds", [])}
        manifest_keys[entry["detectorId"]] = {t["key"]: t for t in entry.get("thresholds", [])}
        out.extend(
            f"manifest threshold {entry['detectorId']}.{t['key']} not declared in spec"
            for t in entry.get("thresholds", [])
            if t["key"] not in declared
        )
        out.extend(
            f"manifest is missing threshold {entry['detectorId']}.{key} declared in spec; "
            "re-run make detectors"
            for key in sorted(declared - set(manifest_keys[entry["detectorId"]]))
        )
    out.extend(
        f"manifest is missing detector {d} declared in spec; re-run make detectors"
        for d in sorted(set(spec_by_id) - manifest_ids)
    )
    for did, keys in example.get("thresholds", {}).items():
        out.extend(
            f"example config threshold {did}.{key} not in generated manifest"
            for key in keys
            if key not in manifest_keys.get(did, {})
        )
        for key, value in keys.items():
            spec_threshold = manifest_keys.get(did, {}).get(key)
            if spec_threshold is not None:
                out.extend(_threshold_value_errors(did, key, value, spec_threshold))


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
    if ttype not in {"int", "float"} or not isinstance(rng, list) or len(rng) != RANGE_BOUNDS:
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
    example = json.loads((ROOT / "config" / "server-guard.example.json").read_text())
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
    defaults = {d["id"]: d["default_mode"] for d in render_detectors.load_spec()}
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
        "number": isinstance(instance, (int, float)) and not isinstance(instance, bool),
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


def _object_errors(instance: dict[str, Json], schema: Json, path: str, depth: int) -> list[str]:
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
            if _schema_validate(k, names, f"{path}.{k}", depth + 1)
        )
    props = schema.get("properties", {})
    pats = schema.get("patternProperties", {})
    for k, v in instance.items():
        if k in props:
            errs += _schema_validate(v, props[k], f"{path}.{k}", depth + 1)
            continue
        pattern_schema = next((sub for pat, sub in pats.items() if re.match(pat, k)), None)
        if pattern_schema is not None:
            errs += _schema_validate(v, pattern_schema, f"{path}.{k}", depth + 1)
            continue
        # additionalProperties false rejects the key; a subschema validates its value.
        additional = schema.get("additionalProperties", True)
        if additional is False:
            errs.append(f"{path}: unexpected key {k!r}")
        elif additional is not True:
            errs += _schema_validate(v, additional, f"{path}.{k}", depth + 1)
    errs.extend(
        f"{path}: missing required key {req!r}"
        for req in schema.get("required", [])
        if req not in instance
    )
    return errs


def _array_errors(instance: list[Json], schema: Json, path: str, depth: int) -> list[str]:
    """Item count and the per-item schema."""
    errs = []
    if "minItems" in schema and len(instance) < schema["minItems"]:
        errs.append(f"{path}: {len(instance)} items < minItems {schema['minItems']}")
    if "maxItems" in schema and len(instance) > schema["maxItems"]:
        errs.append(f"{path}: {len(instance)} items > maxItems {schema['maxItems']}")
    if "items" in schema:
        for i, v in enumerate(instance):
            errs += _schema_validate(v, schema["items"], f"{path}[{i}]", depth + 1)
    return errs


def _schema_validate(instance: Json, schema: Json, path: str = "$", _depth: int = 0) -> list[str]:
    """Minimal JSON Schema (draft-07 subset) validator for the schemas we ship."""
    if _depth > MAX_SCHEMA_DEPTH:
        return [f"{path}: nesting deeper than {MAX_SCHEMA_DEPTH} levels"]
    if "const" in schema:
        if instance != schema["const"]:
            return [f"{path}: expected const {schema['const']!r}, got {instance!r}"]
        return []
    errs = []
    if "enum" in schema and instance not in schema["enum"]:
        errs.append(f"{path}: {instance!r} not in {schema['enum']}")
    if "type" in schema and not _schema_type_ok(instance, schema["type"]):
        errs.append(f"{path}: expected type {schema['type']}, got {type(instance).__name__}")
        return errs
    errs += _scalar_errors(instance, schema, path)
    if "oneOf" in schema:
        matched = [
            i
            for i, sub in enumerate(schema["oneOf"])
            if not _schema_validate(instance, sub, path, _depth + 1)
        ]
        if len(matched) != 1:
            errs.append(f"{path}: matches {len(matched)} of oneOf branches (expected exactly 1)")
        return errs
    if isinstance(instance, dict):
        errs += _object_errors(instance, schema, path, _depth)
    if isinstance(instance, list):
        errs += _array_errors(instance, schema, path, _depth)
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
        try:
            instances = load_instances(data_path)
        except Exception as exc:
            out.append(f"{data_path.relative_to(ROOT)} unparseable: {exc}")
            continue
        for i, instance in enumerate(instances, 1):
            out.extend(
                f"{data_path.relative_to(ROOT)} line {i}: {err}"
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
    """Every open value bag in the evidence schema carries the deny-list.

    Detectors write their observed and expected values into `context`,
    `observations`, `expected`, and `actual`; those bags are the one place a
    detector could hand a raw platform ID, a player name, an address, or a
    credential to the exporter, the operator, and the webhook consumer. The
    deny-list is the machine form of the SCHEMAS.md rule that no schema ever
    carries one.
    """
    schema = json.loads(EVIDENCE_SCHEMA.read_text(encoding="utf-8"))
    return [
        f"evidence schema {path}: open object has no propertyNames deny-list"
        for path, sub in _open_object_schemas(schema)
        if "propertyNames" not in sub
    ]


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
    example = json.loads((ROOT / "config" / "server-guard.example.json").read_text())
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
    schema = json.loads((ROOT / "config" / "schemas" / "config.v1.schema.json").read_text())
    example = json.loads((ROOT / "config" / "server-guard.example.json").read_text())
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()

    failures: dict[str, list[str]] = {
        "em dashes": check_em_dashes(),
        "links": check_links(),
        "TODO checkboxes": check_todo_format(),
        "detector spec": check_spec(),
        "registry sync": check_registry_sync(),
        "detector registry coverage": check_detector_ids(),
        "config example vs schema": check_config_example_keys(),
        "config schema vs docs": check_config_contract(),
        "config JSON schemas": check_config_schemas(),
        "evidence personal data": check_evidence_personal_data(),
        "evidence sample chain": check_evidence_sample_chain(),
        "replay contract": check_replay_contract(),
        "folder structure": check_folder_structure(),
        "backup runbook": check_backup_runbook(),
        "required docs": check_required_docs(),
    }
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
