"""Minimal JSON Schema (draft-07 subset) validator for the schemas this repo ships.

The validator is a library, not a gate: the docs gate (`doccheck.py`) and the
config validator (`config_check.py`) both hold documents to the shipped schemas
through `validate`, so it lives here rather than inside either caller. What the
subset is and why it is not a full implementation is documented on `validate`.
"""

from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Any

# A parsed JSON Schema or instance: shape is what this module checks, so it
# cannot be narrowed statically.
Json = Any

# Recursion bound. Shipped schemas nest at most ~6 levels; the cap only bites on
# pathological documents (deeply nested or self-referential schemas), where
# unbounded recursion would end in RecursionError instead of a reported error.
MAX_SCHEMA_DEPTH = 100

# `format` values the validator asserts. A schema declaring anything else is
# reported rather than silently accepted as unchecked.
SUPPORTED_FORMATS = frozenset({"date-time"})


def _pattern_ok(pattern: str, value: str) -> bool:
    """Whether `value` satisfies a JSON Schema `pattern`.

    `pattern` is an unanchored search, and its `$` is the end of the value. Python's
    `$` also matches immediately before a trailing newline, so `re.match` on a
    fully anchored pattern accepts a value carrying one: "movement.flight\\n" passes
    `^[a-z]+\\.[a-z_]+$` here and is rejected by every conformant validator, which
    makes a stray newline at the end of a detector id, a cause token, or a file name
    a value this validator approves and the loader refuses. A pattern anchored at
    both ends is therefore matched whole; an unanchored one is searched, as the
    spec says.
    """
    if pattern.startswith("^") and pattern.endswith("$") and not pattern.endswith("\\$"):
        return re.fullmatch(pattern, value) is not None
    return re.search(pattern, value) is not None


def _json_equal(instance: Json, expected: Json) -> bool:
    """JSON equality, where a boolean is never a number and never a string.

    Python's `==` says `True == 1` and `False == 0`, so a plain comparison lets a
    record declaring `"schemaVersion": true` satisfy `{"const": 1}` and a `1` in an
    instance satisfy `{"enum": [true]}`. JSON keeps booleans and numbers in
    separate types, and a version field is exactly the place a false match hides.
    """
    if isinstance(instance, bool) != isinstance(expected, bool):
        return False
    return bool(instance == expected)


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
    if "pattern" in schema and not _pattern_ok(schema["pattern"], instance):
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
            if validate(k, names, f"{path}.{k}", depth + 1, root)
        )
    props = schema.get("properties", {})
    pats = schema.get("patternProperties", {})
    for k, v in instance.items():
        if k in props:
            errs += validate(v, props[k], f"{path}.{k}", depth + 1, root)
            continue
        pattern_schema = next((sub for pat, sub in pats.items() if _pattern_ok(pat, k)), None)
        if pattern_schema is not None:
            errs += validate(v, pattern_schema, f"{path}.{k}", depth + 1, root)
            continue
        # additionalProperties false rejects the key; a subschema validates its value.
        additional = schema.get("additionalProperties", True)
        if additional is False:
            errs.append(f"{path}: unexpected key {k!r}")
        elif additional is not True:
            errs += validate(v, additional, f"{path}.{k}", depth + 1, root)
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
            errs += validate(v, schema["items"], f"{path}[{i}]", depth + 1, root)
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
    results = [validate(instance, sub, path, depth + 1, root) for sub in branches]
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
        return ref_errors or validate(instance, target, path, depth + 1, root), root
    if "const" in schema:
        if not _json_equal(instance, schema["const"]):
            return [f"{path}: expected const {schema['const']!r}, got {instance!r}"], root
        return [], root
    return None, root


def validate(
    instance: Json, schema: Json, path: str = "$", depth: int = 0, root: Json = None
) -> list[str]:
    """Validate an instance against `schema`, returning one message per violation.

    The keyword subset is the one the shipped schemas under `config/schemas/` use:
    type, enum, const, properties, patternProperties, propertyNames,
    additionalProperties, required, items, minItems, maxItems, minProperties,
    maxProperties, minimum, maximum, minLength, maxLength, pattern, format
    (date-time only), allOf, oneOf, and local `$ref`. A keyword outside that set is
    ignored, so a schema relying on one is not fully checked and should not ship.
    """
    fast, root = _fast_path(instance, schema, path, depth, root)
    if fast is not None:
        return fast
    errs = []
    if "enum" in schema and not any(_json_equal(instance, e) for e in schema["enum"]):
        errs.append(f"{path}: {instance!r} not in {schema['enum']}")
    if "type" in schema and not _schema_type_ok(instance, schema["type"]):
        errs.append(f"{path}: expected type {schema['type']}, got {type(instance).__name__}")
        return errs
    errs += _scalar_errors(instance, schema, path)
    if "oneOf" in schema:
        return errs + _one_of_errors(instance, schema["oneOf"], path, depth, root)
    for sub in schema.get("allOf") or []:
        errs += validate(instance, sub, path, depth + 1, root)
    if isinstance(instance, dict):
        errs += _object_errors(instance, schema, path, depth, root)
    if isinstance(instance, list):
        errs += _array_errors(instance, schema, path, depth, root)
    return errs
