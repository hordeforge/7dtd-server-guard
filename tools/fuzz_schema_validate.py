"""Fuzz the JSON Schema validator (tools/doccheck.py -> _schema_validate).

_schema_validate is the reference validator behind every schema gate in this repo:
doccheck runs it over the example config, the generated manifest, the evidence
sample, and the replay-trace fixture, and the Phase 2 strict config loader is
specified from the same schemas (docs/SCHEMAS.md). It walks fully attacker-shaped
documents with unbounded recursion, so this harness throws structure-aware
mutations at it:

  target 1  _schema_validate over mutated schema/instance pairs built from all
            four shipped schema + data pairs
  target 2  deep-nesting probe: instances nested far past any legitimate document

Fixed probes: RFC 3339 offsets on timestamp fields, non-finite numbers
(NaN, +/-Infinity) on bounded and unbounded numeric fields, a boolean never
matching a numeric `const` or `enum`, the cross-record reference fields (a
record ID, and a bounded count of them), and the detector spec's threshold
range/default gate.

Invariants asserted per iteration:
  - Totality: no exception (RecursionError included) escapes the validator.
  - The result is a list of str.
  - Determinism: two consecutive runs on the same input return equal results.
  - Sensitivity pair assertion: deleting a required key from a pristine valid
    instance must produce at least one error.
  - Pristine shipped pairs validate clean.
  - The evidence schema refuses personal-data keys in its open value bags.

Deterministic (seeded PRNG), stdlib only, no external fuzzer required.

Usage:
  uv run python tools/fuzz_schema_validate.py [--iterations N] [--seed S]

Exit codes: 0 every invariant held, 1 an invariant broke, 2 usage error. The
replay of a reported failure is `uv run python tools/fuzz_schema_validate.py
--seed <seed>`; the failure and its input go to stderr.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import doccheck as dc
from fuzz_common import InvariantBrokenError, Mutator, add_fuzz_args, fuzz_args, nested

# Schemas and instances are arbitrary JSON by construction here: the harness
# exists to feed the validator documents no static type would admit.
Json = Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "config" / "schemas" / "evidence.v1.schema.json"
SAMPLE_PATH = ROOT / "config" / "schemas" / "evidence.v1.sample.jsonl"


def evidence_schema() -> Json:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def sample_records() -> dict[str, Json]:
    """The shipped sample, keyed by record type, one record each."""
    text = SAMPLE_PATH.read_text(encoding="utf-8")
    return {rec["type"]: rec for rec in (json.loads(ln) for ln in text.splitlines() if ln.strip())}


# A finding hands `context`, `observations`, `expected`, and `actual` to the
# exporter, the operator, and the webhook consumer, so a key that could hold a
# raw identity, a contact address, a network address, or a credential must be
# rejected there. The spelling variants matter: a detector's local naming is its
# own choice, so the deny-list has to hold against the joined-lowercase spellings
# too. A list of whole spellings is defeated by the first variant nobody wrote
# down (`ipaddress`, `hwaddr`, `clientip` read as ordinary snake_case), and the
# camelCase spellings below are stopped by the key charset rather than by the
# deny-list, so both shapes are probed here to keep either one from regressing.
PERSONAL_DATA_KEYS = (
    "steamId",
    "STEAM_ID",
    "steam_id",
    "platformId",
    "platform_id",
    "playerName",
    "player_name",
    "username",
    "client_id",
    "ip",
    "ipAddress",
    "ip_address",
    "ipaddress",
    "ipaddr",
    "clientip",
    "eacGuid",
    "eacguid",
    "auth_ticket",
    "password",
    "passwd",
    "macAddress",
    "mac_address",
    "macaddress",
    "hardware_id",
    "hwaddr",
    "email",
    # The same account under the spelling the engine's own API uses, and the
    # display-name family. A deny-list that names only one spelling of a
    # platform id is half a control: the other spelling carries the same digits
    # to the same exporter.
    "xuid",
    "xuid_value",
    "playerName",
    "nickname",
    "nick",
    "handle",
    "displayName",
    "alias",
    "realName",
    "accountLogin",
    "loginName",
)
# The open bags of a `finding` record, and how to inject a key into each.
EVIDENCE_BAGS = ("context", "expected", "actual", "observations")
# Value-bag keys that name a measured quantity and must survive the deny-list.
# Every one is a key the shipped sample writes, or a spelling the detector spec
# and SCHEMAS.md use for the same kind of measurement.
ALLOWED_BAG_KEYS = (
    "dx",
    "bound",
    "budget",
    "tick",
    "admin",
    "stance",
    "teleport",
    "vehicle",
    "note",
    "delta",
    "sequence",
    "quantity",
)


def load_pairs() -> list[tuple[str, Json, list[Json]]]:
    out = []
    for schema_path, data_path in dc.SCHEMA_DATA_PAIRS:
        name = f"{schema_path.name} vs {data_path.name}"
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            instances = dc.load_instances(data_path)
        except (OSError, ValueError) as exc:
            raise InvariantBrokenError(
                f"shipped pair {name} is unreadable or unparseable: {exc}"
            ) from exc
        for inst in instances:
            errs = dc._schema_validate(inst, schema)
            if errs:
                raise InvariantBrokenError(f"pristine shipped pair {name} reports errors: {errs}")
        out.append((name, schema, instances))
    return out


def check_totality(schema: Json, instance: Json) -> list[str]:
    # The list-ness of the result is now statically guaranteed; the element types
    # are not, because the validator builds messages from mutated content.
    errs = dc._schema_validate(instance, schema)
    if not all(isinstance(e, str) for e in errs):
        raise InvariantBrokenError(f"non-list-of-str result: {errs!r}")
    again = dc._schema_validate(instance, schema)
    if again != errs:
        raise InvariantBrokenError(f"nondeterministic: {errs!r} vs {again!r}")
    return errs


def check_sensitivity(rng: random.Random, name: str, schema: Json, instance: Json) -> bool:
    """Deleting a required top-level key from a valid instance must be caught."""
    required = schema.get("required") or []
    if not required or not isinstance(instance, dict):
        return False
    bad = dict(instance)
    del bad[required[rng.randrange(len(required))]]
    if not dc._schema_validate(bad, schema):
        raise InvariantBrokenError(f"{name}: deleting required key was accepted")
    return True


def check_deep_nesting() -> None:
    """Deeply nested / self-referential schemas must yield errors, never RecursionError."""
    # Self-referential (aliased) schema: validator recursion tracks instance depth.
    cyclic: dict[str, Any] = {"type": "array"}
    cyclic["items"] = cyclic
    # Deep linear schema walked by a matching deep instance.
    deep: dict[str, Any] = {"type": "object"}
    node = deep
    for _ in range(4 * dc.MAX_SCHEMA_DEPTH):
        child = {"type": "object"}
        node["properties"] = {"a": child}
        node = child
    deep_inst: dict[str, Any] = {}
    cur = deep_inst
    for _ in range(4 * dc.MAX_SCHEMA_DEPTH):
        cur["a"] = {}
        cur = cur["a"]
    cases = [
        ("cyclic schema", cyclic, nested(4 * dc.MAX_SCHEMA_DEPTH)),
        ("deep schema", deep, deep_inst),
        (
            "shallow schema",
            {"type": "array", "items": {"type": "integer"}},
            nested(dc.MAX_SCHEMA_DEPTH + 1),
        ),
        ("at the bound", cyclic, nested(dc.MAX_SCHEMA_DEPTH)),
    ]
    for name, schema, inst in cases:
        try:
            errs = dc._schema_validate(inst, schema)
        except Exception as exc:
            raise InvariantBrokenError(f"{name} raised {type(exc).__name__}") from exc
        if not isinstance(errs, list):
            raise InvariantBrokenError(f"{name}: non-list result {errs!r}")
        again = dc._schema_validate(inst, schema)
        if again != errs:
            raise InvariantBrokenError(f"{name}: nondeterministic")
        if name in ("cyclic schema", "deep schema"):
            if len(errs) != 1 or "nesting deeper" not in errs[0]:
                raise InvariantBrokenError(f"{name}: unexpected errors {errs!r}")
        elif name == "shallow schema":
            if not errs:
                raise InvariantBrokenError(f"{name}: pathological document accepted silently")
        elif errs:  # at the bound: depth MAX_SCHEMA_DEPTH must still validate clean
            raise InvariantBrokenError(f"{name}: rejected at the legal bound: {errs!r}")


def check_datetime_format() -> None:
    """Timestamp fields must be UTC instants spelled with `Z`, not local-time strings.

    A value like `2026-07-21T12:34:56` names no instant: each reader resolves it
    against its own zone, so the same record reads as a different moment in
    different deployments. An impossible calendar date is rejected by the same
    path, since `format` is asserted by the platform parser. A non-UTC offset
    names the right moment and is still refused, because its calendar date is
    the writer's local one and the segment that holds the record is named for
    the UTC date.
    """
    schema = evidence_schema()
    records = sample_records()
    field_of = {"finding": "utc", "audit": "utc", "reconciliation": "savedAt"}
    good_values = ("2026-07-21T12:34:56.789Z", "2026-07-21T12:34:56Z")
    bad_values = {
        "2026-07-21T12:34:56.789": "no offset: resolved against the reader's zone",
        "2026-07-21 12:34:56Z": "space separator instead of the RFC 3339 T",
        "2026-07-21T12:34:56": "local wall time with no offset at all",
        "2026-02-30T00:00:00Z": "impossible calendar date",
        "1753098896": "epoch seconds in a string field",
        "yesterday": "not a date at all",
        "2026-07-21T12:34:56+02:00": "non-UTC offset: right instant, local calendar date",
        "2026-07-21T12:34:56-00:00": "zero spelled as a numeric offset rather than Z",
        "2026-07-21T12:34:56+0200": "numeric offset without the RFC 3339 colon",
        "20260721T123456Z": "basic-format date-time, not the extended form",
    }
    for rec_type, field in field_of.items():
        pristine = records[rec_type]
        for good in good_values:
            if dc._schema_validate({**pristine, field: good}, schema):
                raise InvariantBrokenError(f"{rec_type}.{field}: valid instant {good!r} rejected")
        for value, why in bad_values.items():
            if not dc._schema_validate({**pristine, field: value}, schema):
                raise InvariantBrokenError(f"{rec_type}.{field}={value!r} accepted: {why}")


def _with_key(record: Json, bag: str, key: str) -> Json:
    """A copy of `record` carrying `key` inside the open bag `bag`."""
    bad = json.loads(json.dumps(record))
    if bag == "observations":
        bad["observations"][0][key] = "x"
    else:
        bad[bag][key] = "x"
    return bad


def check_personal_data_denylist() -> int:
    """Every personal-data spelling must be rejected in every open evidence bag.

    doccheck.py keeps every open object carrying the deny-list; this pins that
    the deny-list it carries actually fires, in each bag a finding writes to.
    """
    schema = evidence_schema()
    records = sample_records()
    if "finding" not in records:
        raise InvariantBrokenError("no finding record in the shipped evidence sample")
    record = records["finding"]
    checks = 0
    for key in PERSONAL_DATA_KEYS:
        for bag in EVIDENCE_BAGS:
            if not dc._schema_validate(_with_key(record, bag, key), schema):
                raise InvariantBrokenError(f"{bag}.{key} accepted by the evidence schema")
            checks += 1
    # The deny-list must not reject the keys the sample itself writes.
    if dc._schema_validate(record, schema):
        raise InvariantBrokenError("shipped finding record rejected by its own schema")
    # Nor the keys a detector names a value for. A deny-list broad enough to
    # reject `dx` is not a control, it is an outage: the next stem added for
    # sound reasons takes the whole bag with it, so the accepted names are
    # pinned here next to the denied ones.
    for key in ALLOWED_BAG_KEYS:
        for bag in EVIDENCE_BAGS:
            if dc._schema_validate(_with_key(record, bag, key), schema):
                raise InvariantBrokenError(f"{bag}.{key} rejected by the evidence schema")
            checks += 1
    return checks


def check_open_bag_walk() -> int:
    """The open-bag walk must see a bag however the schema reaches it.

    The evidence schema declares its shapes once in `definitions` and $refs them,
    so a walk that stopped at a ref saw a node with no `type` and missed the bag:
    a value bag moved into a definition, or named by an `additionalProperties`
    subschema, passed the gate holding any key a detector wrote. Each case adds
    exactly one unguarded bag and requires the walk to report it; the shipped
    schema, which has six, must still report no error.
    """
    schema = evidence_schema()
    if dc.check_evidence_personal_data():
        raise InvariantBrokenError("the shipped evidence schema failed its own deny-list check")
    cases = {
        "a bag declared in definitions and $ref'd": (
            {"type": "object"},
            "properties",
        ),
        "an array bag declared in definitions and $ref'd": (
            {"type": "array"},
            "properties",
        ),
        "a bag named by an additionalProperties subschema": (
            {"type": "object", "propertyNames": {"$ref": "#/definitions/personalDataDenyList"}},
            "additionalProperties",
        ),
    }
    checks = 0
    for what, (definition, holder) in cases.items():
        mutant = json.loads(json.dumps(schema))
        mutant["definitions"]["openBagProbe"] = definition
        if holder == "properties":
            mutant["oneOf"][0][holder]["openBagProbe"] = {"$ref": "#/definitions/openBagProbe"}
        else:
            mutant["oneOf"][0][holder] = {"$ref": "#/definitions/openBagProbe"}
        reported = [p for p, _ in dc._open_value_bags(mutant) if "openBagProbe" in p]
        if not reported:
            raise InvariantBrokenError(f"{what} was not seen as an open value bag")
        checks += 1
    return checks


def check_evidence_bags_beyond_finding() -> None:
    """The bags outside a `finding` hold the same rule: ids are ids, keys are denied.

    A list declared as an array of free-form strings carries no shape at all, so
    a raw name rides in an `evidenceIds` entry exactly as it would in a value
    bag, and an array with no `items` schema accepts any element. The
    reconciliation record's `deltaItems` and the id lists are the only places
    this is reachable outside the `finding` bags.
    """
    schema = evidence_schema()
    records = sample_records()
    cases = [
        ("finding.causeEventIds", {**records["finding"], "causeEventIds": ["a-player-name"]}),
        ("finding.causeEventIds", {**records["finding"], "causeEventIds": [1234]}),
        ("cause.causeEventIds", {**records["cause"], "causeEventIds": ["STEAM_0:1:2"]}),
        ("audit.evidenceIds", {**records["audit"], "evidenceIds": ["ip=203.0.113.7"]}),
        (
            "reconciliation.deltaItems",
            {**records["reconciliation"], "deltaItems": [{"ipaddress": "203.0.113.7"}]},
        ),
        (
            "reconciliation.deltaItems",
            {**records["reconciliation"], "deltaItems": [{"note": "resourceWood"}]},
        ),
    ]
    for what, instance in cases[:-1]:
        if not dc._schema_validate(instance, schema):
            raise InvariantBrokenError(f"{what} accepted a value that is not an id: {instance}")
    # The last case is the positive control: without it the negative cases would
    # also pass against a schema that rejected every delta item.
    if dc._schema_validate(cases[-1][1], schema):
        raise InvariantBrokenError(f"{cases[-1][0]}: a well-formed delta item was rejected")


def check_non_finite_numbers() -> None:
    """Bounded and unbounded numeric fields must reject NaN and the infinities.

    NaN compares false against every bound, so a range check alone reports
    nothing and the value reaches the loader as a comparison that never fires.
    JSON has no encoding for either, so a strict reader downstream rejects the
    document outright.
    """
    schema = evidence_schema()
    records = sample_records()
    # confidence is bounded (0..1); delta is a number with no bounds, so only the
    # finiteness check stands between an unbounded field and a NaN.
    for rec_type, field, finite in (
        ("finding", "confidence", 0.5),
        ("cause", "delta", -1.25),
    ):
        for bad in (float("nan"), float("inf"), -float("inf")):
            if not dc._schema_validate({**records[rec_type], field: bad}, schema):
                raise InvariantBrokenError(f"{rec_type}.{field}={bad!r} accepted")
        if dc._schema_validate({**records[rec_type], field: finite}, schema):
            raise InvariantBrokenError(f"{rec_type}.{field}={finite!r} rejected")


def check_threshold_gate() -> None:
    """The detector spec's threshold gate must reject the numeric traps.

    A NaN default or bound compares false against every other bound, so it slips
    through an ordering check; a fractional value on an `int` threshold is
    truncated on load, so the spec no longer describes the value that runs.
    """
    ok = {"key": "burst", "type": "int", "range": [1, 100], "default": 50}
    bad = [
        ({**ok, "default": float("nan")}, "NaN default"),
        ({**ok, "range": [float("inf"), 100]}, "infinite range bound"),
        ({**ok, "range": [100, 1]}, "inverted range"),
        ({**ok, "range": [1.5, 100]}, "fractional bound on an int threshold"),
        ({**ok, "default": 1.5}, "fractional default on an int threshold"),
        ({**ok, "default": 200}, "default outside the range"),
        ({"type": "int", "range": [1, 100], "default": 5}, "missing key"),
        ({"key": "burst", "range": [1, 100], "default": 5}, "missing type"),
    ]
    if dc._threshold_errors("d.test", [ok]):
        raise InvariantBrokenError("well-formed threshold reported errors")
    for threshold, why in bad:
        if not dc._threshold_errors("d.test", [threshold]):
            raise InvariantBrokenError(f"{why} accepted")


def check_string_length_units() -> None:
    """`minLength`/`maxLength` count code points, never bytes or graphemes.

    The shipped limits (`note` maxLength 512, `gameVersion` maxLength 64) read
    as a character budget, and JSON Schema defines string length in Unicode code
    points. Counting UTF-8 bytes instead would reject a 512-character note of
    accented text at roughly 170 characters and quietly shrink the budget the
    schema documents; counting graphemes would let a string of combining marks
    exceed it. The astral emoji is the case that separates all three: one code
    point, two UTF-16 units, four UTF-8 bytes, one grapheme.
    """
    schema: Json = {"type": "string", "minLength": 3, "maxLength": 5}
    cases: list[tuple[str, bool, str]] = [
        ("\U0001f600\U0001f600\U0001f600", True, "three emoji are three code points"),
        ("é" * 3, True, "the NFD spelling is three code points, not one"),
        ("é" * 5, True, "the NFC spelling is five"),
        ("é" * 6, False, "six code points exceed maxLength"),
        ("e\u0301" * 6, False, "the NFD spelling of the same word exceeds it too"),
        ("ab", False, "two code points are under minLength"),
    ]
    for value, ok, why in cases:
        errs = dc._schema_validate(value, schema)
        if ok and errs:
            raise InvariantBrokenError(f"length limits rejected {value!r}: {why}: {errs}")
        if not ok and not errs:
            raise InvariantBrokenError(f"length limits accepted {value!r}: {why}")


def check_record_references() -> int:
    """A field naming another record holds a record ID, and it is bounded.

    `causeEventIds`, `evidenceIds`, and `replaces` are the only cross-record
    references in the evidence stream, and an operator follows them to read the
    cause behind a finding or the record behind a purge. A bare string there
    resolves to nothing and reads as a broken link; an unbounded array lets one
    record's size be set by whatever wrote it, on the append-only stream the
    rest of the schema bounds for exactly that reason.
    """
    schema = evidence_schema()
    records = sample_records()
    good_id = "9f2c1a3d-4e5b-4c6d-8e7f-0a1b2c3d4e5f"
    checks = 0
    for rec_type, field, bound in (
        ("finding", "causeEventIds", 32),
        ("cause", "causeEventIds", 32),
        ("audit", "evidenceIds", 64),
    ):
        record = records[rec_type]
        for bad, why in (
            ("not-a-record-id", "a bare string, not a record ID"),
            (good_id.upper(), "an upper-case record ID"),
            (good_id[:-1], "a truncated record ID"),
        ):
            probe = {**record, field: [bad]}
            if not dc._schema_validate(probe, schema):
                raise InvariantBrokenError(f"{rec_type}.{field} accepted {why}: {bad!r}")
            checks += 1
        if dc._schema_validate({**record, field: []}, schema):
            raise InvariantBrokenError(f"{rec_type}.{field}: empty reference list rejected")
        if dc._schema_validate({**record, field: [good_id] * bound}, schema):
            raise InvariantBrokenError(f"{rec_type}.{field}: {bound} references rejected")
        if not dc._schema_validate({**record, field: [good_id] * (bound + 1)}, schema):
            raise InvariantBrokenError(f"{rec_type}.{field}: {bound + 1} references accepted")
        checks += 3
    tombstone = records["tombstone"]
    for bad in ("not-a-record-id", good_id.upper(), good_id[:-1]):
        if not dc._schema_validate({**tombstone, "replaces": bad}, schema):
            raise InvariantBrokenError(f"tombstone.replaces accepted {bad!r}")
        checks += 1
    return checks


def check_bool_is_not_a_number() -> None:
    """A boolean never satisfies a numeric `const` or `enum`.

    Python compares `True == 1` and `False == 0`, so a plain `==` lets a record
    declaring `"schemaVersion": true` pass `{"const": 1}` and let a `1` pass
    `{"enum": [true]}`. JSON keeps booleans and numbers apart, and the version
    field is where a false match would be least visible.
    """
    cases: list[tuple[Json, Json, bool]] = [
        (1, {"const": 1}, True),
        (1.0, {"const": 1}, True),
        (True, {"const": 1}, False),
        (False, {"const": 0}, False),
        (0, {"const": False}, False),
        (1, {"enum": [True, False]}, False),
        (0, {"enum": [True, False]}, False),
        (True, {"enum": [0, 1]}, False),
        (1, {"enum": [0, 1]}, True),
        (True, {"enum": [True, False]}, True),
    ]
    for instance, schema, ok in cases:
        errs = dc._schema_validate(instance, schema)
        if ok and errs:
            raise InvariantBrokenError(
                f"{instance!r} against {schema}: valid value rejected: {errs}"
            )
        if not ok and not errs:
            raise InvariantBrokenError(f"{instance!r} against {schema}: boolean matched a number")


def check_personal_data_values() -> int:
    """A permitted key is not a permitted value: the bags and free text close both.

    The property-name deny-list stops a detector writing `playerName`, and says
    nothing about `note`, `reason`, or `marker`, which the schema permits and
    which is exactly where an interpolated platform id lands. Each case below
    puts one identifying value under a key the schema allows and requires the
    record to be rejected; the positive controls are the other half, because a
    deny-list broad enough to reject every string is an outage, not a control,
    and only a measurement, a version, a mod name, and a segment label surviving
    shows the list is a list and not a rejection of all free text.
    """
    schema = evidence_schema()
    records = sample_records()
    finding = records["finding"]
    cause = records["cause"]
    recon = records["reconciliation"]
    audit = records["audit"]
    leaks = [
        (
            "finding.context, a SteamID2 under a neutral key",
            {**finding, "context": {"note": "STEAM_0:1:4242424242"}},
        ),
        ("finding.context, a SteamID64", {**finding, "context": {"note": "76561198000000000"}}),
        ("finding.context, an XUID", {**finding, "context": {"note": "25354123456789012"}}),
        ("finding.context, a network address", {**finding, "context": {"origin": "203.0.113.7"}}),
        ("finding.context, a MAC address", {**finding, "context": {"note": "02:1b:44:11:3a:b7"}}),
        (
            "finding.context, a contact address",
            {**finding, "context": {"note": "a.player@example.com"}},
        ),
        ("finding.actual", {**finding, "actual": {"peer": "STEAM_1:0:98765432"}}),
        ("finding.expected", {**finding, "expected": {"peer": "STEAM_0:1:1"}}),
        ("finding.observations", {**finding, "observations": [{"peer": "STEAM_0:1:2"}]}),
        ("finding.suppressedReason", {**finding, "suppressedReason": "matched STEAM_0:1:5555"}),
        ("cause.modIdentity", {**cause, "modIdentity": "STEAM_0:1:3"}),
        ("cause.itemId", {**cause, "itemId": "203.0.113.9"}),
        ("reconciliation.marker", {**recon, "marker": "peer 76561198000000000"}),
        ("reconciliation.replayedFrom", {**recon, "replayedFrom": {"src": "10.0.0.5"}}),
        ("reconciliation.deltaItems", {**recon, "deltaItems": [{"src": "STEAM_0:1:8"}]}),
        ("audit.reason", {**audit, "reason": "cleared for 76561198000000000"}),
        ("audit.actor", {**audit, "actor": "op@203.0.113.7"}),
    ]
    accepted = [
        ("the shipped records", [finding, cause, recon, audit, records["health"]]),
        (
            "the sample's own context",
            [{**finding, "context": {"vehicle": "none", "stance": "crouch", "admin": False}}],
        ),
        (
            "measurements, which are numbers and never inspected",
            [{**finding, "context": {"dx": 4.1, "budget": 2.0, "n": 0}}],
        ),
        ("a detector version", [{**finding, "detectorVersion": "0.1.0"}]),
        (
            "a mod identity and an item id",
            [{**cause, "modIdentity": "SomeMod", "itemId": "resourceWood"}],
        ),
        ("a segment marker", [{**recon, "marker": "reconcile-7"}]),
        (
            "an operator's own words",
            [{**audit, "actor": "operator", "reason": "legal-context false positive under review"}],
        ),
        (
            "a nanosecond instant, digits and all",
            [{**finding, "context": {"t": "1758000000000000000"}}],
        ),
    ]
    checks = 0
    for what, instance in leaks:
        if not dc._schema_validate(instance, schema):
            raise InvariantBrokenError(f"{what} was accepted: {instance}")
        checks += 1
    for what, instances in accepted:
        for instance in instances:
            errs = dc._schema_validate(instance, schema)
            if errs:
                raise InvariantBrokenError(f"the value deny-list rejected {what}: {errs}")
        checks += 1
    return checks


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_fuzz_args(ap, default_iterations=1500)
    args = fuzz_args(ap)
    rng = random.Random(args.seed)  # noqa: S311 - seeded corpus fuzzing, not a secret
    mut = Mutator(rng)

    try:
        pairs = load_pairs()
        denylist_checks = check_personal_data_denylist()
        stats = {"runs": 0, "sensitivity": 0, "rejected": 0}
        for _ in range(args.iterations):
            name, schema, instances = rng.choice(pairs)
            instance = rng.choice(instances)
            mutant = mut.mutate(mut.mutate(instance))
            try:
                errs = check_totality(schema, mutant)
            except InvariantBrokenError as exc:
                print(f"fuzz-schema-validate: FAIL target1 ({name}): {exc}", file=sys.stderr)
                print("input:", json.dumps(mutant)[:400], file=sys.stderr)
                return 1
            stats["runs"] += 1
            if errs:
                stats["rejected"] += 1
            if check_sensitivity(rng, name, schema, instance):
                stats["sensitivity"] += 1

        check_deep_nesting()
        check_datetime_format()
        check_non_finite_numbers()
        check_threshold_gate()
        check_string_length_units()
        check_bool_is_not_a_number()
        check_evidence_bags_beyond_finding()
        value_deny_checks = check_personal_data_values()
        reference_checks = check_record_references()
        open_bag_checks = check_open_bag_walk()
    except InvariantBrokenError as exc:
        print(f"fuzz-schema-validate: FAIL: {exc}", file=sys.stderr)
        return 1

    print(
        f"fuzz-schema-validate: ok seed={args.seed} iterations={args.iterations} "
        f"validator_runs={stats['runs']} rejected_mutants={stats['rejected']} "
        f"sensitivity_checks={stats['sensitivity']} denylist_checks={denylist_checks} "
        f"value_denylist_checks={value_deny_checks} "
        f"id_array_probe=ok reference_checks={reference_checks} deep_probe=ok "
        f"open_bag_checks={open_bag_checks} "
        f"datetime_probe=ok non_finite_probe=ok threshold_gate_probe=ok "
        f"length_units_probe=ok bool_vs_number_probe=ok"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
