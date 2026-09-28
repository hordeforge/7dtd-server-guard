"""Validate an operator's runtime config file before it is deployed to a server.

`config/server-guard.example.json` is the shipped contract, and the doccheck gate
keeps it honest. An operator's own file (`config/server-guard.local.json`, deployed
as `server-guard.json` in the mod's data root) is edited by hand and gated by
nothing: a misspelled detector id, an out-of-range threshold, or a webhook left
enabled with its env var unset starts a server that looks configured and is not.
This is the same validation the strict Phase 2 loader is specified from
(SCHEMAS.md -> Config schema), run against a real file before it ships:

  schema     every key, type, enum, and range in config/schemas/config.v1.schema.json;
             unknown keys are rejected, exactly as the loader rejects them
  registry   every `modes` key is a registered detector id, so a typo cannot leave
             a detector silently at its `observe` default
  manifest   every `thresholds` key is declared for that detector in
             config/detector-config-manifest.json, with the declared type and range
  secrets    a sink or the dashboard that is `enabled` with its named environment
             variable unset is an error, not a silent no-op
  hash       the SHA-256 of the effective (defaulted) config, the digest written into
             evidence records, the health report, and the hook manifest, so an
             operator can confirm which config a finding was produced under

The file is the only configuration source (SCHEMAS.md -> Config schema): the two
secret env vars it *names* are the only environment input, and their values are
never read, printed, or written here. `--show-effective` prints the effective
config, which contains env var names, never secret values.

Usage:
  uv run python tools/config_check.py --config config/server-guard.local.json
  uv run python tools/config_check.py --config <file> --show-effective
  uv run python tools/config_check.py --self-test

Exit codes: 0 the config is valid, 1 it is not, 2 usage error.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import shutil
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import doccheck as dc

# Config JSON, loaded from an operator's file or a self-test fixture: shape is
# what the validator checks, so it cannot be narrowed statically.
Json = Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "config" / "schemas" / "config.v1.schema.json"
EXAMPLE_PATH = ROOT / "config" / "server-guard.example.json"
# Depth cap for the defaults walk; the shipped config schema nests four levels,
# and a self-referential `$ref` must not turn a defaults pass into a hang.
MAX_DEFAULTS_DEPTH = 20

# Config sections whose secret value comes from an environment variable the config
# only names. Enabling the consumer without the variable means the feature is on
# in the config and off at runtime, which is the failure this check exists for.
SECRET_ENV_SECTIONS = (("webhook", "urlEnv"), ("dashboard", "secretEnv"))
# The key that turns a section on in both of them.
ENABLED_KEY = "enabled"


def effective_config(config: Json, schema: Json, depth: int = 0) -> Json:
    """The config with every declared schema default filled in.

    Defaults come from the schema, not from the example file, so this is the
    config the loader builds when a key is absent. patternProperties subtrees
    (per-detector modes and thresholds) are left alone: their defaults are the
    spec's, applied by the registry, not by a schema walk.
    """
    if depth > MAX_DEFAULTS_DEPTH or not isinstance(config, dict):
        return config
    out = copy.deepcopy(config)
    for key, sub in schema.get("properties", {}).items():
        if not isinstance(sub, dict) or sub.get("patternProperties"):
            continue
        if key not in out:
            if "default" in sub:
                out[key] = copy.deepcopy(sub["default"])
            elif sub.get("properties"):
                # An absent section is not absent from the effective config: its own
                # keys carry defaults, the same ones the loader applies key by key.
                out[key] = effective_config({}, sub, depth + 1)
            continue
        if sub.get("properties"):
            out[key] = effective_config(out[key], sub, depth + 1)
    return out


def config_hash(effective: Json) -> str:
    """SHA-256 over the sorted-key JSON of the effective config (SCHEMAS.md -> Config
    schema). The same canonicalization the evidence chain uses, so a config digest
    and an evidence digest read the same way."""
    canonical = json.dumps(effective, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _registry_ids() -> set[str]:
    return dc.spec_ids()


def _manifest_thresholds() -> dict[str, dict[str, Json]]:
    """Per-detector threshold entries from the generated manifest, keyed by threshold
    key. Detectors the manifest does not carry are absent, and every threshold set
    naming one is reported rather than skipped."""
    path = ROOT / "config" / "detector-config-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    entries = manifest.get("detectors")
    if not isinstance(entries, list):
        return {}
    return {
        entry["detectorId"]: dc._thresholds_by_key(entry.get("thresholds"))
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("detectorId"), str)
    }


def registry_errors(config: Json) -> list[str]:
    """Every `modes` key is a registered detector, and every `thresholds` block names
    one the manifest declares."""
    registered = _registry_ids()
    out: list[str] = []
    modes = config.get("modes", {})
    if isinstance(modes, dict):
        out.extend(
            f"modes key {did!r} is not a registered detector id; it would load as the "
            f"'observe' default and never run"
            for did in sorted(str(k) for k in modes)
            if did not in registered
        )
    thresholds = config.get("thresholds", {})
    if isinstance(thresholds, dict):
        manifest = _manifest_thresholds()
        for did in sorted(str(k) for k in thresholds):
            if did not in registered:
                out.append(f"thresholds key {did!r} is not a registered detector id")
                continue
            known = manifest.get(did, {})
            out.extend(
                f"thresholds {did}.{key} is not declared in "
                f"config/detector-config-manifest.json"
                for key in sorted(str(k) for k in thresholds[did])
                if key not in known
            )
    return out


def threshold_errors(config: Json) -> list[str]:
    """Each configured threshold value satisfies the type and range its manifest entry
    declares (SCHEMAS.md -> Per-detector config manifest)."""
    manifest = _manifest_thresholds()
    thresholds = config.get("thresholds", {})
    if not isinstance(thresholds, dict):
        return []
    out: list[str] = []
    for did, keys in thresholds.items():
        if did not in manifest or not isinstance(keys, dict):
            # registry_errors already reports an unknown detector or a malformed block.
            continue
        for key, value in keys.items():
            entry = manifest[did].get(key)
            if entry is None:
                continue
            out.extend(dc._threshold_value_errors(did, key, value, entry, "config"))
    return out


def secret_env_errors(config: Json, env: dict[str, str]) -> list[str]:
    """A section that is enabled must find its named environment variable set.

    The value is never read into the report, only its presence: an empty string
    counts as unset, because a process that exports an empty variable is the same
    misconfiguration as one that never exported it.
    """
    out: list[str] = []
    for section, env_key in SECRET_ENV_SECTIONS:
        block = config.get(section)
        if not isinstance(block, dict) or not block.get(ENABLED_KEY):
            continue
        name = block.get(env_key)
        if not isinstance(name, str) or not env.get(name):
            out.append(
                f"{section}.{ENABLED_KEY} is true but the environment variable "
                f"{name!r} is not set; {section} would stay off at runtime"
            )
    return out


def unlisted_detectors(config: Json) -> int:
    """How many registered detectors the file names no mode for. They load at the
    `observe` default, which is safe, so this is reported, not an error."""
    modes = config.get("modes", {})
    named = set(modes) if isinstance(modes, dict) else set()
    return len(_registry_ids() - named)


def check(config: Json, env: dict[str, str] | None = None, check_env: bool = True) -> list[str]:
    """Every reason this config must not be deployed, in the order an operator reads
    them: unparseable shape, schema, then the cross-file and dependent checks."""
    if not isinstance(config, dict):
        return [f"config must be a JSON object, got {type(config).__name__}"]
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    out = list(dc._schema_validate(config, schema))
    if out:
        # Every remaining check reads keys the schema may have rejected; report the
        # contract violation alone rather than a cascade of follow-on errors.
        return out
    out.extend(registry_errors(config))
    out.extend(threshold_errors(config))
    if check_env:
        out.extend(secret_env_errors(config, env if env is not None else dict(os.environ)))
    return out


def load(path: pathlib.Path) -> tuple[Json | None, str | None]:
    """A config file and its parse error, or (None, message) when it cannot be read."""
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except OSError as exc:
        return None, f"cannot read {path}: {exc}"
    except UnicodeDecodeError as exc:
        # An operator's file is hand-edited, and a Windows editor, a Latin-1
        # locale, or a legacy code page (UTF-16, a Latin-1 save) leaves bytes
        # that are not UTF-8. The file is read as UTF-8 because that is what the
        # shipped config and the loader's contract are, so the bytes are refused
        # by name here: UnicodeDecodeError is not a JSONDecodeError, and letting
        # it out aborts the pre-deploy check with a traceback that names no config
        # instead of the refusal every other unreadable file gets.
        return None, f"{path} is not valid UTF-8: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"{path} is not valid JSON: {exc}"


def _rejection_self_test(example: Json, failures: list[str]) -> None:
    """Cases a config must be refused for, each a mutation of the shipped example."""

    def expect_error(name: str, config: Json, fragment: str) -> None:
        errs = check(config)
        if not any(fragment in e for e in errs):
            failures.append(f"{name}: expected an error containing {fragment!r}, got {errs}")

    renamed = copy.deepcopy(example)
    renamed["modes"]["movement.fligth"] = renamed["modes"].pop("movement.flight")
    expect_error("misspelled detector id", renamed, "modes key 'movement.fligth'")

    out_of_range = copy.deepcopy(example)
    out_of_range["thresholds"]["movement.displacement"]["latency_window_ms"] = -1
    expect_error("out-of-range threshold", out_of_range, "outside declared range")

    undeclared = copy.deepcopy(example)
    undeclared["thresholds"]["movement.displacement"]["nope"] = 1
    expect_error("undeclared threshold key", undeclared, "not declared in")

    wrong_type = copy.deepcopy(example)
    wrong_type["thresholds"]["movement.displacement"]["max_speed_mps"] = "fast"
    expect_error("threshold of the wrong type", wrong_type, "is not a number")

    unknown_key = copy.deepcopy(example)
    unknown_key["webhok"] = {"enabled": True}
    expect_error("unknown top-level key", unknown_key, "webhok")

    schema_version = copy.deepcopy(example)
    schema_version["schemaVersion"] = 2
    expect_error("unknown schema version", schema_version, "schemaVersion")

    # A trailing newline is invisible in the file and Python's `$` matches before
    # one, so a value carrying it must still be refused here rather than approved
    # by a gate the loader's stricter reading would contradict.
    trailing_newline = copy.deepcopy(example)
    trailing_newline["identityMap"]["permissions"] = "0600\n"
    expect_error("trailing newline in a pattern-matched value", trailing_newline, "does not match")

    if check("not an object") != ["config must be a JSON object, got str"]:
        failures.append("non-object config was not reported as a shape error")


def _secret_env_self_test(example: Json, failures: list[str]) -> None:
    """An enabled sink with no env var behind it is refused; the same file with the
    variable set, or checked with the env pass skipped, is not."""

    def expect_clean(name: str, config: Json, **kwargs: Any) -> None:
        errs = check(config, **kwargs)
        if errs:
            failures.append(f"{name}: expected no error, got {errs}")

    webhook = copy.deepcopy(example)
    webhook["webhook"][ENABLED_KEY] = True
    errs = check(webhook, env={})
    if not any("SERVERGUARD_WEBHOOK_URL" in e for e in errs):
        failures.append(f"webhook enabled with no env var: expected a refusal, got {errs}")
    expect_clean("webhook enabled, env set", webhook, env={"SERVERGUARD_WEBHOOK_URL": "u"})
    expect_clean("webhook enabled, env pass skipped", webhook, env={}, check_env=False)
    expect_error_empty = check(webhook, env={"SERVERGUARD_WEBHOOK_URL": ""})
    if not expect_error_empty:
        failures.append("webhook enabled with an empty env var: expected a refusal")

    dashboard = copy.deepcopy(example)
    dashboard["dashboard"][ENABLED_KEY] = True
    errs = check(dashboard, env={})
    if not any("SERVERGUARD_DASHBOARD_SECRET" in e for e in errs):
        failures.append(f"dashboard enabled with no env var: expected a refusal, got {errs}")
    expect_clean("dashboard enabled, env set", dashboard, env={"SERVERGUARD_DASHBOARD_SECRET": "s"})

    # The variable name is the operator's to choose, so the report has to name the one
    # the file asks for: a sink pointed at an unset custom name is refused by that name.
    renamed = copy.deepcopy(webhook)
    renamed["webhook"]["urlEnv"] = "OPERATOR_WEBHOOK_URL"
    errs = check(renamed, env={"SERVERGUARD_WEBHOOK_URL": "u"})
    if not any("OPERATOR_WEBHOOK_URL" in e for e in errs):
        failures.append(f"a renamed env var was not named in the refusal: {errs}")
    expect_clean("renamed env var set", renamed, env={"OPERATOR_WEBHOOK_URL": "u"})
    undeclared = copy.deepcopy(webhook)
    undeclared["webhook"]["urlEnv"] = 42
    if not check(undeclared, env={}):
        failures.append("a non-string env var name was accepted")


def _effective_self_test(example: Json, failures: list[str]) -> None:
    """The defaults pass and the config hash it feeds."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    evidence = schema["properties"]["evidence"]["properties"]
    applied = effective_config({"schemaVersion": 1}, schema).get("evidence", {})
    if any(applied.get(k) != v.get("default") for k, v in evidence.items()):
        failures.append("effective config did not apply the schema's evidence defaults")

    effective = effective_config(example, schema)
    reordered = dict(reversed(list(example.items())))
    if config_hash(effective) != config_hash(effective_config(reordered, schema)):
        failures.append("config hash is not stable under key order")
    # A key whose value equals the declared default and a key that is absent are the
    # same effective config, so the hash a finding is stamped with does not depend on
    # how much of the template the operator kept.
    defaulted = copy.deepcopy(example)
    del defaulted["console"]
    if config_hash(effective_config(defaulted, schema)) != config_hash(effective):
        failures.append("config hash differs between an absent key and its declared default")


def _load_self_test(failures: list[str]) -> None:
    """A file the loader must refuse by name, not by raising out of the check.

    A config saved as Latin-1 (or through a Windows editor's default code page,
    or as UTF-16) is a hand-editing accident, not a corrupt deployment, and the
    operator needs the file named back. `load` returns the reason to the caller so
    the gate reports the file; a UnicodeDecodeError escaping it would print a
    traceback that names no config. The bytes below are the shipped example's
    opening with a single Latin-1 e-acute spliced in, so only the encoding is
    wrong.
    """
    scratch = ROOT / ".scratch" / "config-check-self-test"
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    try:
        latin1 = scratch / "server-guard.latin1.json"
        latin1.write_bytes(
            b'{"schemaVersion": 1, "console": {"enabled": true, "level": "caf\xe9"}}\n'
        )
        config, error = load(latin1)
        if config is not None or error is None or "not valid UTF-8" not in error:
            failures.append(f"non-UTF-8 config was not refused by name: {error!r}")
        if (config, error) != load(latin1):
            failures.append("loading the same file twice gave two different results")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def self_test() -> list[str]:
    """Negative and positive cases over the shipped example and mutations of it.

    Each case is built from the real example so the tool is exercised against the
    contract it ships with, not a hand-written fixture that can drift from it.
    """
    example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
    failures: list[str] = []
    if not isinstance(example, dict):
        return ["shipped example is not a JSON object"]
    if errs := check(example, env={}):
        failures.append(f"shipped example: expected no error, got {errs}")
    _rejection_self_test(example, failures)
    _secret_env_self_test(example, failures)
    _effective_self_test(example, failures)
    _load_self_test(failures)
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", type=pathlib.Path, help="config file to validate")
    ap.add_argument(
        "--show-effective",
        action="store_true",
        help="print the effective (defaulted) config and its hash to stdout",
    )
    ap.add_argument(
        "--skip-env",
        action="store_true",
        help="do not require the environment variables named by an enabled webhook or dashboard",
    )
    ap.add_argument("--self-test", action="store_true", help="run the self-tests and exit")
    args = ap.parse_args()

    if args.self_test:
        errs = self_test()
        print(f"config-check self-test: {len(errs)} failure(s)")
        for e in errs:
            print("  " + e)
        return 1 if errs else 0

    if args.config is None:
        ap.print_help()
        return 2

    config, error = load(args.config)
    if error is not None:
        print(f"config-check: {error}", file=sys.stderr)
        return 2

    errs = check(config, check_env=not args.skip_env)
    if errs:
        print(f"config-check: {len(errs)} issue(s) in {args.config}", file=sys.stderr)
        for e in errs:
            print("  " + e, file=sys.stderr)
        return 1

    unlisted = unlisted_detectors(config)
    note = f", {unlisted} detector(s) not named (observe default)" if unlisted else ""
    if args.show_effective:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        effective = effective_config(config, schema)
        print(json.dumps(effective, indent=2, sort_keys=True))
        print(f"config hash: {config_hash(effective)}")
    print(f"config-check: {args.config} is valid{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
