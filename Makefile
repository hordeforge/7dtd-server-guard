# 7dtd-server-guard

# Docs quality gate: run before opening a docs change. Checks em dashes, internal
# links, TODO checkbox format, detector spec + ceiling rule, registry sync, JSON
# Schemas, config/schema cross-references, evidence chain, replay contract.
.PHONY: setup check ci lint detectors exercise test-tools self-test fuzz verify-config verify-evidence export-evidence verify-archive guard-python help

# Fuzzer harness names addressable by `make fuzz FUZZ=<name>`, in the order
# `test-tools` runs them. Every harness tools/fuzz_*.py must appear here, or the
# short-run loop cannot reproduce a seed the full run reported.
FUZZERS := evidence_check schema_validate replay_trace evidence_export detector_spec

# Tools carrying negative self-tests, addressable by `make self-test TOOL=<name>`.
# This list is the registry: `make test-tools` runs every entry, so adding a
# self-test here is enough to put it in the CI run.
SELF_TESTS := evidence_check evidence_export config_check
empty :=
space := $(empty) $(empty)
# Short-run defaults for the edit-test loop; the full budgets live in each
# harness and are what `make test-tools` (and CI) runs. 24301 is 0x5EED, the
# harnesses' own default seed, in decimal because make passes it unparsed.
ITERATIONS ?= 200
SEED ?= 24301

# uv is the only Python toolchain here: it resolves the locked dependency set and
# the interpreter pinned in .python-version, so a bare `make check` on a fresh
# clone runs the same versions CI does. --frozen fails instead of silently
# re-resolving when uv.lock is stale. The uv release itself is pinned by
# required-version in pyproject.toml, so the resolver that reads uv.lock is the
# same one CI runs.
UV := uv run --frozen

# Every recipe runs with a fixed zone and hash seed, so a local gate and the CI
# gate of the same commit agree: a timestamp or an unordered set iteration
# cannot make one host's report differ from another's. CI sets the same three
# variables in ci.yml; LC_ALL stays CI-only because it exists on the runner image
# and may not on a developer host, while every tool here reads and writes UTF-8
# explicitly instead of through the locale.
export TZ := UTC
export PYTHONHASHSEED := 0

# The pinned version in .python-version is the single source of truth for the
# interpreter toolchain: uv installs exactly it, and the guard fails unless the
# running interpreter is that exact version, before any tool runs.
guard-python:
	@$(UV) python tools/guard_python.py

# One-time bootstrap on a fresh clone: materialize .venv from uv.lock, including
# the dev group (black, ruff, mypy). Nothing is installed globally.
setup:
	@command -v uv >/dev/null 2>&1 || { echo "setup: uv not found on PATH." >&2; echo "setup: install uv (https://docs.astral.sh/uv/); the exact required release is" >&2; echo "setup: required-version in pyproject.toml, and uv refuses to run against any other." >&2; exit 2; }
	uv sync --frozen

check: guard-python
	$(UV) python tools/doccheck.py

# Format, lint, and type gates. The targets are the repository root, not
# tools/: a path-scoped target silently exempts any Python added outside it,
# and the .venv, bin/, and obj/ trees are already gitignored.
lint: guard-python
	$(UV) black --check .
	$(UV) ruff check .
	$(UV) mypy .

# Regenerate the detector registry tables and the per-detector config manifest
# from tools/detector_spec.yaml (the single source of truth).
detectors: guard-python
	$(UV) python tools/render_detectors.py
	$(UV) python tools/render_detectors.py --manifest

# Exercise the pre-implementation replay contract and representative vertical-slice vector.
exercise: guard-python
	$(UV) python tools/replay_contract_check.py

# Tests for the shipped Python tooling: evidence hash-chain and archive
# self-tests plus seeded structure-aware fuzzers over the evidence parser, the
# archive verifier and exporter, the JSON Schema validator, the replay-trace
# contract checker, and the detector spec consumers.
test-tools: guard-python
	@set -e; for tool in $(SELF_TESTS); do \
	  echo "$(UV) python tools/$$tool.py --self-test"; \
	  $(UV) python tools/$$tool.py --self-test; \
	done
	$(UV) python tools/fuzz_evidence_check.py
	$(UV) python tools/fuzz_schema_validate.py
	$(UV) python tools/fuzz_replay_trace.py
	$(UV) python tools/fuzz_evidence_export.py
	$(UV) python tools/fuzz_detector_spec.py

# One tool's negative self-tests: the loop while editing that tool, since
# `make fuzz FUZZ=<name>` covers only its fuzzer, not its self-tests.
# Usage: make self-test TOOL=evidence_check
self-test: guard-python
	@test -n "$(TOOL)" || { echo "usage: make self-test TOOL=<$(subst $(space),|,$(SELF_TESTS))>" >&2; exit 2; }
	@case " $(SELF_TESTS) " in \
	  *" $(TOOL) "*) ;; \
	  *) echo "unknown self-test '$(TOOL)'; expected one of: $(SELF_TESTS)" >&2; exit 2 ;; \
	esac
	$(UV) python tools/$(TOOL).py --self-test

# One fuzzer at a short iteration count: the loop for a single harness, and the
# way to re-run a seed a failure reported. A failing seed replays exactly.
# Usage: make fuzz FUZZ=replay_trace [ITERATIONS=200] [SEED=24301]
fuzz: guard-python
	@test -n "$(FUZZ)" || { echo "usage: make fuzz FUZZ=<$(subst $(space),|,$(FUZZERS))> [ITERATIONS=N] [SEED=S]" >&2; exit 2; }
	@case " $(FUZZERS) " in \
	  *" $(FUZZ) "*) ;; \
	  *) echo "unknown fuzzer '$(FUZZ)'; expected one of: $(FUZZERS)" >&2; exit 2 ;; \
	esac
	$(UV) python tools/fuzz_$(FUZZ).py --iterations "$(ITERATIONS)" --seed "$(SEED)"

# CI entry point: everything CI runs, runnable locally as one step.
# C# build + test layers 1-4 are added here in Phase 2 (TODO.md).
ci: lint check exercise test-tools

# Validate an operator's config file before it is deployed: schema, detector
# registry, per-detector manifest thresholds, and the env vars an enabled webhook
# or dashboard names. --skip-env checks the file alone, with no environment.
# Usage: make verify-config FILE=/path/to/server-guard.json [SKIP_ENV=1]
verify-config:
	@test -n "$(FILE)" || { echo "usage: make verify-config FILE=/path/to/server-guard.json [SKIP_ENV=1]" >&2; exit 2; }
	$(UV) python tools/config_check.py --config "$(FILE)" $(if $(SKIP_ENV),--skip-env,)

# Verify an evidence directory's hash chain (append-only segments).
# Usage: make verify-evidence DIR=/path/to/evidence
verify-evidence:
	@test -n "$(DIR)" || { echo "usage: make verify-evidence DIR=/path/to/evidence" >&2; exit 2; }
	$(UV) python tools/evidence_check.py --dir "$(DIR)"

# Archive an evidence directory: the chain is verified before and after the copy,
# and a manifest of per-file sha256 is written beside it.
# Usage: make export-evidence DIR=/path/to/evidence OUT=/path/to/archive-root
export-evidence:
	@test -n "$(DIR)" -a -n "$(OUT)" || { echo "usage: make export-evidence DIR=<evidence-dir> OUT=<archive-root>"; exit 2; }
	$(UV) python tools/evidence_export.py --dir "$(DIR)" --out "$(OUT)"

# Prove an archive is intact and restorable (the restore drill; also catches silent
# backup corruption long before a real restore needs it).
# Usage: make verify-archive ARCHIVE=/path/to/archive
verify-archive:
	@test -n "$(ARCHIVE)" || { echo "usage: make verify-archive ARCHIVE=/path/to/archive"; exit 2; }
	$(UV) python tools/evidence_export.py --archive $(ARCHIVE)

help:
	@echo "Targets:"
	@echo "  make setup           materialize .venv from uv.lock (uv sync --frozen)"
	@echo "  make check           run the docs quality gate (tools/doccheck.py)"
	@echo "  make lint            black, ruff, and mypy over the whole repository"
	@echo "  make detectors       regenerate registry tables + config manifest from the spec"
	@echo "  make exercise        validate the design-time inventory stack replay contract"
	@echo "  make test-tools      self-tests + fuzzers for the Python tooling"
	@echo "  make self-test TOOL=<name>   one tool's negative self-tests (evidence_check, evidence_export, config_check)"
	@echo "  make fuzz FUZZ=<name>    one fuzzer, short run (evidence_check, schema_validate, replay_trace, evidence_export, detector_spec)"
	@echo "  make ci              everything CI runs locally in one step (lint + check + exercise + test-tools)"
	@echo "  make guard-python    interpreter pin gate every other target depends on"
	@echo "  make verify-config FILE=<file> [SKIP_ENV=1]   validate a config file before deploying it"
	@echo "  make verify-evidence DIR=<dir>   verify an evidence hash chain"
	@echo "  make export-evidence DIR=<dir> OUT=<root>   verify + archive an evidence dir"
	@echo "  make verify-archive ARCHIVE=<dir>   re-verify an archive against its manifest"
	@echo "Python version: .python-version, enforced exactly (uv installs it; local builds refuse any other)."
	@echo "uv version: required-version in pyproject.toml, enforced by uv itself and pinned to the same release in CI."
	@echo "Build targets (net48 solution, tests) are added in Phase 2 (TODO.md)."
