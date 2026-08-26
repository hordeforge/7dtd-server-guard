# 7dtd-server-guard

# Docs quality gate: run before opening a docs change. Checks em dashes, internal
# links, TODO checkbox format, detector spec + ceiling rule, registry sync, JSON
# Schemas, config/schema cross-references, evidence chain, replay contract.
.PHONY: setup check ci lint detectors exercise test-tools verify-evidence guard-python help

# uv is the only Python toolchain here: it resolves the locked dependency set and
# the interpreter pinned in .python-version, so a bare `make check` on a fresh
# clone runs the same versions CI does. --frozen fails instead of silently
# re-resolving when uv.lock is stale.
UV := uv run --frozen

# The pinned minor in .python-version is the single source of truth for the
# interpreter toolchain: uv installs exactly it, and the guard enforces it as a
# floor before any tool runs.
guard-python:
	@$(UV) python tools/guard_python.py

# One-time bootstrap on a fresh clone: materialize .venv from uv.lock, including
# the dev group (black, ruff, mypy). Nothing is installed globally.
setup:
	uv sync --frozen

check: guard-python
	$(UV) python tools/doccheck.py

# Format, lint, and type gates for the shipped Python tooling.
lint:
	$(UV) black --check tools
	$(UV) ruff check tools
	$(UV) mypy tools

# Regenerate the detector registry tables and the per-detector config manifest
# from tools/detector_spec.yaml (the single source of truth).
detectors:
	$(UV) python tools/render_detectors.py
	$(UV) python tools/render_detectors.py --manifest

# Exercise the pre-implementation replay contract and representative vertical-slice vector.
exercise: guard-python
	$(UV) python tools/replay_contract_check.py

# Tests for the shipped Python tooling: evidence hash-chain negative self-tests
# plus seeded structure-aware fuzzers over the evidence parser, the JSON Schema
# validator, and the replay-trace contract checker.
test-tools: guard-python
	$(UV) python tools/evidence_check.py --self-test
	$(UV) python tools/fuzz_evidence_check.py
	$(UV) python tools/fuzz_schema_validate.py
	$(UV) python tools/fuzz_replay_trace.py

# CI entry point: everything CI runs, runnable locally as one step.
# C# build + test layers 1-4 are added here in Phase 2 (TODO.md).
ci: lint check test-tools

# Verify an evidence directory's hash chain (append-only segments).
# Usage: make verify-evidence DIR=/path/to/evidence
verify-evidence:
	@test -n "$(DIR)" || { echo "usage: make verify-evidence DIR=/path/to/evidence"; exit 2; }
	$(UV) python tools/evidence_check.py --dir $(DIR)

help:
	@echo "Targets:"
	@echo "  make setup           materialize .venv from uv.lock (uv sync --frozen)"
	@echo "  make check           run the docs quality gate (tools/doccheck.py)"
	@echo "  make lint            black, ruff, and mypy over tools/"
	@echo "  make detectors       regenerate registry tables + config manifest from the spec"
	@echo "  make exercise        validate the design-time inventory stack replay contract"
	@echo "  make test-tools      self-tests + fuzzers for the Python tooling"
	@echo "  make ci              everything CI runs locally in one step (lint + check + test-tools)"
	@echo "  make verify-evidence DIR=<dir>   verify an evidence hash chain"
	@echo "Python floor: .python-version (uv installs exactly it; local builds enforce it)."
	@echo "Build targets (net48 solution, tests) are added in Phase 2 (TODO.md)."
