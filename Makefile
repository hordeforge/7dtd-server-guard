# 7dtd-server-guard

# Docs quality gate: run before opening a docs change. Checks em dashes, internal
# links, TODO checkbox format, detector-registry coverage, and config example vs schema.
.PHONY: setup check ci detectors exercise test-tools verify-evidence help

# Python tools run in the project-local venv created by `make setup`; fall back
# to the system python3 when no venv exists.
PY := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

# One-time bootstrap on a fresh clone: create .venv and install the declared
# dependencies (requirements.txt) into it. Nothing is installed globally.
setup:
	python3 -m venv .venv
	.venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt

check:
	$(PY) tools/doccheck.py

# Regenerate the detector registry tables and the per-detector config manifest
# from tools/detector_spec.yaml (the single source of truth).
detectors:
	$(PY) tools/render_detectors.py
	$(PY) tools/render_detectors.py --manifest

# Exercise the pre-implementation replay contract and representative vertical-slice vector.
exercise:
	$(PY) tools/replay_contract_check.py

# Tests for the shipped Python tooling: evidence hash-chain negative self-tests
# plus the seeded structure-aware fuzzer over the evidence parser.
test-tools:
	$(PY) tools/evidence_check.py --self-test
	$(PY) tools/fuzz_evidence_check.py

# CI entry point: everything CI runs, runnable locally as one step.
# C# build + test layers 1-4 are added here in Phase 2 (TODO.md).
ci: check test-tools

# Verify an evidence directory's hash chain (append-only segments).
# Usage: make verify-evidence DIR=/path/to/evidence
verify-evidence:
	@test -n "$(DIR)" || { echo "usage: make verify-evidence DIR=/path/to/evidence"; exit 2; }
	$(PY) tools/evidence_check.py --dir $(DIR)

help:
	@echo "Targets:"
	@echo "  make setup           bootstrap a project-local .venv and install requirements.txt"
	@echo "  make check           run the docs quality gate (tools/doccheck.py)"
	@echo "  make detectors       regenerate registry tables + config manifest from the spec"
	@echo "  make exercise        validate the design-time inventory stack replay contract"
	@echo "  make test-tools      self-tests + fuzzer for the Python tooling"
	@echo "  make ci              everything CI runs locally in one step (check + test-tools)"
	@echo "  make verify-evidence DIR=<dir>   verify an evidence hash chain"
	@echo "Build targets (net48 solution, tests) are added in Phase 2 (TODO.md)."
