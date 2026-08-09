# 7dtd-server-guard

# Docs quality gate: run before opening a docs change. Checks em dashes, internal
# links, TODO checkbox format, detector-registry coverage, and config example vs schema.
.PHONY: check ci detectors help

check:
	python3 tools/doccheck.py

# Regenerate the detector registry tables and the per-detector config manifest
# from tools/detector_spec.yaml (the single source of truth).
detectors:
	python3 tools/render_detectors.py
	python3 tools/render_detectors.py --manifest

# CI entry point: docs gate now; build + test layers 1-4 are added in Phase 2
# (TODO.md). CI must run layers 1-4 on every change per TEST_PLAN.md.
ci: check

help:
	@echo "Targets:"
	@echo "  make check   run the docs quality gate (tools/doccheck.py)"
	@echo "Build targets (net48 solution, tests) are added in Phase 2 (TODO.md)."
