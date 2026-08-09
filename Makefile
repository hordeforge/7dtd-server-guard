# 7dtd-server-guard

# Docs quality gate: run before opening a docs change. Checks em dashes, internal
# links, TODO checkbox format, detector-registry coverage, and config example vs schema.
.PHONY: check help

check:
	python3 tools/doccheck.py

help:
	@echo "Targets:"
	@echo "  make check   run the docs quality gate (tools/doccheck.py)"
	@echo "Build targets (net48 solution, tests) are added in Phase 2 (TODO.md)."
