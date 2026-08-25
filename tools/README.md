# tools

- `detector_spec.yaml`: canonical detector specification (spec v1), single source of truth
  for all 41 detectors: input authority and role, algorithm sketch, state, threshold keys,
  contexts, fixtures. Edit this, never the generated files.
- `render_detectors.py`: renders docs/DETECTORS.md tables and
  config/detector-config-manifest.json from the spec (`make detectors`).
- `evidence_check.py`: verifies evidence hash chains (canonical serialization, genesis,
  cross-segment links, tamper/truncation) with negative self-tests; the doccheck gate runs
  it on the sample, and `make verify-evidence DIR=...` targets operator evidence dirs.
- `replay_contract_check.py`: semantic contract checks over design-time replay traces;
  `make exercise` runs it on the shipped inventory stack vector.
- `doccheck.py`: docs quality gate (`make check`): em dashes, internal links, TODO checkbox
  format, detector-spec validity (including the D-07 ceiling rule), registry sync,
  config-example/schema/manifest cross-checks, JSON Schema validation of the shipped
  schema/data pairs, evidence sample chain, replay-contract vector, and folder structure.
- `fuzz_evidence_check.py`, `fuzz_schema_validate.py`, `fuzz_replay_trace.py`: seeded,
  deterministic structure-aware fuzzers over the evidence parser, the JSON Schema validator
  in doccheck.py, and the replay-trace contract checker (`make test-tools`).
- `surface_inventory/`: Phase 1 Mono.Cecil metadata probe emitting hook manifest v1
  (SCHEMAS.md). Planned; does not exist yet.
- `fixtures/`: versioned synthetic traces (`traces/`), the labeled false-positive regression
  corpus (`regression/`), and seeded generators/mutation tools (`generators/`) for
  TEST_PLAN.md layers 4 and 7. The inventory stack design vector exists under `traces/`
  and is exercised by `make exercise`; the full corpus and replay harness remain Phase 4
  work, as do `regression/` (Phase 7/9) and `generators/`.
