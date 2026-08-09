# tools

- `detector_spec.yaml`: canonical detector specification (spec v1), single source of truth
  for all 41 detectors: input authority and role, algorithm sketch, state, threshold keys,
  contexts, fixtures. Edit this, never the generated files.
- `render_detectors.py`: renders docs/DETECTORS.md tables and
  config/detector-config-manifest.json from the spec (`make detectors`).
- `evidence_check.py`: verifies evidence hash chains (canonical serialization, genesis,
  cross-segment links, tamper/truncation) with negative self-tests; the doccheck gate runs
  it on the sample, and `make verify-evidence DIR=...` targets operator evidence dirs.
- `doccheck.py`: docs quality gate (`make check`): em dashes, internal links, TODO checkbox
  format, detector-spec validity (including the D-07 ceiling rule), registry sync, and
  config-example/schema/manifest cross-checks.
- `surface_inventory/`: Phase 1 Mono.Cecil metadata probe emitting hook manifest v1
  (SCHEMAS.md). Planned; does not exist yet.
- `fixtures/`: versioned synthetic traces (`traces/`), the labeled false-positive regression
  corpus (`regression/`), and seeded generators/mutation tools (`generators/`) for
  TEST_PLAN.md layers 4 and 7. Empty until Phase 4.
