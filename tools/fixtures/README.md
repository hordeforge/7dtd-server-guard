# fixtures

Planned home for test fixtures, split by purpose (each with its own README):

- `traces/`: versioned synthetic replay inputs (TEST_PLAN.md Layer 4), conforming to the
  replay-trace v1 schema; each carries the hook-manifest hash of the build that recorded it;
  a mismatch skips and reports.
- `regression/`: labeled false-positive and detector-bug fixtures from the labeling
  methodology (Layer 7), de-identified, indefinite retention.
- `generators/`: seeded trace generators and mutation tools (Layer 4).

The inventory stack design vector exists now and is exercised by `make exercise`; the full
corpus and replay harness remain Phase 4 work. The doccheck gate verifies these directories.
