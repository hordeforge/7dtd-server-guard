# fixtures

Planned home for test fixtures, split by purpose (each with its own README):

- `traces/`: versioned synthetic replay traces (TEST_PLAN.md Layer 4), conforming to the
  evidence v1 schema; each carries the hook-manifest hash of the build that recorded it;
  a mismatch skips and reports.
- `regression/`: labeled false-positive and detector-bug fixtures from the labeling
  methodology (Layer 7), de-identified, indefinite retention.
- `generators/`: seeded trace generators and mutation tools (Layer 4).

Empty until Phase 4. The doccheck gate verifies these directories exist.
