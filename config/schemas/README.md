# config/schemas

Machine forms of the data contracts in [docs/SCHEMAS.md](../../docs/SCHEMAS.md)
(JSON Schema draft-07; the doc is canonical, these files are the machine form and are
validated by `make check`):

- `config.v1.schema.json`: strict runtime config contract. Unknown keys and out-of-range
  values are rejected; `config/server-guard.example.json` is validated against it.
- `config-manifest.v1.schema.json`: per-detector config manifest contract; the generated
  `config/detector-config-manifest.json` is validated against it.
- `evidence.v1.schema.json`: evidence stream records (finding, cause, reconciliation,
  health, audit, tombstone) with field bounds; every line of the sample JSONL below is
  validated against it.
- `evidence.v1.sample.jsonl`: one record per type; a test vector for the EvidenceStore and
  the replay harness (TEST_PLAN.md Layer 4).
- `replay-trace.v1.schema.json`: deterministic synthetic replay inputs, authoritative
  decision state, expectations, and bounded-work declarations. Evidence records are output,
  not replay input.

Edit the schemas and the SCHEMAS.md table in the same change; doccheck enforces the
cross-references.
