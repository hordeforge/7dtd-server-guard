# tools

- `detector_spec.yaml`: canonical detector specification (spec v1), single source of truth
  for all 41 detectors: input authority and role, algorithm sketch, state, threshold keys,
  contexts, fixtures. Edit this, never the generated files.
- `render_detectors.py`: renders docs/DETECTORS.md tables and
  config/detector-config-manifest.json from the spec (`make detectors`).
- `evidence_check.py`: verifies evidence hash chains (canonical serialization, genesis,
  intra-segment continuity, cross-segment links, tamper/truncation, a record appended
  twice) with negative self-tests; the doccheck gate runs it on the sample, and
  `make verify-evidence DIR=...`
  targets operator evidence dirs. A tampered last record is not detectable until the next
  record is appended, which is inherent to an append-only chain and is stated in SCHEMAS.md.
  A repeated `eventId` is reported from a bounded window of recent ids, so a retry or a
  crash-replayed append is visible instead of reading as two findings for one event.
- `evidence_export.py`: archives an evidence directory and proves the archive is
  restorable. The chain is verified before the copy and the copies are re-verified
  against a per-file SHA-256 manifest; a chain error, a zero-byte segment, or a copy
  mismatch aborts instead of recording a backup. `make export-evidence DIR=... OUT=...`
  archives, `make verify-archive ARCHIVE=...` re-verifies an existing archive (the
  restore drill in docs/OPERATIONS.md). Secrets are never archived here: the identity map
  and HMAC key are backed up separately. Self-tests run under `make test-tools`.
- `replay_contract_check.py`: semantic contract checks over design-time replay traces;
  `make exercise` runs it on the shipped inventory stack vector.
- `doccheck.py`: docs quality gate (`make check`): em dashes, internal links, TODO checkbox
  format, detector-spec validity (including the D-07/D-15 ceiling rule), registry sync,
  config-example/schema/manifest cross-checks, JSON Schema validation of the shipped
  schema/data pairs, evidence sample chain, replay-contract vector, evidence
  personal-data deny-list, backup/restore runbook, and folder structure.
- `fuzz_evidence_check.py`, `fuzz_schema_validate.py`, `fuzz_replay_trace.py`,
  `fuzz_evidence_export.py`: seeded, deterministic structure-aware fuzzers over the evidence
  parser, the JSON Schema validator in doccheck.py, the replay-trace contract checker, and
  the archive verifier (`make test-tools`; `make fuzz FUZZ=<harness> ITERATIONS=N SEED=S` runs a
  single harness from the Makefile's FUZZERS list at a short run). Temporary segments go under
  `.scratch/`, never the system temp dir.
- `fuzz_common.py`: the mutation engine all three fuzzers share, so their mutation policies
  cannot drift apart. Not an entry point.
- `guard_python.py`: fails the build unless the running interpreter is exactly the
  version in `.python-version`. Runs first in `make check`, `make exercise`,
  `make test-tools`, and `make fuzz`.
- `surface_inventory/`: Phase 1 Mono.Cecil metadata probe emitting hook manifest v1
  (SCHEMAS.md). Planned; only the README contract exists, no code yet.
- `fixtures/`: versioned synthetic traces (`traces/`), the labeled false-positive regression
  corpus (`regression/`), and seeded generators/mutation tools (`generators/`) for
  TEST_PLAN.md layers 4 and 7. The inventory stack design vector exists under `traces/`
  and is exercised by `make exercise`; the full corpus and replay harness remain Phase 4
  work, as do `regression/` (Phase 7/9) and `generators/`.

## Command-line contract

Every tool here is an entry point, so all of them follow the same rules:

- Exit 0 when the check passed, 1 when it failed, 2 for a usage error (an unknown
  flag, a missing argument, a path that does not exist). `make` targets that only
  forward arguments exit 2 with the same meaning.
- A clean run prints its one-line summary to stdout. A run that found something
  prints the report to stderr and leaves stdout empty, so `tool > report.txt`
  records the verdict and the diagnostics stay on the terminal.
- `--help` documents every flag, including the fuzzer `--iterations` and `--seed`
  defaults, and each tool's module docstring carries its exit codes and the exact
  command to replay a reported fuzz failure.
