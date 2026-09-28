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
  mismatch aborts instead of recording a backup. A re-run of the same export into
  the same second converges on the archive that already exists rather than reporting
  a failed backup, and is refused when that archive holds a different evidence set.
  `make export-evidence DIR=... OUT=...`
  archives, `make verify-archive ARCHIVE=...` re-verifies an existing archive (the
  restore drill in docs/OPERATIONS.md). Secrets are never archived here: the identity map
  and HMAC key are backed up separately. Self-tests run under `make test-tools`.
- `restore_drill.py`: performs the monthly restore drill
  (`make drill-restore ARCHIVE=... WORK=... [CONFIG=...]`). It verifies the archive
  against its manifest, copies its segments and index into an empty work directory
  under their own file names, re-verifies the chain over the copy, and reads the
  oldest and newest records back out. With `--config` it also resolves
  `identityMap.path` and `hmacKey.path` and fails on a missing, zero-byte, or
  past-cycle key, so a drill cannot pass on a chain nobody can attribute. The live
  evidence directory is never written, and a non-empty work directory is refused
  rather than merged into. Self-tests run under `make test-tools`.
- `backup_status.py`: the read-only RPO check (`make backup-status ROOT=...`). It
  verifies the archives in a root newest first and reports the age of the newest one
  that verifies, measured from the manifest's `createdUtc` rather than the directory
  timestamp a copy off the server resets. A root with no archive, an archive that
  does not verify, and an archive older than the window are each reported by name, so
  a scheduler that stopped running is a non-zero exit rather than a discovery made
  during an incident. It writes nothing. Self-tests run under `make test-tools`.
- `replay_contract_check.py`: semantic contract checks over design-time replay traces;
  `make exercise` runs it on the shipped inventory stack vector.
- `config_check.py`: validates an operator's own config file the way the strict Phase 2
  loader is specified to: JSON Schema contract (unknown keys, types, enums, ranges),
  `modes` keys against the detector registry, `thresholds` keys and values against
  `config/detector-config-manifest.json`, and an enabled `webhook` or `dashboard` whose
  named environment variable is unset. `--show-effective` prints the effective (defaulted)
  config and the SHA-256 written into evidence records, the health report, and the hook
  manifest. Secret values are never read: the config names the env var, the tool checks only
  that it is set. `make verify-config FILE=...`; self-tests run under `make test-tools`.
- `sbom.py`: renders `uv.lock` as a CycloneDX 1.6 bill of materials
  (`make sbom [OUT=dist/sbom.cdx.json]`), one component per locked package with the
  sha256 the lock records, the dependency graph, and a `runtime` or `dev` scope property,
  so a scanner or auditor can read the release's inventory without running uv. The
  output is deterministic (the serial number is a UUID over the lock digest, and there is
  no timestamp), so an unchanged lock regenerates byte for byte and a diff means the
  dependency set moved. `uv.lock` records no license data, so no license is claimed: a
  wrong license is worse than a missing one. A lock entry with no hash, or a dependency
  the lock does not describe, is an error rather than a quietly omitted component. Runs
  under `make ci`; self-tests run under `make test-tools`.
- `doccheck.py`: docs quality gate (`make check`): em dashes, internal links, TODO checkbox
  format, detector-spec validity (including the D-07/D-15 ceiling rule), registry sync,
  config-example/schema/manifest cross-checks, JSON Schema validation of the shipped
  schema/data pairs, evidence sample chain, replay-contract vector, evidence
  personal-data deny-list, backup/restore runbook, and folder structure.
- `fuzz_evidence_check.py`, `fuzz_schema_validate.py`, `fuzz_replay_trace.py`,
  `fuzz_evidence_export.py`, `fuzz_detector_spec.py`: seeded, deterministic structure-aware
  fuzzers over the evidence parser, the JSON Schema validator in doccheck.py, the
  replay-trace contract checker, the archive verifier, and the detector spec
  (`detector_spec.yaml`) with both of its consumers (doccheck's spec pass and the renderers in
  render_detectors.py) (`make test-tools`; `make fuzz FUZZ=<harness> ITERATIONS=N SEED=S` runs a
  single harness from the Makefile's FUZZERS list at a short run). Temporary segments and spec
  files go under `.scratch/`, never the system temp dir.
- The Makefile's `SELF_TESTS` list is the registry of tools carrying `--self-test`
  (`evidence_check.py`, `evidence_export.py`): `make test-tools` runs every entry, and
  `make self-test TOOL=<name>` runs one alone while editing it. Adding a tool to that list
  is the only edit needed to put its self-tests in the CI run.
- `fuzz_common.py`: the mutation engine all five fuzzers share, so their mutation policies
  cannot drift apart. Not an entry point.
- `guard_python.py`: fails the build unless the running interpreter is exactly the
  version in `.python-version`. Runs first in every target that executes a tool:
  `make check`, `make lint`, `make detectors`, `make exercise`, `make test-tools`,
  `make self-test`, and `make fuzz`.
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
  flag, a missing argument, or an argument combination the tool rejects before it
  starts work, such as `--dir` with no `--out`). A path that does not exist is a
  check failure (1), not a usage error. `make` targets that only forward
  arguments exit 2 with the same meaning.
- A clean run prints its one-line summary to stdout. A run that found something
  prints the report to stderr and leaves stdout empty, so `tool > report.txt`
  records the verdict and the diagnostics stay on the terminal.
- `--help` documents every flag, including the fuzzer `--iterations` and `--seed`
  defaults, and each tool's module docstring carries its exit codes and the exact
  command to replay a reported fuzz failure.

## Host platforms

`make setup`, `make check`, `make lint`, and the fuzzers are the developer gate and run
on the platforms CI runs, which is Linux today. The evidence tools
(`evidence_check.py`, `evidence_export.py`, `restore_drill.py`, `backup_status.py`) are a
different case: the
evidence directory lives on the host the game server runs on, so an operator runs them
there, and a Windows host must get the same verdict as a Linux one. They therefore use
the standard library only, no POSIX-only call, and no shell; `make` targets are the
convenient path, not the only one, and `uv run python tools/evidence_export.py --dir
<evidence-dir> --out <archive-root>` is the equivalent everywhere `uv` runs.

Two rules keep an archive portable, and both are pinned by the self-tests under
`make test-tools`:

- A segment or index name is refused if it is a Windows device stem (`nul`,
  `con`, `com1`, `lpt9`, with or without an extension) or ends in a dot, because a
  Windows host resolves the first to a device and strips the second, so the name
  would not mean the same file there.
- A name from a manifest is matched against the archive's own entries, not joined
  onto it, so a name differing only in case is reported on a case-sensitive host
  and a case-insensitive one alike instead of verifying clean on one and failing on
  the other.
