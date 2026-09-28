# Changelog

Notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); each section matches a
release tag.

This is a 0.x project: minor bumps (`0.Y.z`) may change tooling contracts and
command names, patch bumps are expected not to. Releases before 0.3.0 predate
this file and are described only by their git tags.

## [Unreleased]

This ships as 0.5.0, not a patch: the entries under Breaking change config validation, the
evidence schema, and the exit codes a script reading the tool CLIs sees, and the 0.x policy
above reserves minor bumps for that.

### Breaking

- Config validation rejects an empty `evidence.dir`, `identityMap.path`, or `hmacKey.path`, and
  rejects a `webhook.urlEnv` or `dashboard.secretEnv` that is not `^[A-Z][A-Z0-9_]*$`. Before
  this release a lower-case or hyphenated environment variable name loaded, and a misspelled one
  silently disabled the webhook sink or the dashboard secret. The config is rejected wholesale at
  startup, so an operator whose deployed `server-guard.json` names such a variable must rename it
  in the file and in the environment before upgrading. The values themselves are unchanged.
- The evidence schema's root object is now `additionalProperties: false`. A record carrying an
  unrecognized top-level key fails validation, where it passed before. No shipped sample carried
  one, and a detector emitting one needs it named in `docs/SCHEMAS.md` first.
- A replay trace requires the `determinism` block, so a trace written before this release no
  longer validates. Regenerate traces with the current harness (including
  `tools/fixtures/traces/inventory/stack.v1.sample.json`), which writes `startUtc`,
  `startMonotonicMs`, and the recomputed `fingerprint`.
- The tool CLIs report a usage error as exit 2 and a verification failure as exit 1, and print
  failures on stderr with a clean verdict on stdout. A script that treated any nonzero exit as
  "the evidence is bad" now sees 2 for its own invocation mistake and must read stdout to
  distinguish a pass from a failure.

### Added

- A doccheck rule that the Makefile's test registries cover the tree: every
  `tools/fuzz_*.py` is in `FUZZERS` and run by `make test-tools` in that order, and every
  `tools/*.py` exposing `--self-test` is run by `make test-tools` or `make exercise`. A
  harness added to `tools/` without joining `FUZZERS` used to pass `make ci` without ever
  running, and `make fuzz FUZZ=` could not address a seed the full run never produced.
  `tools/doccheck.py --self-test` covers the rule and joins `SELF_TESTS`, so the gate now
  carries a self-test like every other tool in the registry.
- `tools/sbom.py`, driven by `make sbom [OUT=dist/sbom.cdx.json]`: renders `uv.lock` as a
  CycloneDX 1.6 bill of materials, so a vulnerability scanner or an auditor can read what
  a release contains without running uv. One component per locked package, carrying the
  sha256 the lock records, the dependency graph, and a `runtime` or `dev` scope property
  (the runtime list is one package; the rest is the dev toolchain). The output is
  deterministic, the serial number being a UUID over the lock digest and the document
  carrying no timestamp, so an unchanged lock regenerates byte for byte. `uv.lock` records
  no license data, so the document claims none. A lock entry with no hash, or a dependency
  the lock does not describe, is an error rather than a silently dropped component.
  `make ci` renders it, so a lock that cannot be inventoried fails the gate.
- `tools/config_check.py`, driven by `make verify-config FILE=<file> [SKIP_ENV=1]`:
  validates an operator's own config file before it is deployed, with the same rules
  the strict Phase 2 loader is specified from. It rejects unknown keys, types, enums,
  and ranges from `config.v1.schema.json`, a `modes` key that is not a registered
  detector id, a `thresholds` key the generated manifest does not declare for that
  detector, a threshold value outside its declared range, and a `webhook` or
  `dashboard` that is `enabled` while the environment variable its `urlEnv` or
  `secretEnv` names is unset or empty. `--show-effective` prints the effective
  (defaulted) config and the SHA-256 that evidence records, the health report, and the
  hook manifest carry. Secret values are never read: only the presence of the named
  variable. Self-tests run under `make test-tools`. The shipped example was gated by
  `make check`; an operator's file was gated by nothing.
- `sg config show` and `sg config check [path]` in `docs/OPERATIONS.md`: the effective
  config as loaded, under the recorded `configHash`, and a validation pass that reports
  what startup would refuse without reloading.
- `make self-test TOOL=<evidence_check|evidence_export|restore_drill|backup_status|config_check|sbom>`
  runs one tool's negative self-tests,
  the half of `make test-tools` that `make fuzz FUZZ=<name>` does not cover. The Makefile's
  `SELF_TESTS` list is the registry: `make test-tools` iterates it, so a tool added to the list
  joins the CI run with no other edit.
- The uv release is pinned machine-readably as `required-version` under `[tool.uv]` in
  `pyproject.toml`, the same release `astral-sh/setup-uv` installs in CI. uv refuses to run
  against a mismatch and names the required release, so the check belongs to the tool instead
  of to a line of prose in the README.
- `tools/evidence_export.py`: `export` takes an optional `stamp` naming the archive rather than
  timestamping it. The CLI default is unchanged.
- `tools/fuzz_detector_spec.py`: a seeded, structure-aware fuzzer over
  `tools/detector_spec.yaml` and both of its consumers (doccheck's spec pass and the
  renderers in `render_detectors.py`). It mutates the spec into YAML documents and
  corrupts the document text, and asserts that `load_spec` either returns a list or
  raises `SpecError`, that no doccheck spec consumer raises on any content, and that
  the render path survives any value in the fields the structural validator leaves
  free. Pair assertions drop and mistype each required field. Run by
  `make test-tools` and `make fuzz FUZZ=detector_spec`.
- `tools/restore_drill.py`, driven by
  `make drill-restore ARCHIVE=<archive> WORK=<empty-dir> [CONFIG=<config-file>]`: the
  monthly restore drill as a command with an exit code. It verifies the archive
  against its manifest, copies its segments and index into an empty work directory
  under their own file names, re-verifies the hash chain over the copy, and reads the
  oldest and newest records back out. With `--config` it also resolves
  `identityMap.path` and `hmacKey.path` and fails when either is missing, zero bytes,
  or older than the 7-day copy cycle, so a drill cannot pass on evidence nobody can
  attribute. The live evidence directory is never written and a non-empty work
  directory is refused rather than merged into. Self-tests run under
  `make test-tools`.
- `tools/backup_status.py`, driven by
  `make backup-status ROOT=<archive-root> [MAX_AGE_HOURS=24]`: the read-only RPO check.
  It verifies the archives in a root newest first and reports the age of the newest
  one that verifies, measured from the archive manifest's `createdUtc` rather than a
  directory timestamp that copying off the server resets. A missing archive, an
  archive that does not verify, and an archive older than the window are each reported
  by name and exit non-zero, which is what makes a scheduler that stopped running
  visible before an incident needs it. It writes nothing. Self-tests run under
  `make test-tools`.
- `make backup DIR=<evidence-dir> OUT=<archive-root>`: the scheduled archive run as
  one command with one exit code, the same verification `make export-evidence` runs.
  `make check` now requires the target, the drill, and the runbook lines that name
  both, so the recovery contract and the commands that execute it cannot drift apart.
- `tools/fuzz_config_check.py`: a seeded, structure-aware fuzzer over
  `tools/config_check.py`, the only gate an operator's hand-edited config file
  passes before it starts a server. It mutates the shipped example on its schema
  pass, mutates it again in a shape that survives the schema pass so the registry,
  manifest, and secret-env passes are reached, and corrupts the config file's
  bytes. It asserts that `check` and each cross-file consumer never raise and are
  deterministic, that `load` returns a config or a reported error whatever the
  bytes are, and that the config hash is 64 lowercase hex characters and stable
  under key order. Pair assertions pin the enabled-sink verdicts, the unlisted
  detector count, and a file round trip that must not change the hash. Run by
  `make test-tools` and `make fuzz FUZZ=config_check`.
- The archive manifest carries `manifestSha256`, a digest over its own remaining
  fields, and `manifestVersion` is 2. The per-file SHA-256s proved the archived
  bytes; the self-digest proves the attestation describing them, so a manifest
  edited in place no longer verifies clean. A version 1 manifest has no
  self-digest and is reported as an unsupported version by
  `make verify-archive`.
- `make fuzz FUZZ=<evidence_check|schema_validate|replay_trace|detector_spec|evidence_export|config_check>
  [ITERATIONS=N] [SEED=S]`
  runs one fuzzer at a short iteration count, with a usage error naming the valid
  harnesses. Every harness already took `--iterations` and `--seed`.
- `CONTRIBUTING.md` states the runnable path: prerequisites, bootstrap, the loop, the
  single-fuzzer target, generated-file regeneration, and what a change must include.
- Replay traces carry a required `determinism` block: `startUtc` and
  `startMonotonicMs` are the virtual clock origin a replay derives event times and
  evidence `utc`/`monotonicMs` from, and `fingerprint` pins the expected outcome
  projection (run header, clock origin, per-case findings, actions, and work units)
  so a diverging replay fails on one digest. `tools/replay_contract_check.py`
  verifies both and rejects a case whose `tick` steps backwards.
- The evidence schema's open value bags (`context`, `observations`, `expected`,
  `actual`, `replayedFrom`) carry a `propertyNames` deny-list, so a detector
  cannot write a raw platform ID, player name, address, or credential into a
  record that operators and webhook consumers read. `doccheck.py` fails when an
  open object drops it, and the schema fuzzer pins that it rejects.
- `tools/evidence_export.py`, driven by `make export-evidence DIR=<dir> OUT=<root>`
  and `make verify-archive ARCHIVE=<dir>`: the evidence directory's hash chain is
  verified before anything is copied, every copy is re-hashed, and the export is
  refused outright if either fails, so a bad backup is never declared complete. The
  archive carries `archive-manifest.json` (`manifestVersion: 2`, see the manifest
  entry under Added) with the sha256, byte count, and record count of every file
  written, described from the copies rather than the source. `make verify-archive` re-checks an archive against its
  manifest and re-verifies the chain inside it, which is the restore drill.
- `docs/OPERATIONS.md` -> Backup and restore: the operator procedure for the
  archive, including that the identity map and the HMAC key live outside the evidence
  directory and are backed up separately. Archiving a pseudonym key beside the records
  it unmasks would hand one stolen copy both halves.

### Changed

- `ruff.toml` selects two more rule groups. `ISC` rejects implicit string concatenation
  inside a collection, where two adjacent literals read as one element but are in fact two,
  and `+` concatenation that the formatter would otherwise rewrite. `PGH` rejects a bare
  `# noqa` and a `# type: ignore` with no error code, so a suppression must name the rule
  it silences instead of the whole line. Every existing suppression already named its rule,
  so the tree passes both groups unchanged apart from five message literals that now carry
  their concatenation parentheses.
- The restore drill (`make drill-restore ... CONFIG=<file>`) confirms the config is
  the one the restored evidence was written under: every record carries the
  `configHash` of the effective config in force when it was written, so a config
  that hashes to a value no restored record carries is reported instead of being
  paired with findings that were never produced under it. Without `CONFIG` the
  verdict now says the config, identity map, and HMAC key went unchecked, so the
  drill record does not imply a cross-check that never ran. The drill previously
  resolved the key and map paths from whatever config it was handed, so a wrong
  file passed it.
- `make backup-status ROOT=<root>` reports a gap wider than the RPO window between
  two adjacent archives. A scheduler that ran for a week and then stopped left a
  fresh newest archive and no failing exit code; the age of the newest archive is
  the one thing that could not see it, and the monthly "confirm the archives for
  the last 30 days are present" was a directory listing an operator read by hand.
- The evidence schema's `personalDataDenyList` denies the identity spellings it
  missed: `xuid` (the same account as `steam` under the engine's own name), and
  `name`, `nick`, `handle`, `alias`, `ident`, `login` for the display-name family.
  A key charset of `[a-z_]+` already excluded the camelCase spellings, so the
  snake_case ones were the reachable gap, and they carried the same account to
  the same exporter. `tools/fuzz_schema_validate.py` probes each new spelling in
  every open bag and pins twelve value-bag keys that must still validate, so a
  later stem cannot take the whole bag with it.
- Free-text fields in the evidence schema are bounded: `suppressedReason` at 64,
  `itemId` and `marker` at 128, alongside the `modIdentity`, `actor`, and `reason`
  bounds that already existed. These are the fields a writer fills by
  interpolating whatever the game handed it; an unbounded string there is where a
  name or a quoted line would sit in a record for its whole retention window.
- The `ci` workflow runs on `push` to `main` and on `pull_request`, not on a push to
  every branch. A branch with an open pull request fired both events for the same
  commit, so each push spent a second runner repeating the same gate.
- The operator-facing make targets (`verify-config`, `verify-evidence`,
  `export-evidence`, `verify-archive`, `backup`, `backup-status`, `drill-restore`)
  now depend on `guard-python` like every other target, so a scheduled backup run
  refuses an interpreter other than the pinned one instead of archiving evidence
  under a drifting toolchain. `backup` and `drill-restore` report a missing argument
  on stderr with exit 2, matching the other targets, and drop the deprecated
  `test -a`.
- `make check` compares `[project] version` in `pyproject.toml` against the newest dated
  section in this file, and requires the dated sections to be in descending order. A
  release is a tag, a manifest version, and a dated section, and nothing read the other
  two, so a bump that missed one shipped a tag whose metadata still named the previous
  release. `## [Unreleased]` is above the comparison on purpose: between releases it is
  expected to be ahead of the last tag.
- `CONTRIBUTING.md` states the release step: which bump the 0.x policy above implies, the
  three places a release edits, and that a published tag is not moved or re-cut.
- `docs/SCHEMAS.md` states the two config rules the file alone cannot enforce: a
  detector id or threshold key outside the registry and the manifest is rejected
  rather than loaded as an `observe` default, and a sink enabled with its environment
  variable unset is a load failure rather than a feature that stays off. Path keys
  resolve against the host's mod data root, not against a data root "the operator sets
  in the config", which no schema key sets.
- `make lint` runs black, ruff, and mypy over the repository root rather than
  `tools/`. The tools are the only Python shipped today, so the gate is
  unchanged, but a path-scoped target exempts every Python file added outside
  it from black, ruff, and mypy without any visible failure.
- `ruff.toml` selects the `N`, `PIE`, `TID`, `FA`, `ERA`, and `TD` rule groups on
  top of the existing set. They catch a mis-signed method argument and an
  unconventional error-class name, commented-out code that hides unmerged work
  behind a green gate, and a `TODO` with no owner. The fuzzer error class is
  renamed `InvariantBrokenError` to satisfy `N818`.
- `mypy.ini` adds `possibly-undefined` to the enabled error codes, so a name read
  after a guard that may not have assigned it is an error.
- The archive self-test no longer depends on two exports landing in the same
  wall-clock second. The overwrite refusal is keyed on the destination archive
  name, and `utc_stamp()` resolves to one second, so the case it exercises ran
  only when the clock happened not to tick between the two exports. `export()`
  takes an optional `stamp` naming the archive, the self-test passes the first
  archive's name, and the case runs every time.
- `ruff.toml` selects the `SIM` and `S` rule groups, so `make lint` now covers
  control-flow simplification and the suspicious-construct checks (bandit's
  subprocess and weak-PRNG rules included). The five seeded fuzzer `random.Random`
  sites and the one `subprocess.run` in `tools/doccheck.py` carry a scoped
  `# noqa` naming the rule and the reason.
- The Python toolchain pin is the whole version, not the minor: `.python-version` names
  `3.12.12`, `tools/guard_python.py` fails on any other interpreter instead of accepting
  an older patch, and CI pins the uv release it installs. CI also fixes `LC_ALL`, `TZ`,
  and `PYTHONHASHSEED`, so gate output and rendered files do not follow the runner's
  locale, zone, or hash order.
- `make lint` and `make detectors` run the interpreter guard first, like the other
  tool targets.
- `tools/evidence_check.py` streams evidence segments instead of materializing them, so
  `make verify-evidence` costs constant memory on a production evidence directory
  (measured 217MB to 42MB peak RSS on a 25MB segment, flat from 25MB to 101MB segments).
- `pyproject.toml` sets `tool.uv.required-version` to the uv release CI installs, so the
  resolver that reads `uv.lock` is pinned for a local run too and a different uv release
  refuses to run instead of resolving the lock differently.
- The Makefile exports `TZ=UTC` and `PYTHONHASHSEED=0`, the values ci.yml already set, so a
  local `make ci` and the CI gate of one commit report the same thing.
- `make fuzz FUZZ=evidence_export` runs the archive fuzzer at a short iteration count, like
  the other five harnesses. It was missing from the Makefile's fuzzer list, so a seed its
  full run reported could not be replayed. `make export-evidence` quotes `DIR` and `OUT`, as
  `make verify-evidence` already did, so a path containing a space is one path.
- `tools/evidence_export.py` counts a segment's records by streaming the file, matching the
  constant-memory property `evidence_check.py` already had and the module claimed for the
  copy and hash path.
- `tools/render_detectors.py` parses `tools/detector_spec.yaml` once per process; the
  doccheck gate parsed it three times at ~90ms each.
- The evidence audit record bounds `reason` at 512 characters.
- `hmacKey.permissions` joins `identityMap.permissions`: the re-identification
  key file is stored at the same `0600` default as the identity map.

### Fixed

- `make export-evidence` is re-runnable. The archive name carries a one-second
  stamp, so a retried export landed on the directory the first attempt had written
  and was reported as a failure, which the backup schedule in
  [docs/OPERATIONS.md](docs/OPERATIONS.md) alerts on: a retried backup raised the
  alarm for a backup that was present and verified. A retry whose existing archive
  holds exactly the segments and index it would have copied now exits 0 and writes
  nothing. An archive holding a different evidence set under the same name is
  still refused, because a different export must not replace an archive the
  operator may already have copied off the server.
- Each `make export-evidence` stages into its own directory. Two exports of the
  same second shared one staging path, so the second deleted the first's copy in
  progress. A staging directory left by a killed run is swept once it is older than
  a day, so the archive root does not grow a directory per crash.

### Added

- `tools/replay_contract_check.py --self-test`, run first by `make exercise`, fires every
  contract rule from a mutation of the shipped trace and names the message each must
  produce. The plain run only proves the shipped trace satisfies the contract, so a
  checker that accepted every trace passed it, as did one whose budget comparison or
  stack-invariant rule was inverted.
- `tools/replay_contract_check.py --fix-fingerprint` reseals a trace's recorded
  `determinism.fingerprint` from its current outcome projection, rewriting only the
  digest. Editing a trace without resealing it failed the gate with two digests and no
  way to compute the right one short of running the projection by hand.
- `actions.tempBanLocal` (bool, default `false`) in config v1. The `temp-ban (local)`
  action was in the accepted action vocabulary (D-04, POLICY.md -> Action set) and in the
  evidence action enum, but no config key enabled it, so the documented
  "actions as separately enabled switches" did not hold for the one action that needs
  the strongest gate. Enabling it still requires the kick gate and per-incident operator
  approval.

### Fixed

- `config_check.py` exited 2 on a config file that could not be read, where
  `tools/README.md` -> Command-line contract and its own docstring make a path that
  does not exist a check failure (1). A deploy script branching on the code read a
  missing path as its own invocation mistake and skipped investigating it. The
  unreadable-file report now goes through the same stderr report as every other
  failing check.
- `doccheck.py`'s spec pass raised `TypeError` on a detector whose `inputs` is not a
  list, which aborted `check_spec` and discarded every other finding from the pass
  with it; the report line saying `inputs must be a list` was unreachable. Seeds 14
  and 17 of `fuzz_detector_spec.py` failed on it.
- The evidence personal-data check walked `properties`, `patternProperties`, `oneOf`,
  and `items` only, so an open value bag reached through a local `$ref`, declared in
  `definitions`, or named by an `additionalProperties` subschema was never seen and
  passed the gate holding any key a detector wrote. The evidence schema is `$ref`-heavy,
  so that was where the next bag would land. Refs are now followed and `definitions`
  and an `additionalProperties` subschema are walked, with the resolved refs on the
  path tracked so mutually referencing definitions terminate.
- `doccheck.py`'s link check resolved the file half of a markdown target and skipped
  the anchor, so `docs/SCHEMAS.md#does-not-exist` passed, though the gate documents
  that internal links resolve to a file or an anchor. GitHub-style heading slugs
  (ATX and setext, outside fenced blocks, with `-1`/`-2` for repeated headings) are
  now resolved, for a bare `#fragment` as well as `file.md#fragment`.
- `doccheck.py`'s TODO.md check rejected only the literal `- [` and `* [` spellings,
  so `-  [ ]` and `-[ ]`, which CommonMark still renders as a checkbox, passed a
  phase-gate check that documents one canonical form. Fenced blocks are now skipped,
  so an example of the format in a code block is not reported as the format.
- The evidence export self-test asserted that a second export refuses to overwrite a live
  archive, but it relied on both exports landing in the same wall-clock second. When the
  first export crossed a second boundary the two names differed, the export correctly
  succeeded, and the self-test failed on a correct tree. The stamp is now pinned through
  `export(..., stamp=...)`, so the collision is the export guard's doing rather than a race
  against the clock.
- The accepted decision D-13 named `EntityAlive.DamageEntity` as the primary damage
  path. No detector, seam, or registry entry has ever hooked it: the census-grounded seam
  in `tools/detector_spec.yaml` and `docs/ARCHITECTURE.md` is `NetPackageDamageEntity`
  paired with `NetPackageRangeCheckDamageEntity`. D-13, the Phase 6 checkbox in
  `TODO.md`, and the corresponding open question in `docs/RESEARCH.md` now name the
  package the code hooks.
- D-05 credited "Layer 4 property tests" with the chain, truncation, and tombstone
  invariants. Layer 4 is the offline replay layer; the property tests are Layer 2. The
  entry now names the Layer 4 `review-surface` fixture family that actually covers them.
- `config_check.py` raised a traceback on a config file that is not UTF-8 (a UTF-16
  or Latin-1 save, the shape a Windows editor produces), where every other
  unreadable file was reported as a message. It now names the file and the decode
  error, and exits 2 as a usage error.
- The shipped inventory replay fixture carried a `determinism.fingerprint` that matched
  no outcome projection, so `make check` and `make exercise` failed on a clean tree from
  the commit that added the field. The fixture now carries the digest its own content
  produces under the projection `tools/replay_contract_check.py` recomputes.
- `doccheck.py`, `evidence_check.py`, and `replay_contract_check.py` printed
  failure detail on stdout, where a script reading the verdict also reads the
  diagnostics. A failing run now reports on stderr and a clean one on stdout, which
  is what `render_detectors.py` and the fuzzers already did.
- `evidence_check.py` reported a missing `--dir` as a verification failure (exit 1)
  and silently ignored `--index` without `--dir`; both are usage errors now (exit 2),
  as is a bare invocation, which prints its help to stderr.
- `render_detectors.py --check` raised a traceback when `docs/DETECTORS.md` was
  absent; it now reports the registry as missing.
- `--iterations` and `--seed` had no help text and accepted `0` or a negative count,
  which reported a clean run having tested nothing. Every harness rejects a count
  below 1, and the three fuzzers share one flag definition so the help, defaults,
  and validation cannot drift apart.
- `make fuzz` and `make verify-evidence` passed operator-supplied paths unquoted, so
  an evidence directory containing a space split into two arguments, and their usage
  errors printed to stdout.
- The doccheck spec and manifest checks indexed spec, threshold, and detector fields
  with `[]`, so a hand-edited `tools/detector_spec.yaml` or manifest missing one of them
  raised out of the gate instead of reporting the entry. Those reads report now, and a
  threshold whose declared type is `int` or `float` must carry a numeric default inside
  its range (a YAML `true` passed the range comparison as an int, and
  `render_manifest` copies that default into the shipped manifest).
- `make check` verified the rendered detector registry against the spec but not
  `config/detector-config-manifest.json`, so a manifest left behind by an earlier spec
  edit could ship a stale threshold default, range, unit, or note.
  `tools/render_detectors.py --manifest --check` now fails on that, and `doccheck.py`
  runs it.
- `doccheck.py` walked `.scratch/`, so a contributor following the workspace rule of
  keeping scratch work there failed the docs gate on links in their own scratch notes.
  Version control, the local environment, tool caches, and `.scratch/` are now skipped.
- A malformed `tools/detector_spec.yaml` crashed the doccheck gate that is meant to report
  it. `render_detectors.load_spec` raises `SpecError` instead of `KeyError` on a document
  with no detector list; `doccheck` reads the spec through `parsed_spec()` and its
  validators tolerate non-mapping records, non-mapping inputs and thresholds, non-list
  fixture and context lists, and non-numeric threshold bounds; vocabulary membership goes
  through `in_vocab`, because `x in {...}` raises on an unhashable `x`; and the renderers
  skip list fields that are not lists instead of iterating or joining them.
- `fuzz_replay_trace.py` built its deep-nesting probe from a mutated trace and then
  indexed `cases[0]["events"][0]`, so a mutant that dropped or replaced either crashed
  the harness with a bare `TypeError`. The probe now copies the pristine sample. The
  default seed happened to survive; `--iterations 50 --seed 1234` did not.
- `make ci` now includes `make exercise`, so the replay contract check gates CI and not
  only a manual run.
- README, RESEARCH, and the 0.4.0 entry described V3.2.0 (b9) as the pinned
  build, which contradicts the shipped `buildPin.buildId` default, the config
  schema, and POLICY.md. The installed build and the supported pin are now
  stated separately, and RESEARCH cites the V3.1.0 census path it actually
  names.
- The V3.2.0 (b9) pin from 0.4.0 now reaches the whole design contract: `docs/POLICY.md`,
  `docs/ARCHITECTURE.md`, `docs/SCHEMAS.md`, `docs/TEST_PLAN.md`, `docs/RESEARCH.md`,
  `docs/METHODOLOGY.md`, `SECURITY.md`, `TODO.md`, the config v1 default, the config and
  evidence samples, and the replay fixture all still named V3.1.0 (b14).
- `docs/DECISIONS.md` records the re-pin as D-18 and marks D-01's build pin superseded; the
  one-build fail-open rule is unchanged.
- The seam map cites the V3.2.0 netpackage census (195 types) instead of the V3.1.0 census
  (193 types), and `world.budget` no longer names `NetPackagePOIAround`, which the V3.2.0
  census does not contain.
- `tools/evidence_check.py` verifies chain continuity inside every segment, not only in
  the first one. A record after the first line of a non-genesis segment was skipped along
  with the cross-segment link, so a tampered record there passed verification.
- The JSON Schema validator and the evidence parser reject non-finite numbers
  (`NaN`, `Infinity`, `-Infinity`). NaN compares false against every bound, so a
  `minimum`/`maximum` check alone reported nothing and a NaN confidence or
  threshold reached a consumer as a comparison that never fires. The evidence
  segment parser now refuses the bare literals at the file:line boundary, and
  `canonical()` serializes with `allow_nan=False` so a non-finite value can
  never be hashed into the chain as a token no reader reproduces.
- `render_detectors.py` writes the config manifest with `allow_nan=False`, so a
  non-finite threshold in the spec fails loudly instead of producing a bare
  `Infinity` literal in a shipped JSON file.
- A `oneOf` mismatch with no matching branch now reports the first branch's
  errors instead of only the branch count, and a `oneOf` that is not a non-empty
  array is reported rather than iterated.
- The detector spec gate rejects a non-finite or inverted range, a default that is
  not a finite number, and a fractional range bound or default on an `int` threshold,
  which truncates on load. A threshold entry missing `key` or `type` is now reported
  instead of raising `KeyError`.
- `evidence.rotationSizeMB` is documented as decimal megabytes in
  `docs/SCHEMAS.md` and the config schema, so rotation sizing has one unit.
- Evidence `utc` and `savedAt` are validated as offset-qualified RFC 3339
  date-times. The schema now declares `format: date-time` and the gate rejects a
  value carrying no offset, which names no instant and is read in the reader's own
  local zone, so two readers of the same record could disagree on when it happened.
- The evidence segment parser reports a bare `NaN`/`Infinity` literal with its
  `file:line` context like any other unparseable line. The non-finite hook raised a
  bare `ValueError` that escaped the `JSONDecodeError` handler uncontextualized, so
  a segment with a `NaN` anywhere was reported without saying which line to look at.
  `fuzz_evidence_check.py` caught this on the default seed.
- The replay contract checker reports a trace whose outcome projection is not
  serializable (a non-finite number where the projection reads one) instead of
  raising, which broke its own contract to return an error list for any input and
  made a hand-edited trace a traceback rather than a diagnosis. `fuzz_replay_trace.py`
  caught this on the default seed.
- `--index` is checked to be a plain ASCII file name before it is joined onto the
  evidence directory, on both tools that take it. `directory / name` resolves an
  absolute name to itself and walks out of the directory on a `..` segment, so a
  crafted value read a file outside the evidence directory, and `evidence_export.py`
  copied that file into the archive. The exporter already applied this rule to the
  member names a manifest carries; the check is now one shared predicate
  (`evidence_check.valid_file_name`) both tools use.
- A manifest file entry whose `bytes` is not a non-negative integer is reported as a
  malformed entry instead of raising out of the archive verifier, which summed it
  while checking `totalBytes`.
- `make verify-archive` checks the per-file and total record counts the manifest
  records, not only the sha256 and byte count. An archive whose manifest misstated
  how many records it holds verified clean, and the restore drill would have
  accepted it.
- `fuzz_evidence_export.py` asserts that `verify()` never raises, which its docstring
  claimed and the harness never checked, and requires manifest byte damage to be
  detected only when it changes a field `verify()` reads. Byte damage inside a field
  it ignores (the source path, the canonicalization note) left a verifiable archive
  verifiable, and the harness reported that correct verdict as a failure.
- The CI job is bounded by a 20-minute timeout, so a wedged fuzzer fails the run
  instead of holding a runner for the 6h default, and the checkout token is not
  persisted into `.git/config` between steps, since nothing pushes from CI.
- An archive member name that is a Windows device stem (`nul`, `con`, `com1`,
  `lpt9`, with or without an extension) or that ends in a dot is refused instead of
  being joined onto the directory. On a Windows host, which is where the evidence
  directory lives, the first resolves to a device and the second has its dot
  stripped, so the name would not mean the same file there as it does on the host
  that wrote the manifest.
- A file named by an index or an archive manifest is matched against the directory's
  own entries rather than joined onto it. On a case-insensitive filesystem (NTFS,
  APFS, ext4 casefold) a name differing only in case opened the wrong file, so an
  archive could verify clean on one host and report a missing member on another.
- The doccheck link pass resolves each path component against the directory's own
  entries, so a link whose case does not match the file on disk is reported instead
  of passing on a contributor's case-insensitive checkout and breaking on the
  case-sensitive host CI runs.
- The generated registry, the generated config manifest, and a resealed replay
  trace are written with LF line endings, the policy `.gitattributes` declares, so
  regenerating them on a host whose default terminator is CRLF no longer rewrites
  every line of a tracked file.
- The `evidence_export.py` self-test read the clock to place its two exports in the
  same second, so the same-second collision refusal it checks failed whenever the
  second boundary fell between them (roughly one run in four). `export()` takes the
  archive stamp as an argument and the self-test passes a fixed one.
- `evidence_export.py verify` raised a traceback instead of reporting the archive
  when a member or the manifest itself could not be read, and `export` did the same
  when the archive root could not be created or a segment's size could not be read.
  A restore drill runs after the disk has already lost something, and an unreadable
  file is one of the answers the drill exists to produce. All three are named in the
  report now, and the other manifest entries are still checked.
- `config_check.py` raised a traceback naming no config file when an operator's
  hand-edited config was not UTF-8 (a legacy code page or a UTF-16 save). It reports
  the file and the reason, like the other load failures.

## [0.4.1] - 2026-09-20

### Changed

- Tooling and CI upkeep only, all via dependabot: black 25.9.0 to 26.5.1 and
  ruff 0.16.4 to 0.16.6 in the lock, `actions/checkout` 4.2.2 to 7.0.1, and
  `astral-sh/setup-uv` 5.4.2 to 10.0.1 in the workflows. No detector, gate, or
  command behavior changes. Patch bump: `make ci` is green unchanged.

## [0.4.0] - 2026-09-11

### Changed

- `AGENTS.md` states what this repository owns and does not own: server-side
  behavioural validation and anti-cheat evidence here, no client scanners and
  no automatic permanent bans by default, stock RE in `7dtd-engine-research`.
- The research citations point at the grouped `docs/<subsystem>/` tree, and the
  locally installed server (V3.2.0 b9) is now recorded separately from the
  supported pin. The pin itself is still **V3.1.0 (b14)**: the example config,
  the config schema, and POLICY.md were not moved, so any hook written now
  targets b14 and other builds load observe-only.

## [0.3.0] - 2026-08-26

Toolchain and gate release. The design contract (`docs/`, `TODO.md`) is
unchanged apart from the corrections listed below; no detector behavior exists
yet to change.

### Added

- `make lint`: black, ruff, and mypy `--strict` over `tools/`, wired into
  `make ci` and therefore into CI. The tooling is clean under all three.
- `pyproject.toml`, `uv.lock`, `ruff.toml`, and `mypy.ini` declare the tool
  dependencies and the lint and type settings.
- The em-dash gate now reads shipped source files (`tools/*.py`, `Makefile`,
  `config/**.json`, CI workflows, the lint configs), not just markdown.

### Changed

- Python toolchain is uv. `make setup` is `uv sync --frozen` and every tool runs
  through `uv run --frozen`; CI uses `astral-sh/setup-uv` in place of
  `actions/setup-python`. `requirements.txt` is gone, replaced by
  `pyproject.toml` plus a committed `uv.lock`.
- `tools/fuzz_evidence_check.py` writes its temporary segments under `.scratch/`
  instead of the system temp dir, which is tmpfs (RAM) on the dev host.
- The design-contract review prompt moved from the repo root to
  `.github/reviews/design-contract-review.md`.
- `docs/INDEX.md` repo layout lists the top-level files and directories that
  exist on disk; `tools/README.md` covers `fuzz_common.py` and
  `guard_python.py`.

### Fixed

- `tools/replay_contract_check.py` reported "normal case expects findings" when
  a normal case *had* findings, which is the opposite of the rule it enforces.
- `docs/SCHEMAS.md` pointed at a bare interpreter invocation for the evidence
  verifier instead of `make verify-evidence DIR=<dir>`.
