# Threat model

Last reviewed: 2026-09-28, against the tree at the Phase 0 exit state described in
[TODO.md](../TODO.md): the design contract is complete, the C# runtime is not written, and the
only executable code in the tree is the Python tooling under `tools/` plus the CI workflow.

Every entry point, boundary, and control named below carries a file reference. A claim without
one is a claim the next review must re-derive; do not add one you have not read.

## Risk-ranked summary

Ranked by exploitability against the shipped surface first, then by impact on the planned
runtime. "Shipped" means the code in this repository today.

| # | Threat | Where | Impact | Status |
|---|---|---|---|---|
| 1 | Evidence chain cannot detect tampering with the final record of the last segment | `tools/evidence_check.py:259` (`verify_chain` returns `last_hash`, consumed as the next segment's expected `chainPrev` at `:381` and assigned at `:412`) | Evidence repudiation: a moderator's timeline ends at a rewritten record | Unmitigated by design, inherent to an append-only chain |
| 2 | The evidence chain is unkeyed in the shipped tooling, so anyone with write access to the evidence directory can re-chain an entire segment set | `tools/evidence_check.py:198` (`record_hash`, a plain sha256 over canonical JSON from `:192`; no MAC); HMAC and the identity map are `TODO.md:108`, unimplemented | Tampering, spoofing, repudiation of the whole audit trail | Unmitigated; scheduled for Phase 3 |
| 3 | `--out` is used verbatim for directory creation and for a recursive delete of stale staging trees, with no check that the target is the intended archive root | `tools/evidence_export.py:340` (`mkdir(parents=True)`), `:346` (`mkdtemp` under it), `:292` to `:311` (`_sweep_stale_staging` `rmtree` of every `STAGING_PREFIX*` directory older than the cutoff) | Tampering and denial of service against an operator-chosen path | Unmitigated; hand to sec-review |
| 4 | `sbom --out` creates parent directories for an operator-chosen path, the same class as threat 3 with no validation in front of it | `tools/sbom.py:458`, `:459` | Tampering: a path that matters is created and overwritten | Unmitigated; hand to sec-review |
| 5 | The restore drill resolves the identity-map and HMAC-key paths named in an operator config and stats them, with no permission or ownership check on the result | `tools/restore_drill.py:140` (`secrets_errors`), `:132` (`_resolve` returns a relative path joined onto `--runtime-root`) | Information disclosure: the report names the key paths and their age to anyone who can run the drill | Unmitigated; scheduled for Phase 3 |
| 6 | Pseudonym re-identification keys have no runtime protection because no runtime exists | `config/schemas/config.v1.schema.json`, `docs/SCHEMAS.md`; no `os.chmod` anywhere in `tools/` | Information disclosure: platform IDs map back to players from any readable evidence copy | Unmitigated; scheduled for Phase 3 |
| 7 | Self-tests and fuzzers create and recursively delete paths inside the repository, and run in CI | `tools/evidence_check.py:63` (`SCRATCH = ROOT / ".scratch"`), consumed at `:468`, `:558`, `:659`, `:692`, and by `restore_drill.py:232`, `backup_status.py:164`, `fuzz_evidence_export.py:41`, `fuzz_evidence_check.py:46`, `fuzz_config_check.py:74`, `fuzz_detector_spec.py:60` | Denial of service to a checkout; a wedged or slow fuzzer burns the CI budget | Bounded: every scratch path is a fixed constant, never a flag, and CI caps the job at `timeout-minutes: 20` (`.github/workflows/ci.yml:28`) |
| 8 | Generated thresholds and the detector registry are rewritten from one YAML file, so editing the spec silently changes config defaults and published tables | `tools/render_detectors.py:91` (safe load), writes at `:336` and `:348` | Tampering: a lower threshold becomes a default in shipped config | Mitigated: `tools/doccheck.py:643` (`check_registry_sync`) fails when the generated files drift from the spec |
| 9 | Every in-game control this document previously listed as present (permissioned console, permission-restricted evidence files, dashboard auth, webhook) has no implementation | `TODO.md:108`, `TODO.md:112`, `TODO.md:189`, `TODO.md:192` | A false mitigation claim is worse than a named gap: a reader builds on a control that does not exist | Fixed in this document; the surface is now marked planned |

Two earlier revisions of this document carried findings that are now resolved, and they are
recorded rather than deleted so the next pass knows the class was already hit.

- A traversing `--index` path was ranked third. That is no longer a threat: `verify_dir` refuses
  any name that is not a plain file name (`tools/evidence_check.py:362`), and `evidence_export.py`
  reuses the same predicate on its manifest's `indexFile` (`:445`) through `_entry_name` (`:399`).
  The remaining instance of the class is threat 3 (`--out`), because `--out` is a directory, not a
  name, and never passes through that gate.
- The absent-surface list claimed there is "no `socket`, `urllib`, `requests`, or `http` import in
  `tools/`". That was false as written: `tools/doccheck.py:55` imports `urllib.parse.unquote`. The
  claim is corrected below; `urllib.parse` is a string transform, not network I/O, but a reader
  grepping for the named modules would have found the import and stopped trusting the list.

The line references in this document drifted wholesale when the archive member list was shared
between export and verify (commit `ddefe21`): most cited line numbers in the prior revision no
longer pointed at the code they named. Every reference below was re-derived from the current tree
in this pass. A reference is only as good as the last time somebody re-read the line, so verify
before building on one.

## Shipped attack surface

This is the entire executable surface today. Every entry is a local CLI invoked by an operator or
by CI, never a network listener. There is no HTTP endpoint, no listener, no message consumer, no
webhook, and no IPC in the tree.

| Entry point | Untrusted input | Reads | Writes |
|---|---|---|---|
| `tools/evidence_check.py:924` (`--dir`, `--sample`, `--self-test`, `--index`) | Evidence JSONL segments and the segment index, produced by the runtime or by an attacker who reached the evidence directory | `tools/evidence_check.py:198` (record hash), `:319` (`load_index`) | none |
| `tools/evidence_export.py:906` (`--dir`, `--archive`, `--out`, `--index`, `--self-test`) | Evidence segments, an archive manifest, and the member names inside it | `tools/evidence_export.py:126` (`archive_members`), `:181` (`preflight`), `:450` (`verify`) | `tools/evidence_export.py:340`, `:346`, `:242` |
| `tools/restore_drill.py:370` (`--archive`, `--work`, `--config`, `--runtime-root`, `--key-max-age-hours`) | An archive directory, an empty work directory, and an operator config naming the key and identity-map paths | `tools/restore_drill.py:88` (`restore`), `:140` (`secrets_errors`) | `tools/restore_drill.py:88` (restores into `--work`, refusing a non-empty one) |
| `tools/backup_status.py:260` (`--root`, `--max-age-hours`) | An archive root: manifests and file digests | read-only | none |
| `tools/config_check.py:442` (`--config`, `--show-effective`, `--skip-env`) | An operator config file, validated against the shipped JSON Schemas and detector registry | `tools/config_check.py:219` (process environment) | none |
| `tools/sbom.py:429` (`--out`) | `uv.lock` | `uv.lock` | `tools/sbom.py:458` to `:459` |
| `tools/doccheck.py:1475` (no flags) | The repository tree itself, treated as content to lint rather than as instructions; spawns three sibling tools as subprocesses | `tools/doccheck.py:625` (`subprocess.run`, literal script names, `shell` off) | none |
| `tools/render_detectors.py:300` (`--check`, `--manifest`) | `tools/detector_spec.yaml`, parsed with the safe loader | `tools/render_detectors.py:91` | `tools/render_detectors.py:336`, `:348` |
| `tools/replay_contract_check.py:586` (`--self-test`, `--fix-fingerprint`; paths are fixed constants) | A committed sample trace | `tools/replay_contract_check.py:605` (safe load) | `tools/replay_contract_check.py:581`, under `--fix-fingerprint` only |
| `tools/guard_python.py:21` (no flags) | `.python-version` | `tools/guard_python.py:24` | none |
| `tools/fuzz_evidence_check.py`, `tools/fuzz_evidence_export.py`, `tools/fuzz_schema_validate.py`, `tools/fuzz_replay_trace.py`, `tools/fuzz_detector_spec.py`, `tools/fuzz_config_check.py` (`--iterations`, `--seed`) | Seeds, then self-generated mutations | see each harness | `.scratch` only, via `tools/evidence_check.py:63` |
| `Makefile` | The same operator-chosen paths, since `backup`, `backup-status`, `drill-restore`, `verify-config`, `export-evidence`, and `sbom OUT=` are the documented invocations | as above | as above |
| `.github/workflows/ci.yml` | The repository and the pull-request diff | `on: [push to main, pull_request]`, `.github/workflows/ci.yml:5` to `:8` | none |

### Surface deliberately absent

These are the properties a reader is most likely to assume and that no shipped code has:

- No network I/O. There is no `socket`, `requests`, `http`, `ftplib`, or `smtplib` import in
  `tools/`. The one `urllib` import is `urllib.parse.unquote` (`tools/doccheck.py:55`), which
  decodes percent-escapes in a string and opens nothing; a prior revision of this list claimed no
  `urllib` import at all, and that was wrong.
- No deserialization of untrusted data. No `pickle`, no `eval`, no `exec`; every YAML read goes
  through `yaml.safe_load` (`tools/render_detectors.py:91`, `tools/replay_contract_check.py:605`).
  `tools/fuzz_detector_spec.py` parses no YAML of its own: it mutates the structure that
  `render_detectors.load_spec` returns and writes mutated YAML back with `yaml.safe_dump` (`:122`),
  so the loader it exercises is the safe one.
- No archive extraction. No `tarfile` or `zipfile`, so the zip-slip class does not exist; the
  archive format is a manifest plus a flat directory, and every member name is validated before
  any filesystem use (`tools/evidence_export.py:399`, `:445`, `:489`, `:682`, `:687`).
- No credential handling. The chain is an unkeyed sha256 over canonical JSON
  (`tools/evidence_check.py:198`); no tool reads key or token contents. Two tools come close
  enough to name: `config_check.py:219` reads the process environment to check that a
  `webhook.urlEnv` or `dashboard.secretEnv` name is set, and reports presence only, never the
  value (`tools/config_check.py:176`); `restore_drill.py:140` stats the identity-map and HMAC-key
  files named in a config and reports their size and age, never their contents. Both resolve
  against a planned runtime, and both are threat 5 above.
- No process spawning except `doccheck.py:625`, which runs three literal script names through
  `sys.executable` with `shell` off and a `TOOL_TIMEOUT_S` cap (`:609`).

### Surface from dependencies and CI

- Third-party actions are SHA-pinned (`.github/workflows/ci.yml:42`, `:50`) with
  `persist-credentials: false` (`:44`). The runner image is pinned to `ubuntu-24.04` (`:26`),
  not `latest`, and the uv release the bootstrap action fetches is named in the workflow (`:52`).
- Workflow permissions are `contents: read` (`:11`) and the trigger is `pull_request`, never
  `pull_request_target` (`:8`), so untrusted PR code never runs in a privileged context. A `push`
  trigger also exists, scoped to `main` (`:6`, `:7`); that runs on already-merged code with the
  same read-only permission, so it adds no privilege.
- No CI secret is used: no `secrets.*`, no registry push, no release job. Dependency updates come
  from Dependabot on the `github-actions` and `uv` ecosystems.
- Dependencies resolve from a locked `uv.lock` through `uv sync --locked` and `uv run --locked`,
  so a lockfile that no longer matches `pyproject.toml` fails the run instead of installing or
  re-resolving. Every artifact in the lock carries a sha256,
  so an install verifies the bytes it fetched rather than the ones the index served.
- The dependency set has a machine-readable inventory: `make sbom` renders `uv.lock` as
  CycloneDX 1.6 (`tools/sbom.py`), one component per locked package with its hash, the
  dependency graph, and a `runtime` or `dev` scope, and `make ci` renders it on every run
  so a lock that cannot be inventoried fails the gate. `uv.lock` carries no license data, so
  the document claims no license rather than guessing one.
- Adding a dependency is a reviewed edit to `pyproject.toml`: the runtime list is
  deliberately one package, every entry in the `dev` group is a tool that runs nowhere but
  this repository's gate, and Dependabot covers the `uv` and `github-actions` ecosystems
  weekly so the pin is the thing a human sees.

## Planned surface (not implemented)

The C# runtime under `src/ServerGuard/` is scaffolding: the directories hold only README files,
and no `.cs` file exists. Everything in the two sections below is design intent with a phase
number, and is listed here so a reader can aim a later review, not because the control exists.

| Planned control | Phase | Ledger entry |
|---|---|---|
| HMAC pseudonyms, key rotation, local identity map, file permissions, redaction | 3 | `TODO.md:108` |
| WebDashboard, only after authentication and permission checks are tested | 3 | `TODO.md:112` |
| Permissioned console and dashboard review with timeline | 8 | `TODO.md:189` |
| Operator alert sink sending evidence IDs off the game thread | 8 | `TODO.md:192` |
| Build fingerprint and hook manifest v1, computed rather than declared | 1 | `TODO.md:83` |
| Harmony hooks on pinned seams, with the exact hook resolver and fail-open startup | 1 | `TODO.md:96` |
| Per-hook exception guard with a fault counter and runtime self-disable | 1 to 2 | `TODO.md:97` |

One artifact of the unimplemented state is worth naming: the only shipped replay trace carries
`"hookManifestHash": "UNVERIFIED"` (`tools/fixtures/traces/inventory/stack.v1.sample.json:6`).
The schema permits that sentinel deliberately, alongside a real digest
(`config/schemas/replay-trace.v1.schema.json:27`: `^(UNVERIFIED|[0-9a-f]{64})$`), so the value
validates by design rather than slipping past a loose check, and
`tools/replay_contract_check.py` does not require the digest branch. The consequence to carry
forward: a trace whose hash reads `UNVERIFIED` proves nothing about the build it was recorded
against, and nothing in the tree verifies a running server against the pinned `3.2.0-b9`
(`config/server-guard.example.json:6`). The pin is documentary and config-level until Phase 1
computes a fingerprint (`TODO.md:83`).

## Trust boundaries

Trusted: the dedicated-server process, authoritative world state, the server clock, the installed
mod configuration, evidence keys written locally, and explicit operator actions.

Untrusted: all client-supplied position, rotation, claimed hit, item stack, action timing, display
name, chat, reconnect state, and network ordering outside the server's validated state.

Conditionally trusted: game APIs and other mods. Every hook is build-pinned and fails open in
observe mode. Compatibility exceptions must be named and measured, never hidden in a global
threshold increase.

The boundaries that exist in shipped code today, with what crosses them:

1. **Operator to tool.** `--dir`, `--out`, `--work`, `--archive`, `--config`, and `--index` are
   the whole operator-controlled input surface. The evidence tools act on these paths with the
   authority of the invoking user, and `evidence_export.py` both creates and deletes directory
   trees. Threats 3 and 4 live here.
2. **Evidence directory to verifier.** A JSONL segment set and a `segment-index.json` are read as
   if authored by the runtime, but the directory is ordinary local storage. Nothing binds the
   segments to a key, so a hostile directory is a hostile author. Threats 1 and 2 live here.
3. **Archive to verifier and restore drill.** `--archive` takes a directory whose manifest names
   its members. This is the only boundary where manifest text becomes a filesystem path, and it
   is validated: member names and the manifest's own `indexFile` pass `valid_file_name`
   (`tools/evidence_export.py:399`, `:445`) before any join.
4. **Archive to restore drill (ordering is load-bearing).** `restore_drill.py` reads
   `manifest["indexFile"]` and joins it onto the archive directory (`tools/restore_drill.py:202`,
   `:88`). That join is safe only because `ee.verify(archive)` runs first (`:193`) and rejects a
   manifest whose `indexFile` is not a plain name (`tools/evidence_export.py:445`). Reordering
   those two calls reintroduces a traversal, and nothing else would catch it.
5. **Operator config to key paths.** A config file names the identity-map and HMAC-key paths, and
   the drill resolves a relative one onto `--runtime-root` and stats it
   (`tools/restore_drill.py:140`, `:132`). The config is trusted as operator input; the paths it
   names are then read from disk by a tool that reports their existence, size, and age. This is
   threat 5.
6. **Repository content to generated artifacts.** `tools/detector_spec.yaml` is the single source
   of truth; `tools/render_detectors.py` writes both the config manifest and the registry table
   inside `docs/DETECTORS.md` from it. Editing the spec is a repository change, and
   `tools/doccheck.py:643` fails the build when the generated files disagree with it.
7. **Pull request to CI.** Untrusted code runs on `ubuntu-24.04` under `contents: read` with
   SHA-pinned actions and no secrets. This is a build boundary with no production privilege
   behind it, which is the property to preserve if the workflow ever gains a release step.

### Secrets flow

No secret enters the shipped tooling and no tool reads a credential's contents. Two tools touch
the edges of that flow, and both are operator-invoked:

- `config_check.py:219` reads the process environment to confirm that a name in
  `webhook.urlEnv` or `dashboard.secretEnv` is set for an enabled section. Only presence is
  reported (`config_check.py:176`); `--skip-env` and `make verify-config SKIP_ENV=1` suppress it.
- `restore_drill.py:140` stats the files named by `identityMap.path` and `hmacKey.path` and
  reports whether each is present, non-empty, and inside the backup cycle.

The planned flow, for a later pass to verify once Phase 3 lands: the HMAC key and the identity map
are files created locally at `0600` and declared in `config/schemas/config.v1.schema.json`, and
the webhook URL arrives through an environment variable name rather than the config file
(`docs/SCHEMAS.md`) so the URL never lands in a committed file. Rotation starts a new chain
segment set (`docs/DECISIONS.md`).

## Assets and impact

| Asset | Class | Why it is worth attacking | Concrete blast radius |
|---|---|---|---|
| Evidence segments and index | Integrity, availability | The basis for every moderator decision; a false hard-reject denies legitimate play | A rewritten final record removes the last event from a decision timeline (`tools/evidence_check.py:259`, assigned at `:412`) |
| HMAC pseudonym key and identity map | Confidentiality, integrity | The re-identification key; pseudonyms are worthless once platform IDs map back | De-anonymization of every retained record, not just the operator's copy |
| Detector spec and generated config | Integrity | Lowering a threshold changes what the server rejects for every player | A fleet-wide false-reject rate on ordinary play |
| Build pin and hook manifest | Integrity | Hooks resolve against a specific Mono build; a wrong pin means the wrong method is patched | Either hooks silently no-op, leaving the server unprotected, or a fault on the game thread |
| Server game thread | Availability | Every detector runs inside the process that serves players | A hang or fault is a server outage for every player, not one session |
| Archive root and the operator's filesystem | Integrity, availability | `--out` and `sbom --out` create and delete trees wherever they are pointed | Loss of an unrelated directory tree under the archive root, not just of the evidence copy |
| Moderator reputation and player trust | Reputational | Enforcement decisions are visible and hard to reverse | A single wrong enforcement attributed to a player, made from a tampered timeline |

## Threats per boundary

STRIDE classes per boundary, tied to the entry points above. Each is a named threat with a
location, not a checklist.

**Operator to tool (evidence CLI).**
- *Tampering and denial of service*: `--out` reaches `mkdir(parents=True)` and, through
  `_sweep_stale_staging`, a recursive `rmtree` of every `STAGING_PREFIX*` directory under it older
  than the cutoff (`tools/evidence_export.py:340`, `:346`, `:292` to `:311`). A crafted or
  simply mistyped root can lose an unrelated tree.
- *Repudiation*: an operator can archive a chosen evidence set and the archive is indistinguishable
  from a complete one, because no signature binds an archive to the segment set it came from
  (`tools/evidence_export.py:242` writes the manifest, and nothing signs it).
- *Information disclosure*: bounded, not a gap. Every untrusted name that reaches the filesystem
  passes `valid_file_name` first (`tools/evidence_check.py:136`, `tools/evidence_export.py:399`),
  and `exact_child` (`tools/evidence_check.py:159`) resolves a name against the directory's own
  entries rather than joining it, so a case-insensitive host cannot substitute a different file.

**Evidence directory to verifier.**
- *Tampering and spoofing*: the chain is an unkeyed sha256 (`tools/evidence_check.py:198`), so an
  attacker with write access recomputes the whole chain rather than breaking it. The chain proves
  the file was not edited without recomputation; it does not prove who wrote it.
- *Repudiation*: the last record of the final segment has no successor hash to check against, so
  it is mutable until the next append (`tools/evidence_check.py:259`, consumed at `:381`).
- *Information disclosure*: an evidence file that reaches a backup or an archive carries
  pseudonymous records whose re-identification key has no enforced permissions today.

**Archive to verifier and restore drill.**
- *Tampering*: mitigated. Member names and the manifest index name are validated before use
  (`tools/evidence_export.py:399`, `:445`), hashes and byte counts are compared (`:402`), unlisted
  extra files are reported (`:484`), and the chain is re-verified inside the archive (`:489`).
- *Denial of service*: bounded by the per-entry name length cap `MAX_FILE_NAME_LEN`
  (`tools/evidence_check.py:117`), which the ASCII allowlist at `:123` makes a byte cap as well,
  so a hostile name is reported rather than rejected by the OS as `ENAMETOOLONG`.

**Operator config to key paths (restore drill).**
- *Information disclosure*: the drill reports the resolved path, size, and mtime of the identity
  map and the HMAC key (`tools/restore_drill.py:140`). A relative path resolves against
  `--runtime-root` (`:132`), so a config that names an absolute path reads a file the operator may
  not have intended. Contents are never read, so the blast radius is metadata.
- *Spoofing*: a config naming a different key file makes the drill report the wrong file as
  protected, which is a false assurance rather than a compromise. The Phase 3 work that binds the
  key to the chain is what removes it.

**Repository content to generated artifacts.**
- *Tampering*: mitigated by the registry-sync check (`tools/doccheck.py:643`) and the config
  schema cross-reference, both in `make check`.

**Pull request to CI.**
- *Elevation of privilege*: not present today. `pull_request` with `contents: read` and no
  secrets (`.github/workflows/ci.yml:8`, `:11`). A future release job would change this and must be
  re-reviewed before it is added.
- *Denial of service*: a wedged fuzzer is bounded by `timeout-minutes: 20`
  (`.github/workflows/ci.yml:28`), and each subprocess `doccheck` spawns has its own
  `TOOL_TIMEOUT_S` (`tools/doccheck.py:609`).

**Client to game (planned, no code yet).** The adversaries and scenarios in the next section are
the design for this boundary. They are unmitigated by construction until Phases 1 and 2 land.

## Threats the code's history already demonstrates

- **Unvalidated path components.** This class was live and was fixed: `verify_dir` now refuses a
  traversing `--index` (`tools/evidence_check.py:362`) and the manifest's `indexFile` is checked
  the same way (`tools/evidence_export.py:445`). The same validator is now the single gate for
  every untrusted name that reaches the filesystem, which is why threat 3 (`--out`) is the
  remaining instance of the class: `--out` is a directory, not a name, and never passes through
  that gate.
- **Unkeyed integrity claims.** The docs and the code agree that the chain does not prove
  authorship (`SECURITY.md`). The failure mode to watch is a future reader treating "the chain
  verifies" as "the evidence is authentic".
- **Generated-file drift.** A single YAML source feeding two generated files is a recurring
  failure mode; the registry-sync check exists because of it.
- **Ordering that carries the safety.** The restore drill's index join is safe only because the
  archive verify runs first (boundary 4 above). A reordering would not fail any existing test.
- **Documentation drift.** Every line reference in the prior revision of this document was
  re-verified in this pass and most were stale, and one absent-surface claim (no `urllib` import)
  was contradicted by `tools/doccheck.py:55`. A security document whose references no longer
  resolve is worse than a short one, because a reader cannot tell which parts are still true.

## Abuse cases

- A hostile but authenticated player is not the shipped threat; no runtime exists. In the design,
  the abuse shapes are quota bypass by batching within individual hard limits, resource
  exhaustion through repeated cheap requests, scraping the review surface for another player's
  timeline, and gaming the workflow by inducing findings against a victim so the enforcement lands
  on them (attack scenarios below). Each maps to a detector family in DETECTORS.md.
- Client-side enforcement is trusted nowhere: every scenario in the table below is resolved on the
  server, which is the entire premise of the design.
- Today, the realistic abuse is against the tooling, not the game: an attacker with write access
  to a shared evidence directory, or an operator tricked into pointing `--out` or `sbom --out` at a
  path that matters. Both are recorded as threats 3 and 4 and neither is fixed here.

## Attack scenarios

Concrete narratives for the planned runtime; each maps to an adversary below and a detector
family in DETECTORS.md. None is demonstrated here, and none is mitigated by shipped code.

| Scenario | Exploit | Signal and response |
|---|---|---|
| Teleport skip | During a chunk stall, a client sends `EntityTeleport` to cover ground it never moved | Movement: teleport without a server-issued capability token. Hard once all origins are enumerated, else Strong; stock >8 m deltas remain ordinary discontinuities |
| Stack overflow | Client claims a stack of 100 for an item whose authoritative stack limit is 50 | Inventory: stack exceeds item definition (Hard, `correct`) |
| Replayed transaction | Client replays a container move twice | Inventory: session-scoped idempotency (Hard); the second application is a no-op |
| Induced findings | Attacker repeatedly knocks a victim to push movement debt onto them | Attribution: impulses initiate on the attacker; findings attribute to the initiator or suppress, never the victim |
| Flood and join churn | High-fan-out or malformed request flood to starve the game thread | Availability: cost-weighted token buckets, `throttle`; never counts toward enforcement |
| Privilege reuse | Debug/creative/godmode action without admin permission | Protocol: permission checked at execution point (Hard) |
| Review-surface theft | Stolen dashboard session or spoofed webhook alert | Review-surface: authenticated dashboard, evidence IDs only, alert sink off the game thread (Phase 3 and 8; unbuilt) |

## Adversaries

- A modified client that sends validly encoded but impossible or unauthorized requests.
- A client that manipulates movement, timing, fire cadence, reach, inventory, crafting, or loot.
- A bot that automates repetitive gameplay while remaining within individual hard limits.
- A player abusing a vanilla duplication, rollback, disconnect, or transaction race.
- A stolen or shared account. Identity history is evidence, not proof of the human operator.
- A malicious mod or administrator. The DLL cannot defend against code with equal server trust.
- A packet flood or join churn. Host firewall and rate limiting remain part of defense in depth.
- A player weaponizing the anti-cheat itself: inducing findings against a victim (container
  races, explosion knockback, session games) to trigger corrections or enforcement on them.
- An attacker targeting the review surface: dashboard authentication bypass or session theft,
  and interception of webhook alert endpoints.
- An attacker with filesystem access to the evidence directory, who does not need to be a player
  at all. This one is realizable today and is the reason threats 1 and 2 outrank the rest.

## Response readiness

- **Audit trail for the tooling.** The evidence chain is the audit trail
  (`tools/evidence_check.py`), and it has the last-record gap in threat 1. There is no separate
  log of who ran `evidence_export.py` with which `--out`: the archive manifest records hashes and
  byte counts, not the operator or the time (`tools/evidence_export.py:242`).
- **Path from report to fix.** [SECURITY.md](../SECURITY.md) names the contact, the in-scope
  classes, coordinated disclosure, and the rule that Hard-invariant fixes ship with a regression
  fixture. What is not written down anywhere is the internal path: which phase absorbs a reported
  finding, and what the reporter is told after triage. Inventing that here would be worse than
  the gap.
- **Release gates.** `make ci` is the gate (black, ruff, mypy, doccheck, replay contract,
  self-tests, fuzzers) and runs in CI (`.github/workflows/ci.yml:57`).
- **Owner and cadence.** Not defined in this repository. The last-reviewed date at the top of this
  document is the only freshness signal here; if you add a cadence, add the person or team that
  owns it too.

## Out of scope

- Client memory, process, module, screenshot, input-device, or kernel inspection.
- Deobfuscating or bypassing EAC.
- Preventing information disclosure already sent by the stock game protocol.
- Automatically proving aimbot, ESP, or wallhack use from behavioral coincidence.
- Moderating ordinary chat content. Spam rate can be availability evidence; content policy is separate.
- Protecting against a compromised host, malicious server admin, or malicious same-process DLL.
- Network-level volumetric denial of service, which belongs to the host firewall (SECURITY.md).
