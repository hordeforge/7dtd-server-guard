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
| 1 | Evidence chain cannot detect tampering with the final record of the last segment | `tools/evidence_check.py:237` | Evidence repudiation: a moderator's timeline ends at a rewritten record | Unmitigated by design, inherent to an append-only chain |
| 2 | The evidence chain is unkeyed in the shipped tooling, so anyone with write access to the evidence directory can re-chain an entire segment set | `tools/evidence_check.py:78` (sha256, no MAC); HMAC and the identity map are `TODO.md:108`, unimplemented | Tampering, spoofing, repudiation of the whole audit trail | Unmitigated; scheduled for Phase 3 |
| 3 | Pseudonym re-identification keys have no runtime protection because no runtime exists | `config/schemas/config.v1.schema.json:151`, `docs/SCHEMAS.md:63`; no `os.chmod` anywhere in `tools/` | Information disclosure: platform IDs map back to players from any readable evidence copy | Unmitigated; scheduled for Phase 3 |
| 4 | `--index` is joined to the evidence directory without name validation, so a crafted value reads a file outside it | `tools/evidence_check.py:179`, `tools/evidence_export.py:118`; the fix already exists in the sibling function `tools/evidence_export.py:189` | Information disclosure, bounded: the value is only JSON-parsed and failures are reported, not raised | Unmitigated; hand to sec-review |
| 5 | `--out` is used verbatim for directory creation and for a recursive delete of the staging directory, with no check that the target is the intended archive root | `tools/evidence_export.py:171`, `:175`, `:185` | Tampering and denial of service against an operator-chosen path | Unmitigated; hand to sec-review |
| 6 | Self-tests and fuzzers create and recursively delete paths inside the repository, and run in CI | `tools/evidence_export.py:329`, `:330`, `:338`; `tools/fuzz_evidence_check.py:197` | Denial of service to a checkout; a wedged or slow fuzzer burns the CI budget | Bounded by `.scratch` and a 20 minute CI timeout (`.github/workflows/ci.yml:19`) |
| 7 | Generated thresholds and the detector registry are rewritten from one YAML file, so editing the spec silently changes config defaults and published tables | `tools/render_detectors.py:78`, `:209`, `:220` | Tampering: a lower threshold becomes a default in shipped config | Mitigated: `tools/doccheck.py:338` fails when the generated files drift from the spec |
| 8 | Every in-game control this document previously listed as present (permissioned console, permission-restricted evidence files, dashboard auth, webhook) has no implementation | `TODO.md:108`, `:112`, `:189`, `:192` | A false mitigation claim is worse than a named gap: a reader builds on a control that does not exist | Fixed in this document; the surface is now marked planned |

## Shipped attack surface

This is the entire executable surface today. Every entry is a local CLI invoked by an operator or
by CI, never a network listener. There is no HTTP endpoint, no listener, no message consumer, no
webhook, and no IPC in the tree.

| Entry point | Untrusted input | Reads | Writes |
|---|---|---|---|
| `tools/evidence_check.py:291` (`--dir`, `--sample`, `--self-test`, `--index`) | Evidence JSONL segments and the segment index, produced by the runtime or by an attacker who reached the evidence directory | `tools/evidence_check.py:176`, `:179`, `:53` | none |
| `tools/evidence_export.py:342` (`--dir`, `--archive`, `--out`, `--index`, `--self-test`) | Evidence segments, an archive manifest, and the member names inside it | `tools/evidence_export.py:80`, `:216` | `tools/evidence_export.py:139`, `:156`, `:171`, `:181` |
| `tools/doccheck.py:845` (no flags) | The repository tree itself, treated as content to lint rather than as instructions | `tools/doccheck.py:57`, `:64` | none |
| `tools/render_detectors.py:197` (`--check`, `--manifest`) | `tools/detector_spec.yaml`, parsed with the safe loader | `tools/render_detectors.py:78` | `tools/render_detectors.py:209`, `:220` |
|  `tools/replay_contract_check.py:581` (`--self-test`, `--fix-fingerprint`; paths are fixed constants) | A committed sample trace | `tools/replay_contract_check.py:31`, `:32`, `:597` | none |
| `tools/guard_python.py` (no flags) | `.python-version` | `tools/guard_python.py:15` | none |
| `tools/fuzz_evidence_check.py`, `tools/fuzz_evidence_export.py`, `tools/fuzz_schema_validate.py`, `tools/fuzz_replay_trace.py` (`--iterations`, `--seed`) | Seeds, then self-generated mutations | see each harness | `.scratch` only (`tools/fuzz_evidence_check.py:197`) |
| `.github/workflows/ci.yml` | The repository and the pull-request diff | `runs on: [push, pull_request]`, `.github/workflows/ci.yml:2` | none |

### Surface deliberately absent

These are the properties a reader is most likely to assume and that no shipped code has:

- No network I/O. There is no `socket`, `urllib`, `requests`, or `http` use in `tools/`.
- No deserialization of untrusted data. No `pickle`, no `eval`, no `exec`; both YAML readers use
  the safe loader (`tools/render_detectors.py:78`, `tools/replay_contract_check.py:597`).
- No archive extraction. No `tarfile` or `zipfile`, so the zip-slip class does not exist; the
  archive format is a manifest plus a flat directory, and every member name is validated against
  `[A-Za-z0-9._-]` with `.` and `..` rejected before any filesystem use
  (`tools/evidence_export.py:189`, `:223`).
- No environment variable reads. `webhook.urlEnv` and `dashboard.secretEnv`
  (`docs/SCHEMAS.md:35`, `:81`) are schema declarations for a runtime that does not exist.
- No secret handling in the shipped tooling. The chain is an unkeyed sha256 over canonical JSON
  (`tools/evidence_check.py:74`); no key file, HMAC, or credential is read anywhere in `tools/`.

### Surface from dependencies and CI

- Third-party actions are SHA-pinned with `persist-credentials: false`
  (`.github/workflows/ci.yml:26`, `:32`, `:28`). The runner image is pinned to `ubuntu-24.04`
  (`.github/workflows/ci.yml:17`), not `latest`.
- Workflow permissions are `contents: read` (`.github/workflows/ci.yml:5`) and the trigger is
  `pull_request`, never `pull_request_target` (`.github/workflows/ci.yml:2`), so untrusted PR code
  never runs in a privileged context.
- No CI secret is used: no `secrets.*`, no registry push, no release job. Dependency updates come
  from Dependabot on the `github-actions` and `uv` ecosystems.
- Dependencies resolve from a locked `uv.lock` through `uv sync --frozen`, so a stale lockfile
  fails the run instead of silently re-resolving. Every artifact in the lock carries a sha256,
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
| Harmony hooks on pinned seams, with runtime fault guard and fail-open | 1 to 2 | `TODO.md:92` |

One artifact of the unimplemented state is worth naming: the only shipped replay trace carries
`"hookManifestHash": "UNVERIFIED"` (`tools/fixtures/traces/inventory/stack.v1.sample.json:6`).
The schema permits that sentinel deliberately, alongside a real digest
(`config/schemas/replay-trace.v1.schema.json:27`:
`"^(UNVERIFIED|[0-9a-f]{64})$"`), so the value validates by design rather than slipping past a
loose check, and `tools/replay_contract_check.py` does not require the digest branch. The
consequence to carry forward: a trace whose hash reads `UNVERIFIED` proves nothing about the
build it was recorded against, and nothing in the tree verifies a running server against the
pinned `3.2.0-b9` (`config/server-guard.example.json:6`). The pin is documentary and config-level
until Phase 1 computes a fingerprint (`TODO.md:83`).

## Trust boundaries

Trusted: the dedicated-server process, authoritative world state, the server clock, the installed
mod configuration, evidence keys written locally, and explicit operator actions.

Untrusted: all client-supplied position, rotation, claimed hit, item stack, action timing, display
name, chat, reconnect state, and network ordering outside the server's validated state.

Conditionally trusted: game APIs and other mods. Every hook is build-pinned and fails open in
observe mode. Compatibility exceptions must be named and measured, never hidden in a global
threshold increase.

The boundaries that exist in shipped code today, with what crosses them:

1. **Operator to tool.** `--dir`, `--out`, and `--index` are the whole operator-controlled input
   surface. `evidence_check.py` and `evidence_export.py` act on paths from these flags with the
   authority of the invoking user, and `evidence_export.py` both creates and deletes directory
   trees. Threats 4 and 5 above live here.
2. **Evidence directory to verifier.** A JSONL segment set and a `segment-index.json` are read as
   if authored by the runtime, but the directory is ordinary local storage. Nothing binds the
   segments to a key, and the index's `file` entries are compared as strings and never opened
   (`tools/evidence_check.py:205`), so a hostile index name is not itself a traversal. Threats 1
   and 2 live here.
3. **Archive to restore drill.** `--archive` takes a directory whose manifest names its members.
   This is the only boundary where names become filesystem paths, and it is the one that is
   validated (`tools/evidence_export.py:189`, `:223`).
4. **Repository content to generated artifacts.** `tools/detector_spec.yaml` is the single source
   of truth; `tools/render_detectors.py` writes both the config manifest and the registry table
   inside `docs/DETECTORS.md` from it. Editing the spec is a repository change, and
   `tools/doccheck.py:338` fails the build when the generated files disagree with it.
5. **Pull request to CI.** Untrusted code runs on `ubuntu-24.04` under `contents: read` with
   SHA-pinned actions and no secrets. This is a build boundary with no production privilege
   behind it, which is the property to preserve if the workflow ever gains a release step.

### Secrets flow

No secret enters the shipped tooling. There is no environment read, no key file, and no
credential anywhere in `tools/`. The planned flow, for a later pass to verify once Phase 3 lands:
the HMAC key and the identity map are files created locally at `0600` and declared in
`config/schemas/config.v1.schema.json:151`, and the webhook URL arrives through an environment
variable name rather than the config file (`docs/SCHEMAS.md:81`) so the URL never lands in a
committed file. Rotation starts a new chain segment set (`docs/DECISIONS.md:81`).

## Assets and impact

| Asset | Class | Why it is worth attacking | Concrete blast radius |
|---|---|---|---|
| Evidence segments and index | Integrity, availability | The basis for every moderator decision; a false hard-reject denies legitimate play | A rewritten final record removes the last event from a decision timeline (`tools/evidence_check.py:237`) |
| HMAC pseudonym key and identity map | Confidentiality, integrity | The re-identification key; pseudonyms are worthless once platform IDs map back | De-anonymization of every retained record, not just the operator's copy |
| Detector spec and generated config | Integrity | Lowering a threshold changes what the server rejects for every player | A fleet-wide false-reject rate on ordinary play |
| Build pin and hook manifest | Integrity | Hooks resolve against a specific Mono build; a wrong pin means the wrong method is patched | Either hooks silently no-op, leaving the server unprotected, or a fault on the game thread |
| Server game thread | Availability | Every detector runs inside the process that serves players | A hang or fault is a server outage for every player, not one session |
| Moderator reputation and player trust | Reputational | Enforcement decisions are visible and hard to reverse | A single wrong enforcement attributed to a player, made from a tampered timeline |

## Threats per boundary

STRIDE classes per boundary, tied to the entry points above. Each is a named threat with a
location, not a checklist.

**Operator to tool (evidence CLI).**
- *Information disclosure*: a crafted `--index` escapes the evidence directory and the target is
  read and JSON-parsed (`tools/evidence_check.py:179`, `tools/evidence_export.py:118`). Bounded
  by the parser: a non-JSON target yields a parse error, not its contents.
- *Tampering and denial of service*: `--out` reaches `mkdir` and a recursive delete without
  validation (`tools/evidence_export.py:171`, `:175`, `:185`).
- *Repudiation*: an operator can archive a chosen evidence set and the archive is indistinguishable
  from a complete one, because no signature binds an archive to the segment set it came from
  (`tools/evidence_export.py:156` writes the manifest, and nothing signs it).

**Evidence directory to verifier.**
- *Tampering and spoofing*: the chain is an unkeyed sha256 (`tools/evidence_check.py:78`), so an
  attacker with write access recomputes the whole chain rather than breaking it. The chain proves
  the file was not edited without recomputation; it does not prove who wrote it.
- *Repudiation*: the last record of the final segment has no successor hash to check against, so
  it is mutable until the next append (`tools/evidence_check.py:237`).
- *Information disclosure*: an evidence file that reaches a backup or an archive carries
  pseudonymous records whose re-identification key has no enforced permissions today
  (`docs/SCHEMAS.md:63`).

**Archive to restore drill.**
- *Tampering*: mitigated. Every member name and the index name are validated before use
  (`tools/evidence_export.py:189`, `:216`, `:223`), hashes and byte counts are compared
  (`:233`, `:235`), unlisted extra files are reported (`:237`), and the chain is re-verified inside
  the archive (`:247`).
- *Denial of service*: bounded by the per-entry name length cap
  (`MAX_MEMBER_NAME_LEN`, `tools/evidence_export.py:53`).

**Repository content to generated artifacts.**
- *Tampering*: mitigated by the registry-sync check (`tools/doccheck.py:338`) and the config
  schema cross-reference (`tools/doccheck.py:665`), both in `make check`.

**Pull request to CI.**
- *Elevation of privilege*: not present today. `pull_request` with `contents: read` and no
  secrets (`.github/workflows/ci.yml:2`, `:5`). A future release job would change this and must be
  re-reviewed before it is added.
- *Denial of service*: a wedged fuzzer is bounded by `timeout-minutes: 20`
  (`.github/workflows/ci.yml:19`).

**Client to game (planned, no code yet).** The adversaries and scenarios in the next section are
the design for this boundary. They are unmitigated by construction until Phases 1 and 2 land.

## Threats the code's history already demonstrates

- **Unvalidated path components.** The archive path already has a validator
  (`tools/evidence_export.py:189`); the `--index` path does not, on either tool that takes it. The
  fix pattern exists in-tree, so this is a known class, not an unknown one.
- **Unkeyed integrity claims.** The docs and the code agree that the chain does not prove
  authorship (`SECURITY.md:19`). The failure mode to watch is a future reader treating "the chain
  verifies" as "the evidence is authentic".
- **Generated-file drift.** A single YAML source feeding two generated files is a recurring
  failure mode; the registry-sync check exists because of it.

## Abuse cases

- A hostile but authenticated player is not the shipped threat; no runtime exists. In the design,
  the abuse shapes are quota bypass by batching within individual hard limits, resource
  exhaustion through repeated cheap requests, scraping the review surface for another player's
  timeline, and gaming the workflow by inducing findings against a victim so the enforcement lands
  on them (attack scenarios below). Each maps to a detector family in DETECTORS.md.
- Client-side enforcement is trusted nowhere: every scenario in the table below is resolved on
  the server, which is the entire premise of the design.
- Today, the realistic abuse is against the tooling, not the game: an attacker with write access
  to a shared evidence directory, or an operator tricked into archiving an incomplete evidence set
  with `--out` pointed at a path that matters.

## Attack scenarios

Concrete narratives for the planned runtime; each maps to an adversary above and a detector
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
  byte counts, not the operator or the time (`tools/evidence_export.py:156`).
- **Path from report to fix.** [SECURITY.md](../SECURITY.md) names the contact, the in-scope
  classes, coordinated disclosure, and the rule that Hard-invariant fixes ship with a regression
  fixture. What is not written down anywhere is the internal path: which phase absorbs a reported
  finding, and what the reporter is told after triage. Inventing that here would be worse than
  the gap.
- **Release gates.** `make ci` is the gate (black, ruff, mypy, doccheck, replay contract,
  self-tests, fuzzers) and runs in CI (`.github/workflows/ci.yml:38`).
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
