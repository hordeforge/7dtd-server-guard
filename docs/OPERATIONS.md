# Operations and incident runbook (draft)

This document is a requirements-level runbook: the operator workflows the product must
support, written now so the Response, Evidence, and console components
([ARCHITECTURE.md](ARCHITECTURE.md)) are designed against them. The procedures below are
validated and finalized in Phase 9; until then they are design requirements, not
instructions for a shipped product.

## Roles

- **Operator**: runs the server and holds this deployment's evidence, identity map, and
  HMAC key. All appeals and reviews go to the operator, never the mod maintainer
  ([POLICY.md](POLICY.md) -> Roles and appeals).
- **Reviewer**: same person as the operator on a single-operator deployment; the mitigations
  are the dry-run diff and the disposition record (POLICY.md -> Roles and appeals).

## Before enabling anything

1. Post the monitoring notice ([PRIVACY.md](../PRIVACY.md)) in the server rules/MOTD/Discord
   and substitute the operator's own contact.
2. Verify the config hash and hook manifest hash against the release notes. No command
   does this yet: `make check` is a repository docs and schema gate, and the release-artifact
   verifier is a Phase 9 requirement (this runbook is a requirements document, see the
   preamble). Until it exists, compare the values the health report prints by hand.
3. Start in observe mode. Confirm the health report shows every detector `active` and the
   hook manifest resolved fully on the pinned build.
4. For each detector to raise: run its legal-context matrix (TEST_PLAN.md Layer 5), review
   the dry-run diff (what *would* have happened), then enable with explicit opt-in
   ([POLICY.md](POLICY.md) -> Enforcement gates). One corrective invariant per run.

## Routine checks

- Weekly: review the health record for self-disabled hooks, faults, queue drops, and
  correction suspensions; each is a signal of a compatibility or tuning problem, not a
  player accusation.
- Weekly: review new findings with disposition `benign` or `uncertain` and export confirmed
  false positives to the regression corpus (TEST_PLAN.md Layer 7).
- Monthly: confirm evidence rotation, retention expiry, and HMAC key rotation are running;
  spot-verify a tombstone keeps the chain verifiable; run the restore drill and the archive
  verification below (Backup and restore).

## Incident response

| Incident | Immediate action | Follow-up |
|---|---|---|
| False hard-reject on a legal player | Note evidence ID; `sg detector set <id> observe` for that detector; tell the player the override is in place | Export the trace to the regression corpus; fix ships with failing-then-passing trace |
| Correction loop on one entity | The design auto-suspends corrections past the burst limit (ARCHITECTURE.md); verify the suspension in the health report | Review the detector's uncertainty windows and contexts |
| Hook self-disables at runtime | Detector reverts to unavailable; confirm via health report | Check for a game update or co-patch change; re-run metadata-contract tests |
| Evidence queue full / drops | Soft observations dropped first by design; check `serverguard.queue.*` metrics | Review flood config and evidence writer throughput |
| Suspected anti-cheat weaponization (induced findings) | Check attribution: findings must name the initiating connection, never the victim (POLICY.md -> Enforcement gates) | Review container-race and impulse fixtures; verify victim accrued nothing |
| Emergency | `sg emergency-disable` reverts all detectors to observe without restart | Audit log records actor, timestamp, reason; investigate before re-enabling |
| Evidence tampering suspected | Verify the hash chain from segment start to end; a broken link names the first tampered record | If keyholder is suspected, the chain cannot prove against them (ARCHITECTURE.md -> Evidence model); rotate key and identity map |

## Appeal flow

1. Player receives rule and evidence ID (kick message, quarantine notice, or ban reason).
2. Operator resolves the pseudonym via the identity map, reviews the evidence timeline and
   contextual values.
3. Operator records a disposition: `confirmed`, `benign`, `uncertain`, or `detector bug`
   (POLICY.md -> Roles and appeals; labeling method in [METHODOLOGY.md](METHODOLOGY.md) -> Labeling).
4. `benign` and `detector bug` export to the regression corpus; `confirmed` may keep the
   action; `uncertain` lowers the detector or narrows its context until resolved.
5. Every disposition is an `audit` record. A player erasure request follows
   [PRIVACY.md](../PRIVACY.md) (tombstones preserve the chain; the audit log records the
   purge).

## Console commands

Required surface for the operator-facing workflows above; every command is permissioned
(`console.permissionLevel` in [SCHEMAS.md](SCHEMAS.md)), audited via the audit log, and
never prints secrets or raw identities (pseudonyms only).

| Command | Purpose | Audited |
|---|---|---|
| `sg status` | Health report: per-detector state, faults, queue depth, drops, uptime | no |
| `sg detector list` | Registry IDs with current mode, ceiling, and context list | no |
| `sg detector set <id> <mode> [reason]` | Per-detector override; lowering is instant, raising requires the gates | yes |
| `sg findings <entityId> [--since <h>]` | Review findings for one entity (pseudonym resolution only during review) | no |
| `sg evidence export <path>` | Pseudonymous export of chained segments | yes |
| `sg review <evidenceId> <disposition> [reason]` | Record appeal disposition; `benign`/`detector bug` export to the regression corpus | yes |
| `sg dry-run <id>` | Show what *would* have happened in the target mode without changing mode | no |
| `sg purge <evidenceId>` | Tombstone a record; requires a review disposition | yes |
| `sg config reload` | Strict reload with the same validation as startup | yes |
| `sg emergency-disable` / `sg emergency-enable` | Revert all detectors to observe / restore configured modes | yes |

## Webhook alert payload

The optional alert sink receives finding notifications off the game thread. Payloads carry
evidence IDs only, never player identity:

```json
{ "type": "finding", "evidenceId": "9f2c...", "detectorId": "movement.displacement",
  "severity": "strong", "mode": "observe", "utc": "2026-07-21T12:34:56.789Z" }
```

The webhook URL comes from `SERVERGUARD_WEBHOOK_URL` (SCHEMAS.md config), never a config
file. Interception or spoofing of the endpoint is an in-scope report class
([SECURITY.md](../SECURITY.md)).

## Backup and restore

The evidence directory, the identity map, and the HMAC key are the only state the
operator cannot regenerate. All three live on the server's local disk, the evidence
directory is gitignored, and retention expiry deletes segments, so a lost disk is an
unrecoverable loss of every finding, disposition, and audit record this deployment
made. The procedures below are the recovery contract; the storage that holds the
archives is the operator's choice and must be named in the deployment notes.

### Targets

| RPO | RTO | Meaning |
|---|---|---|
| Evidence: 24 h | 4 h | Worst case: evidence written since the last successful archive is lost, and recovery takes one archive restore plus a chain verification |
| Identity map and HMAC key: per backup cycle, never longer than 7 days | 1 h | A pseudonym epoch whose key is lost can never be resolved again; the affected evidence becomes permanently unattributable |
| Config: per upgrade | minutes | `server-guard.json` and the local override are copied on every upgrade |

An archive counts as existing only when `make verify-archive ARCHIVE=<dir>` exits 0.
A scheduled copy whose exit code nobody checks is not a backup.

### What gets archived, and what does not

`make export-evidence DIR=<evidence-dir> OUT=<archive-root>` copies every
`evidence-*.jsonl` segment and the segment index, after verifying the hash chain and
re-verifying the copies, and writes `archive-manifest.json` with a per-file SHA-256
and byte count, plus a `manifestSha256` over the rest of the manifest. The per-file
digests prove the archived bytes; the self-digest proves the attestation describing
them, so a manifest edited in place (a rewritten source path, a corrected record
count) is reported instead of verifying clean. A manifest without that field is
manifest version 1 and is not verifiable by this tool. It refuses to run on a chain
that does not verify, on a zero-byte segment, and on a copy that does not match the
source, so a failed write can never be recorded as a successful backup.

The identity map and the HMAC key are archived separately, under different
credentials, in a different failure domain than the evidence they explain. A single
stolen archive containing both would turn every pseudonym in it into a named player.

### Schedule

- Every 24 h: `make export-evidence` for the live evidence directory, then copy the
  resulting archive off the server. Alert on a non-zero exit and on a missing
  archive for a scheduled run; a silent archive is a missed backup, not a clean one.
- Every 7 days: copy the identity map and the HMAC key to the separate store.
- Before any retention expiry or purge: archive the affected segments first. Expiry
  and purge are the only mass-deletion paths in the system, and the archive is the
  undo.
- Monthly: restore drill (below), and confirm the archives for the last 30 days are
  present and verify.

### Restore

1. Stop the server. Never restore over a running store: the evidence writer holds the
   active segment, and the restored chain would be extended from a record the restore
   does not contain.
2. Move the current evidence directory aside rather than deleting it. It is evidence.
3. Copy the archive's segments and index into the configured `evidence.dir`, keeping
   the file names: the cross-segment links are name ordered, and a rename breaks the
   chain.
4. Restore `hmac.key` before the identity map. Pseudonym resolution fails closed
   without the key, and a map restored under a different key epoch resolves to the
   wrong players.
5. `make verify-evidence DIR=<evidence-dir>`. A broken link names the first record that
   does not chain; stop and use the next archive rather than editing records. A repeated
   `eventId` names a record the writer appended twice; the archive still holds the event,
   so restore it and let the writer's duplicate suppression be the fix.
6. Start the server and confirm the health report and the oldest finding resolve.
7. Keep the moved-aside directory until the restored chain verifies and the operator
   has confirmed the appeals record reads correctly.

### Restore drill

Monthly, into a scratch directory on a machine that is not the production server:
`make verify-archive ARCHIVE=<dir>`, then copy the archive into an empty directory,
run `make verify-evidence` against the copy, and open a recent finding. Record the
date and the result in the deployment notes. An archive that has never been restored
is a hypothesis, and the first real restore is the worst possible time to discover a
missing key or a renamed segment.

## Upgrade and rollback


- Upgrade path: stop the server, archive `ServerGuard/` with
  `make export-evidence DIR=<evidence-dir> OUT=<archive-root>` plus a separate copy of the
  identity map, HMAC key, and config, replace the DLL, run the config migration tool if the
  schema changed ([SCHEMAS.md](SCHEMAS.md) -> Schema evolution), restart, verify the health
  report.
- Rollback: replace the previous DLL and config; evidence written by the newer version is
  read-only to the older one (schema mismatch refuses, it does not guess). The older build
  must not overwrite newer segments; verify before restoring.
- Enforcement families require explicit opt-in again after any upgrade
  ([TODO.md](../TODO.md) Phase 10 exit).

## Disclosure

Follow [SECURITY.md](../SECURITY.md). Do not include real players' pseudonym-to-identity
mappings, auth tickets, or raw packet captures in reports.
