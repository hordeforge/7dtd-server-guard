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
2. Validate the config file before it reaches the server:
   `make verify-config FILE=config/server-guard.local.json`. It rejects unknown keys, a
   misspelled detector id, a threshold outside the manifest's declared range, a temp-ban
   permitted with the kick gate closed, a path escaping the data root, and an
   enabled webhook or dashboard whose environment variable is unset. A non-zero exit means
   the file is not deployable; the mod would refuse the same file at startup
   ([SCHEMAS.md](SCHEMAS.md) -> Config schema). Add `SHOW_EFFECTIVE=1` to also print the
   effective config's hash, which step 3 compares by hand.
3. Verify the config hash and hook manifest hash against the release notes. No command
   does this yet: `make check` is a repository docs and schema gate, and the release-artifact
   verifier is a Phase 9 requirement (this runbook is a requirements document, see the
   preamble). Until it exists, compare the values the health report prints by hand. The
   config hash `make verify-config FILE=<path> SHOW_EFFECTIVE=1` prints is the one the
   evidence records and the health
   report carry, so the two can be compared directly.
4. Start in observe mode. Confirm the health report shows every detector `active` and the
   hook manifest resolved fully on the pinned build.
5. For each detector to raise: run its legal-context matrix (TEST_PLAN.md Layer 5), review
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
| Server refuses to start on a config change | Startup rejected the file whole, so nothing ran under a relaxed config; the log names the first violations | `make verify-config FILE=<same file>` reproduces the verdict off-server, or `sg config check` on a live server |
| Evidence tampering suspected | Verify the hash chain from segment start to end; a broken link names the first tampered record | If keyholder is suspected, the chain cannot prove against them (ARCHITECTURE.md -> Evidence model); rotate key and identity map |

## Appeal flow

1. Player receives rule and evidence ID (kick message, quarantine notice, or ban reason).
2. Operator resolves the pseudonym via the identity map, reviews the evidence timeline and
   contextual values.
3. Operator records a disposition: `confirmed`, `benign`, `uncertain`, or `detector-bug`
   (POLICY.md -> Roles and appeals; labeling method in [METHODOLOGY.md](METHODOLOGY.md) -> Labeling).
4. `benign` and `detector-bug` export to the regression corpus; `confirmed` may keep the
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
| `sg evidence export <path>` | Pseudonymous export of chained segments | no |
| `sg review <eventId> <disposition> [reason]` | Record appeal disposition; `benign`/`detector-bug` export to the regression corpus | yes |
| `sg dry-run <id>` | Show what *would* have happened in the target mode without changing mode | no |
| `sg purge <eventId>` | Tombstone a record; requires a review disposition | yes |
| `sg config show` | The effective config as loaded, under the `configHash` every evidence record carries. Secret env var names, never their values | no |
| `sg config check [path]` | Validate the deployed file without reloading; reports exactly what startup would refuse | no |
| `sg config reload` | Strict reload with the same validation as startup | yes |
| `sg emergency-disable` | Revert all detectors to observe | yes |
| `sg emergency-enable` | Restore configured modes | no |

The `yes` rows are the commands that map to an `audit.action` value (SCHEMAS.md -> Audit
log). An export copies records and changes no mode, and re-enabling is the absence of the
disable the audit log already records, so neither has an action to write.

## Webhook alert payload

The optional alert sink receives finding notifications off the game thread. Payloads name the
record by its `eventId` and carry no player identity:

```json
{ "type": "finding", "eventId": "a2e00258-5c85-4bdf-97d1-a68ff9910d41",
  "detectorId": "movement.displacement", "severity": "strong", "mode": "observe",
  "utc": "2026-07-21T12:34:56.789Z" }
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
| Config: per upgrade | minutes | The deployed `server-guard.json` and the gitignored working copy (`config/server-guard.local.json`) are copied on every upgrade |

An archive counts as existing only when `make verify-archive ARCHIVE=<dir>` exits 0.
A scheduled copy whose exit code nobody checks is not a backup. `make backup-status
ROOT=<archive-root>` is the read-only check for the case neither the copy nor the
verifier can see: it verifies the archives newest first and exits non-zero when the
newest one that verifies is past the 24 h window, when a newer archive does not
verify, when the root holds none, and when two adjacent archives are more than the
window apart. That last one is a run that never landed: a root holding a
three-hour-old archive and a ten-day-old one is fresh, and the nine days between
them are unarchived with no failing exit code to show for it. Age comes from the
archive manifest's `createdUtc`, not the directory timestamp, which copying off the
server resets. A `createdUtc` later than the clock the check runs on is reported
too: the archive verifies, but it is dated to an instant that has not happened, so
its age is negative and no window comparison can read it as anything but fresh. It
cannot open the window, and the RPO is unproven until the exporting host's clock
and the checking host's agree. Run it on the same schedule as the export, against
the archive root the operator actually keeps off the server.

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

The archive name carries a one-second stamp, so a retried export lands on the
directory the first attempt wrote. A retry that finds that archive holding exactly the
segments and index it would have copied exits 0 and writes nothing: the retry is a
no-op, not a second archive and not a failed backup. A retry that finds a different
evidence set under that name is refused, because that is a different export and must
not replace an archive the operator may already have copied off the server. The same
rule settles two exports naming the same archive at once: the one that loses the race
applies it against the archive the winner wrote, so the loser exits 0 on identical
evidence and is refused on different evidence. Each
export stages into its own directory, so two exports running at once cannot delete
each other's copy in progress. A staging directory left by a run that died is removed
by the next export into that root, whichever second it died in and including a run that
converged on an archive it had already written, so a root whose exports keep retrying
does not accumulate a second copy of the evidence stream per death.

The identity map and the HMAC key are archived separately, under different
credentials, in a different failure domain than the evidence they explain. A single
stolen archive containing both would turn every pseudonym in it into a named player.

### Schedule

- Every 24 h: `make backup DIR=<evidence-dir> OUT=<archive-root>` for the live evidence
  directory, then copy the resulting archive off the server. The target archives and
  re-verifies in one step and exits non-zero when the chain did not verify or the copy
  did not match, so a scheduler that alerts on the exit code covers the whole run. A
  silent archive is a missed backup, not a clean one; `make backup-status` on the same
  schedule is what turns a scheduler that stopped running into a reported failure.
- Every 7 days: copy the identity map and the HMAC key to the separate store. The
  drill below reports either one as missing or older than this cycle, which is how a
  copy that quietly stopped running becomes visible.
- Before any retention expiry or purge: archive the affected segments first. Expiry
  and purge are the only mass-deletion paths in the system, and the archive is the
  undo.
- Monthly: restore drill (below), and confirm the archives for the last 30 days are
  present and verify. `make backup-status` on the archive root is the same check in
  one command, and belongs on the 24 h schedule as well.

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
5. Restore the config the evidence was written under, not the one currently on disk.
   Every record carries the `configHash` of the effective config in force when it was
   written, so a restored chain is attributable to a config; a config that hashes to
   something no restored record carries is not the one those findings were produced
   under, and its thresholds and `evidence.dir` are not the ones the evidence means.
   The copy kept on every upgrade is the one to reach for; if it is gone, the archive
   still names the hash to search the release history for.
6. `make verify-evidence DIR=<evidence-dir>`. A broken link names the first record that
   does not chain; stop and use the next archive rather than editing records. A repeated
   `eventId` names a record the writer appended twice; the archive still holds the event,
   so restore it and let the writer's duplicate suppression be the fix.
7. Start the server and confirm the health report and the oldest finding resolve.
8. Keep the moved-aside directory until the restored chain verifies and the operator
   has confirmed the appeals record reads correctly.

### Restore drill

Monthly, into a scratch directory on a machine that is not the production server:
`make drill-restore ARCHIVE=<dir> WORK=<empty-dir> [CONFIG=<config-file>]`.

The target verifies the archive against its manifest, copies its segments and index
into `WORK` under their own file names, re-verifies the hash chain over the copy, and
reads the oldest and newest records back out, printing their types and event IDs. With
`CONFIG` it also checks that the config is the one the restored evidence was written
under: every record carries the `configHash` of the effective config in force when it
was written, so a config that hashes to a value no restored record carries is
reported instead of paired with findings that were never produced under it. It then
resolves `identityMap.path` and `hmacKey.path` (a relative one against the config
file's own directory, or against `--runtime-root`) and fails when either
is missing, zero bytes, older than the 7-day copy cycle, or stamped with an mtime
later than the current time, so a drill cannot pass on
an archive that restores records nobody can attribute. The config is hand-edited on
the Windows host that runs the server, so both separators are read as separators:
`keys\hmac.key` and `keys/hmac.key` are the same file here. A drive-qualified path
names the server host, which a drill run elsewhere cannot open, and is reported
rather than resolved against the runtime root. Without `CONFIG` the verdict
says so, so the drill record does not imply a cross-check that never ran. `WORK` must
be empty or absent;
a directory that still holds files is refused rather than merged into, because a
restore that silently keeps a stale segment is the failure this exists to catch. The
copy is staged in a directory beside `WORK` and moved into place only once the chain
verifies over it, so a drill that fails anywhere leaves `WORK` as it found it and the
same command can simply be run again. The live evidence directory is never touched. A
non-zero exit is a failed drill: record the date, the archive name, and the result in
the deployment notes.

An archive that has never been restored is a hypothesis, and the first real restore
is the worst possible time to discover a missing key or a renamed segment.

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
