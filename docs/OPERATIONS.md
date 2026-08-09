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
2. Run `make check` on the shipped release artifacts and verify the config hash and hook
   manifest match the release notes.
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
  spot-verify a tombstone keeps the chain verifiable.

## Incident response

| Incident | Immediate action | Follow-up |
|---|---|---|
| False hard-reject on a legal player | Note evidence ID; `sg override <detector> observe` for that detector; tell the player the override is in place | Export the trace to the regression corpus; fix ships with failing-then-passing trace |
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
   (POLICY.md -> Roles and appeals).
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

## Upgrade and rollback


- Upgrade path: stop the server, back up `ServerGuard/` (evidence, identity map, HMAC key,
  config), replace the DLL, run the config migration tool if the schema changed
  ([SCHEMAS.md](SCHEMAS.md) -> Schema evolution), restart, verify the health report.
- Rollback: replace the previous DLL and config; evidence written by the newer version is
  read-only to the older one (schema mismatch refuses, it does not guess). The older build
  must not overwrite newer segments; verify before restoring.
- Enforcement families require explicit opt-in again after any upgrade
  ([TODO.md](../TODO.md) Phase 10 exit).

## Disclosure

Follow [SECURITY.md](../SECURITY.md). Do not include real players' pseudonym-to-identity
mappings, auth tickets, or raw packet captures in reports.
