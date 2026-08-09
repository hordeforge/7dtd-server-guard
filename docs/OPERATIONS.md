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
