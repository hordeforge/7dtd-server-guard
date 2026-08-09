# Schemas

This document defines the concrete, versioned data contracts the implementation must honor:
the runtime **config**, the **evidence stream**, the **hook manifest**, the **audit log**,
the **health report**, and the **metrics** naming. These are the Phase 2 and Phase 3
"define schema" TODO items, written down before code so the strict-versioning guarantees
in [ARCHITECTURE.md](ARCHITECTURE.md) can be tested against something concrete.

Rules that apply to every schema in this document:

- Every schema carries a `schemaVersion` integer. A consumer that sees an unknown version
  refuses to start (config) or skips and reports (evidence replay), never guesses.
- Unknown keys are rejected, not ignored. Invalid ranges and enums are rejected.
- Every identifier (detector ID, evidence ID, cause token, session epoch) is validated
  against a bounded charset: `[a-z0-9._-]`, max 64 chars.
- No schema ever contains a raw platform identity, IP address, auth ticket, password, or
  full packet body. Identities are HMAC pseudonyms (see [PRIVACY.md](../PRIVACY.md)).
- The file paths below are relative to the mod's data root, which the operator sets in the
  config. Defaults live under the server's `UserDataFolder`-adjacent `ServerGuard/` tree;
  the exact default location is confirmed in Phase 2.

## Config schema (config v1)

File: `server-guard.json` (example in `config/server-guard.example.json`). Loaded at startup,
rejected wholesale on any violation, reloadable by console command with the same checks.

| Key | Type | Default | Range / enum | Meaning |
|---|---|---|---|---|
| `schemaVersion` | int | 1 | exactly 1 | Reject otherwise |
| `enabled` | bool | true | - | Master switch; `false` behaves like emergency disable at startup |
| `emergencyDisable` | bool | false | - | Revert every detector to observe without restart; operator-only, audited |
| `buildPin.buildId` | string | `3.1.0-b14` | exact match | Pinned game build; other builds load with all failing hooks disabled (observe-only) |
| `buildPin.policy` | string | `observe-else` | `observe-else` only in v1 | Behavior on build mismatch |
| `modes.<detectorId>` | string | `observe` | `observe` / `correct` / `enforce` | Per-detector mode; raising requires the phase gates in POLICY.md, never just config editing |
| `actions.correct` | bool | true | - | Permit `correct` transitions for Hard invariants in `correct`/`enforce` modes |
| `actions.quarantine.damage` | bool | false | - | Each quarantine restriction is separately enabled |
| `actions.quarantine.containers` | bool | false | - | Same |
| `actions.quarantine.worldMutation` | bool | false | - | Same |
| `actions.kick` | bool | false | - | Subject to the kick gate in POLICY.md |
| `actions.throttle` | bool | true | - | Availability protection; never counts toward enforcement |
| `thresholds.<detectorId>.<key>` | number/string | per detector | per detector | Placeholder until Phase 10 calibration; every key must be declared in the detector's config manifest |
| `evidence.dir` | string | `ServerGuard/evidence` | writable | Append-only JSONL segments |
| `evidence.retentionDays` | int | 30 | 1..365 | Segment expiry |
| `evidence.rotationSizeMB` | int | 64 | 1..1024 | Rotate at this size or at day boundary |
| `evidence.positionHistoryDays` | int | 7 | 0..90 | 0 disables replay history |
| `evidence.positionHistorySamplesPerPlayer` | int | 3600 | 0..20000 | Bounded replay timeline |
| `identityMap.path` | string | `ServerGuard/identity-map.json` | restricted perms | Pseudonym -> platform identity, operator-only |
| `identityMap.permissions` | string | `0600` | POSIX octal | Enforced at startup on POSIX hosts |
| `hmacKey.path` | string | `ServerGuard/hmac.key` | restricted perms | Pseudonym key; destroyed when evidence under it expires |
| `hmacKey.rotationDays` | int | 90 | 1..365 | Starts a new pseudonym epoch |
| `queues.actionQueueMax` | int | 4096 | 64..65536 | Main-thread action queue bound |
| `queues.evidenceQueueMax` | int | 8192 | 64..65536 | Writer queue bound; drop soft first |
| `faultGuard.maxFaults` | int | 5 | 1..100 | Per-hook runtime faults before self-disable |
| `faultGuard.windowSeconds` | int | 300 | 1..3600 | Fault window |
| `correction.cooldownTicks` | int | 20 | 1..600 | Min ticks between corrections on one entity (1 s at 20 TPS) |
| `correction.suspendWindowTicks` | int | 200 | 1..3600 | Suspend corrections for an entity past the burst limit |
| `correction.maxPerWindow` | int | 3 | 1..100 | Burst limit per entity per window |
| `availability.burst` | int | 200 | 1..100000 | Initial per-connection token burst (placeholder) |
| `availability.refillPerSecond` | int | 40 | 1..10000 | Global refill rate (placeholder) |
| `availability.globalCostPerTick` | int | 2000 | 1..100000 | Cross-connection aggregate cap per tick (placeholder) |
| `availability.cost.<class>` | int | see SIGNALS.md | 1..1000 | Cost class weights; keys are `tiny`, `play`, `state`, `expensive` |
| `console.permissionLevel` | string | `admin` | `admin` / `moderator` | Minimum level for Server Guard console commands |
| `webhook.enabled` | bool | false | - | Optional alert sink |
| `webhook.evidenceIdsOnly` | bool | true | must be true in v1 | No player identity in payloads |
| `dashboard.enabled` | bool | false | - | Ships only after auth and permission tests (Phase 3) |
| `metrics.enabled` | bool | true | - | APM-compatible counters |

Config hash: SHA-256 over the normalized (sorted-key) JSON of the *effective* config,
computed after defaults are applied. The hash is written into every evidence record, the
health report, and the hook manifest so a finding can always be traced to the config that
produced it.

## Evidence stream (evidence v1)

Append-only JSONL, one object per line, hash-chained. Segment files
`evidence-<UTC-date>-<seq>.jsonl` plus a `segment-index.json`. Every record starts with
`schemaVersion`, `type`, and `eventId` (UUID v4). `chainPrev` is the SHA-256 of the
canonical serialization (sorted keys, no whitespace) of the previous record in the chain;
the first record of a segment chains to the last record of the previous segment.

Record types and their extra fields:

| `type` | Purpose | Extra fields |
|---|---|---|
| `finding` | A detector produced a finding | `detectorId`, `detectorVersion`, `severity`, `confidence`, `mode`, `suppressedReason?`, `pseudonym`, `entityId`, `sessionEpoch`, `utc`, `monotonicMs`, `tick`, `tickHealthMs`, `latencyMs`, `context`, `observations` (bounded array), `expected`, `actual`, `causeEventIds`, `action`, `disposition?`, `configHash`, `buildId`, `hookManifestHash` |
| `cause` | A registered mod cause-API invocation | `causeToken`, `modIdentity`, `itemId?`, `delta?`, `sessionEpoch`, `pseudonym`, `causeEventIds` |
| `reconciliation` | Ledger reconciled from durable save after crash/disconnect | `scope` (player/container), `savedAt`, `replayedFrom` (segment range), `deltaItems` (bounded), `marker` |
| `health` | Detector-health snapshot (periodic and on change) | `detectors` (array of status objects), `queueDepth`, `drops`, `faults`, `uptimeS` |
| `audit` | Operator override, unban, purge, reload, emergency disable | `actor`, `action`, `reason`, `evidenceIds`, `utc` |
| `tombstone` | Purge/redaction placeholder | `replaces` (event ID), `reasonClass` (`operator-purge` / `erasure-request` / `retention-expiry`), `payloadHash` (SHA-256 of the original record's canonical form) |

A `finding` example:

```json
{
  "schemaVersion": 1,
  "type": "finding",
  "eventId": "9f2c...",
  "chainPrev": "ab12...",
  "utc": "2026-07-21T12:34:56.789Z",
  "monotonicMs": 1827364,
  "tick": 36547,
  "tickHealthMs": 41,
  "latencyMs": 88,
  "buildId": "3.1.0-b14",
  "configHash": "cafe...",
  "hookManifestHash": "beef...",
  "sessionEpoch": 7,
  "pseudonym": "p-9f2c1a...",
  "entityId": 81234,
  "detectorId": "movement.displacement",
  "detectorVersion": "0.1.0",
  "severity": "strong",
  "confidence": 0.83,
  "mode": "observe",
  "suppressedReason": "latency-burst",
  "context": { "vehicle": "none", "stance": "crouch", "admin": false, "teleport": false },
  "observations": [ { "tick": 36546, "dx": 4.1, "budget": 2.0 } ],
  "expected": { "bound": 2.0 },
  "actual": { "dx": 4.1 },
  "causeEventIds": [],
  "action": "record",
  "disposition": null
}
```

Boundedness: `observations` is capped at 32 entries and each entry at 4 scalar fields;
`context` at 8 string keys. Anything larger is truncated with a `truncated: true` marker so
a hostile request cannot inflate evidence size.

Purge semantics: replacing a record with a `tombstone` keeps `chainPrev`/hash continuity so
the chain still verifies. Purge of a `finding` also purges its referenced `cause` records in
the same operation, and the operation is written as an `audit` record.

## Hook manifest (manifest v1)

Machine-readable JSON emitted by Phase 1 tooling, consumed by `HookRegistry` at startup and
by the metadata-contract tests (TEST_PLAN.md Layer 3). One entry per hook:

```json
{
  "manifestVersion": 1,
  "buildId": "3.1.0-b14",
  "buildFingerprint": "sha256:...",
  "configSchemaHash": "...",
  "hooks": [
    {
      "detectorId": "movement.displacement",
      "assembly": "Assembly-CSharp",
      "type": "EntityPlayerLocal",
      "method": "MovePosition",
      "fullSignature": "void EntityPlayerLocal.MovePosition(Vector3, float)",
      "paramRoles": ["position", "deltaTime"],
      "returnType": "System.Void",
      "metadataToken": "06001234",
      "hookKind": "postfix",
      "seamClass": "post-state",
      "thread": "main",
      "expectedRatePerSecond": 20,
      "rejectCapability": "prefix-skip-original",
      "compatibilityRisk": "suppresses vanilla body; co-patch documented",
      "fallbackEvent": "ModEvents.PlayerTick?",
      "inputAuthority": { "position": "client-declared", "deltaTime": "server-derived" },
      "enabled": true
    }
  ]
}
```

`buildFingerprint` is SHA-256 over the pinned assembly identity: name, assembly version,
and file hash of `Assembly-CSharp.dll` as installed, plus the `ModInfo.xml` version of the
mod itself. A fingerprint mismatch at startup fails open per hook.

## Audit log (audit v1)

Operator actions only, no gameplay data. Fields: `schemaVersion`, `type: "audit"`, `eventId`,
`utc`, `actor` (operator label, never a platform identity), `action` (`override`,
`unban`, `purge`, `config-reload`, `emergency-disable`, `appeal-disposition`),
`reason` (free text, required), `evidenceIds` (array), `chainPrev`. Retention: 1 year
([PRIVACY.md](../PRIVACY.md)).

## Health report (health v1)

Periodic `health` record plus a live console summary. Per detector: `detectorId`,
`version`, `mode`, `hookResolved` (bool), `state` (`active` / `self-disabled` /
`fail-open` / `off`), `faults`, `findingsThisEpoch`, `configHash`. Global: `queueDepth`,
`drops`, `uptimeS`, `epochs`. The health record is the input to the "detector-health report"
on shutdown (ARCHITECTURE.md -> Runtime lifecycle).

## Metrics naming

Counters compatible with `7dtd-apm` collectors; Prometheus-style dotted names, no player
identity labels:

| Counter | Meaning |
|---|---|
| `serverguard.hooks.resolved` | Hooks resolved at startup |
| `serverguard.hooks.faults` | Runtime hook faults (per detector as a label) |
| `serverguard.hooks.self_disabled` | Self-disabled hooks |
| `serverguard.findings.<detectorId>` | Findings emitted |
| `serverguard.findings.suppressed` | Soft findings suppressed with `suppressedReason` |
| `serverguard.corrections.<detectorId>` | Corrections applied |
| `serverguard.corrections.suspended` | Entity corrections suspended (loop prevention) |
| `serverguard.queue.action_depth` | Main-thread action queue depth (gauge) |
| `serverguard.queue.evidence_depth` | Evidence queue depth (gauge) |
| `serverguard.queue.dropped_soft` | Soft observations dropped (drop-soft-first) |
| `serverguard.movement.samples` | Movement samples accepted |
| `serverguard.movement.voxel_queries` | Swept no-clip voxel queries (cost dominator) |
| `serverguard.inventory.diffs` | Full-inventory diffs (cost dominator) |
| `serverguard.tick.p95_added_ms` | p95 added main-thread time per tick (budget gate) |

## Schema evolution

- Bump `schemaVersion` when a field's meaning changes incompatibly. Additive fields bump a
  minor marker in the same version number only when every consumer is updated in the same
  release.
- Evidence replay (TEST_PLAN.md Layer 4) refuses traces whose `schemaVersion`, `buildId`,
  or `configHash` does not match the replaying build, and reports instead of guessing.
- Config upgrade rules: `schemaVersion` must match exactly; unknown keys are an error. A
  config migration tool (Phase 10 packaging) rewrites old configs to the new schema and
  prints the diff before writing.
