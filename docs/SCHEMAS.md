# Schemas

This document defines the concrete, versioned data contracts the implementation must honor:
the runtime **config**, the **evidence stream**, the **hook manifest**, the **audit log**,
the **health report**, and the **metrics** naming. These are the Phase 2 and Phase 3
"define schema" TODO items, written down before code so the strict-versioning guarantees
in [ARCHITECTURE.md](ARCHITECTURE.md) can be tested against something concrete.

Rules that apply to every schema in this document:

- Every record schema carries a `schemaVersion` integer; the two manifests
  (`config-manifest.v1.schema.json` and the hook manifest) carry a `manifestVersion`
  instead. A consumer that sees an unknown version
  refuses to start (config) or skips and reports (evidence replay), never guesses.
- Unknown keys are rejected, not ignored. Invalid ranges and enums are rejected.
- Identifiers are validated per field, not by one shared charset. A detector ID is
  `^[a-z]+\.[a-z_]+$`, an evidence `eventId` is a UUID, a `pseudonym` is `^p-[0-9a-f]{8,64}$`,
  and a session epoch is an integer, so a hyphenated or numeric name is rejected where the
  field's own pattern says it must be.
- No schema ever contains a raw platform identity, IP address, auth ticket, password, or
  full packet body. Identities are HMAC pseudonyms (see [PRIVACY.md](../PRIVACY.md)).
  Every open value bag in the evidence schema (`context`, `observations`, `expected`,
  `actual`, `replayedFrom`, `deltaItems` elements) additionally carries a
  `propertyNames` deny-list, so a detector that writes a raw name, address, or
  credential into its own values is rejected at validation rather than at export. The
  list is declared once, in the schema's `definitions`, and every bag `$ref`s it, so a
  newly denied key is added in one place; it denies a stem anywhere in the key, not a
  fixed spelling, because an enumerated spelling is bypassed by the first variant
  nobody wrote down. `make check` fails when an open bag drops the ref, inlines its own
  copy, or is an array with no element schema at all.
- A permitted key is not a permitted value, so the value is checked too. The name list
  closes the key a detector writes and says nothing about `note`, `reason`, or `marker`,
  which the schema permits and which is exactly where an interpolated platform id lands.
  Every open value bag therefore carries a second shared definition,
  `personalDataValueDenyList`, as its `additionalProperties`, and every bounded
  free-text field (`suppressedReason`, `modIdentity`, `itemId`, `marker`, `actor`,
  `reason`) carries it in `allOf`. It denies the values this project can name as
  identifying a person: both spellings of a Steam id, the 64-bit and Xbox forms of the
  same account, a dotted-quad network address, a MAC address, and a contact address. A
  display name has no shape, so this is not a name filter. The dotted-decimal rule also
  rejects a four-part dotted version string, which is traded deliberately: a value that
  reads as an address is rejected at validation, where the writer sees it, rather than
  stored for the retention window. `make check` fails when an open bag or a
  `maxLength` field drops the ref.
- Paths in the config table (`evidence.dir`, `identityMap.path`, `hmacKey.path`) are the
  one place this schema names the filesystem. Nothing in the table sets a data root: the
  host does, and the loader resolves a relative path against the mod's data root beside
  the server executable, using an absolute path as given. A path that escapes that root
  through `..`, or an empty one, is rejected at load; the identity map and the HMAC key
  are created with the `permissions` the table names. The default `ServerGuard/` tree
  below the data root is confirmed in Phase 2. The file is hand-edited on the Windows
  host that runs the server and read by the operator tooling wherever it runs, so a
  configured path is read with either separator: `keys\hmac.key` and `keys/hmac.key`
  name the same file. A path is saved as UTF-8, with or without a byte-order mark.

## Config schema (config v1)

File: `server-guard.json` in the mod's data root. The repo ships
`config/server-guard.example.json` (the documented contract); an operator keeps their working
copy at `config/server-guard.local.json` (gitignored) and deploys it as
`server-guard.json`. That deployed file is the only configuration source: there is no
environment-variable override for any key in this table, so the file, not the environment,
is what an operator changes. The two exceptions are secret *values* the file only names,
`webhook.urlEnv` and `dashboard.secretEnv`.

Loaded at startup, rejected wholesale on any violation, reloadable by console command with
the same checks. The machine form of this table is the JSON Schema at
`config/schemas/config.v1.schema.json`; the doccheck gate validates the example config
against it, and the strict loader in Phase 2 is generated from the same schema.

Two classes of violation are checked against more than the file, and both are failures at
load time rather than a feature that quietly does nothing:

- Detector keys. A `modes` key that is not a registered detector id, and a `thresholds` key
  that the per-detector manifest does not declare for that detector, are rejected. A typo
  would otherwise load as the `observe` default and read as a detector that never fires.
- Dependent secrets. A `webhook` or `dashboard` that is `enabled` while the environment
  variable its `urlEnv` or `secretEnv` names is unset or empty is rejected, so a sink
  enabled in the file cannot stay off at runtime. Secret values are never read into a
  finding, a log line, or a report; only the presence of the variable is.

Two further rejections read one file's values against each other, so the JSON Schema cannot
state them, and the pre-deploy check runs both:

- Dependent actions. `actions.tempBanLocal` requires `actions.kick`; a local temp-ban is a
  kick the mod applies itself, and [POLICY.md](POLICY.md) -> Enforcement gates opens it only
  behind the kick gate. Either flag alone is a valid config, the pair with the gate closed
  is not: the file would read as an approved enforcement that no gate permits.
- Paths. `evidence.dir`, `identityMap.path`, and `hmacKey.path` may not carry a `..` path
  segment, at either end or between separators, a backslash counting as a separator as on
  Windows. A relative path is resolved against the data root and an absolute one is used as
  given (the rules above this section), so a `..` puts the evidence, the re-identification
  key, or the identity map outside the root the backup and the restore drill cover. Dots
  inside a name (`ev..idence`) are not a traversal and are accepted.

An operator runs the same checks before deploying, on the machine that will run the mod:
`make verify-config FILE=<path>` ([tools/README.md](../tools/README.md) -> `config_check.py`).
It prints the effective config's hash, the digest every evidence record, the health report,
and the hook manifest carry. `make verify-config FILE=<path> SHOW_EFFECTIVE=1` forwards
`--show-effective` to get that hash; a plain run prints only the verdict. `--skip-env`
checks the file alone, for a config being reviewed
where the serving environment is not the one running the check.

| Key | Type | Default | Range / enum | Meaning |
|---|---|---|---|---|
| `schemaVersion` | int | 1 | exactly 1 | Reject otherwise |
| `enabled` | bool | true | - | Master switch; `false` behaves like emergency disable at startup |
| `emergencyDisable` | bool | false | - | Loaded true, every detector starts at `observe`. At runtime the same state is reached with `sg emergency-disable`, which is operator-only and audited |
| `buildPin.buildId` | string | `3.2.0-b9` | exact match | Pinned game build; other builds load with all failing hooks disabled (observe-only) |
| `buildPin.policy` | string | `observe-else` | `observe-else` only in v1 | Behavior on build mismatch |
| `modes.<detectorId>` | string | `observe` | `observe` / `correct` / `enforce` | Per-detector mode; raising requires the phase gates in POLICY.md, never just config editing |
| `actions.correct` | bool | true | - | Permit `correct` transitions for Hard invariants in `correct`/`enforce` modes |
| `actions.quarantine.damage` | bool | false | - | Each quarantine restriction is separately enabled |
| `actions.quarantine.containers` | bool | false | - | Same |
| `actions.quarantine.worldMutation` | bool | false | - | Same |
| `actions.kick` | bool | false | - | Subject to the kick gate in POLICY.md |
| `actions.tempBanLocal` | bool | false | - | Permit the evidence action `temp-ban-local`; requires the kick gate plus per-incident operator approval (POLICY.md) |
| `actions.throttle` | bool | true | - | Availability protection; never counts toward enforcement |
| `thresholds.<detectorId>.<key>` | number/string | per detector | per detector | Placeholder until Phase 10 calibration; every key must be declared in the detector's config manifest |
| `evidence.dir` | string | `ServerGuard/evidence` | writable, non-empty | Append-only JSONL segments |
| `evidence.retentionDays` | int | 30 | 1..365 | Segment expiry |
| `evidence.rotationSizeMB` | int | 64 | 1..1024 | Rotate at this size or at day boundary; 1 MB = 1,000,000 bytes (decimal, not MiB) |
| `evidence.positionHistoryDays` | int | 7 | 0..90 | 0 disables replay history |
| `evidence.positionHistorySamplesPerPlayer` | int | 3600 | 0..20000 | Bounded replay timeline |
| `identityMap.path` | string | `ServerGuard/identity-map.json` | restricted perms, non-empty | Pseudonym -> platform identity, operator-only |
| `identityMap.permissions` | string | `0600` | POSIX octal | Enforced at startup on POSIX hosts, by the Phase 3 runtime; no shipped code enforces it yet (TODO.md) |
| `hmacKey.path` | string | `ServerGuard/hmac.key` | restricted perms, non-empty | Pseudonym key; destroyed when evidence under it expires |
| `hmacKey.permissions` | string | `0600` | POSIX octal | Enforced at startup on POSIX hosts, as for the identity map: platform IDs are enumerable, so this file is the re-identification key. Phase 3 runtime; no shipped code enforces it yet (TODO.md) |
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
| `webhook.urlEnv` | string | `SERVERGUARD_WEBHOOK_URL` | `^[A-Z][A-Z0-9_]*$` env var name | Webhook URL comes from the environment, never the config file (workspace secrets rule) |
| `dashboard.enabled` | bool | false | - | Ships only after auth and permission tests (Phase 3) |
| `dashboard.secretEnv` | string | `SERVERGUARD_DASHBOARD_SECRET` | `^[A-Z][A-Z0-9_]*$` env var name | Dashboard auth secret from the environment, never the config file |
| `metrics.enabled` | bool | true | - | APM-compatible counters |

Config hash: SHA-256 over the normalized (sorted-key) JSON of the *effective* config,
computed after defaults are applied. The hash is written into every evidence record, the
health report, and the hook manifest so a finding can always be traced to the config that
produced it.

## Replay trace (replay-trace v1)

Replay traces are deterministic detector inputs and expectations; they are not evidence
records. The machine contract is `config/schemas/replay-trace.v1.schema.json`. A trace names
its detector, seed, build and hook-manifest identity, observe-only mode, bounded work, cases,
ordered synthetic events, authoritative decision state, and expected findings/actions.

The required `determinism` block is what makes a replay reproducible instead of merely
repeatable. `startUtc` and `startMonotonicMs` are the virtual clock origin: the harness
derives every event's `tick`, and every evidence record's `utc` and `monotonicMs`, from them
plus the trace's own tick values. No wall clock is read during replay, on any host and at any
date. `fingerprint` is the SHA-256, over the canonical serialization pinned by
`tools/evidence_check.py`, of the outcome projection: the run header (`build`, `detectorId`,
`mode`, `seed`, `workBudget`), the clock origin, and, per case in file order, the case name,
class, expected findings, expected actions, and work-unit charge. The harness recomputes the
projection from what its detectors actually produced and fails the replay when the digests
differ, so a divergent run is reported as one field rather than a hand-read record diff.
A case whose `tick` decreases as `sequence` increases is rejected: it makes the run's result
depend on delivery order, which is exactly what replay must not.

Design-time samples may use `UNVERIFIED` as the hook-manifest hash only before Phase 1 emits
the pinned manifest. The Phase 4 harness skips `UNVERIFIED` and mismatched hashes rather than
replaying them as build evidence. Shipped regression fixtures require a 64-character lowercase
SHA-256 hash.

The schema deliberately requires observe mode and an empty action list. Corrective behavior
belongs to live integration tests after authority and legal-context gates pass. Replay events
contain synthetic pseudonymous state only and must never carry platform identities, auth data,
raw packets, chat, or copied server data.

## Evidence stream (evidence v1)

Append-only JSONL, one object per line, hash-chained. Segment files
`evidence-<UTC-date>-<seq>.jsonl` plus a `segment-index.json`. Every record starts with
`schemaVersion`, `type`, and `eventId` (a UUID; the schema pins the shape, not the
version nibble). `chainPrev` is the SHA-256 of the
canonical serialization of the previous record in the chain; the first record of a segment
chains to the last record of the previous segment.

Canonical serialization (pinned by `tools/evidence_check.py`):
`json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
allow_nan=False)`. No record may carry `NaN` or an infinity: JSON has no encoding for
either, and a NaN compares false against every bound, so it would pass a range check and
then reach a reader as a comparison that never fires. Genesis:
the first record of the very first segment has `chainPrev` equal to 64 zeros. A chain
detects tampering of any record except the last one; tampering the last record is only
detected when the next record is appended, because an append-only chain has no later
record to cross-check. The stream is at-least-once: a writer that retries after a crash, or
a hook that fires twice for one event, appends the same `eventId` twice, and the chain of
the repeat is intact because it links to whatever record preceded it. A repeated
`eventId` is therefore a chain error in its own right, reported by the verifier, and the
writer must not append an `eventId` it has already written. The verifier keeps the last
65536 `eventId`s while it walks, so a repeat inside that window is reported and one older
than the window is not. `utc` and `savedAt` are RFC 3339 date-times serialized in UTC with a
`Z` terminal, declared once as `definitions/utcInstant` and `$ref`ed by both fields; the schema
declares `format: date-time` and the gate rejects a value without an offset, which names no
instant and would be read in the reader's own local zone, and a value with a non-`Z` offset,
which names the right instant but carries the writer's local calendar date and so disagrees
with the `evidence-<UTC-date>-<seq>.jsonl` segment holding it. Duration fields (`monotonicMs`,
`tickHealthMs`, `latencyMs`, `uptimeS`) come from the server monotonic
clock, so they measure elapsed time within one process and are never compared across
processes or machines. `tickHealthMs` is the tick loop's lag, the monotonic time a tick
overran its budget by, and the monotonic clock is the only clock it can be measured against:
a lag taken from the wall clock goes negative the moment timesync steps the clock backwards,
and the schema's `minimum: 0` then refuses the whole record, losing a finding over a clock
event that says nothing about the player. The verifier is `make verify-evidence DIR=<evidence-dir>`
and the shipped sample (`config/schemas/evidence.v1.sample.jsonl`) is a real, verifiable
chain run by the doccheck gate. The verifier walks each segment line by line, so its
memory cost does not grow with segment size.

The machine form of this section is the JSON Schema at
`config/schemas/evidence.v1.schema.json` with a one-record-per-type sample at
`config/schemas/evidence.v1.sample.jsonl`; the doccheck gate validates the sample, and the
EvidenceStore and replay harness (Phase 2 and Phase 4) validate against the schema. Machine
`severity` values are
lowercase (`hard`/`strong`/`weak`); POLICY.md terms are the display vocabulary.

Record types and their extra fields:

| `type` | Purpose | Extra fields |
|---|---|---|
| `finding` | A detector produced a finding | `detectorId`, `detectorVersion`, `severity`, `confidence`, `mode`, `suppressedReason?`, `pseudonym`, `entityId`, `sessionEpoch`, `utc`, `monotonicMs`, `tick`, `tickHealthMs`, `latencyMs`, `context`, `observations` (bounded array), `expected`, `actual`, `causeEventIds` (bounded), `action`, `disposition?`, `configHash`, `buildId`, `hookManifestHash` |
| `cause` | A registered mod cause-API invocation | `causeToken`, `modIdentity`, `itemId?`, `delta?`, `sessionEpoch`, `pseudonym`, `causeEventIds` |
| `reconciliation` | Ledger reconciled from durable save after crash/disconnect | `scope` (player/container), `savedAt`, `replayedFrom` (segment range), `deltaItems` (bounded), `marker` |
| `health` | Detector-health snapshot (periodic and on change) | `detectors` (array of status objects), `queueDepth`, `drops`, `faults`, `uptimeS` |
| `audit` | Operator override, unban, purge, reload, emergency disable | `actor`, `action`, `reason`, `evidenceIds`, `utc` |
| `tombstone` | Purge/redaction placeholder | `replaces` (event ID), `reasonClass` (`operator-purge` / `erasure-request` / `retention-expiry`), `payloadHash` (SHA-256 of the original record's canonical form) |

A `finding` example (`action` is one of `record`, `correct`, `quarantine`, `throttle`,
`kick`, `temp-ban-local`; `temp-ban-local` is a ban this mod applies from its own
evidence, not one delegated to an external service). The identifiers are the elided-digest
values the shipped sample uses, because the schema pins their length and pattern: a reader
copying this example into a record needs values that validate.

```json
{
  "schemaVersion": 1,
  "type": "finding",
  "eventId": "a2e00258-5c85-4bdf-97d1-a68ff9910d41",
  "chainPrev": "0000000000000000000000000000000000000000000000000000000000000000",
  "utc": "2026-07-21T12:34:56.789Z",
  "monotonicMs": 1827364,
  "tick": 36547,
  "tickHealthMs": 41,
  "latencyMs": 88,
  "buildId": "3.2.0-b9",
  "configHash": "cafe000000000000000000000000000000000000000000000000000000000000",
  "hookManifestHash": "beef000000000000000000000000000000000000000000000000000000000000",
  "sessionEpoch": 7,
  "pseudonym": "p-3e8d6f083e8d6f083e8d6f083e8d6f083e8d6f083e8d6f083e8d6f083e8d6f08",
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

Boundedness: `observations` is capped at 32 entries and each entry at 4 keys (the schema
bounds the key count and the deny-listed names, and every value against the shared
value deny-list, so a value that carries an identifier is rejected whether or not it
fits);
`context`, `expected`, and `actual` at 8 keys each; `causeEventIds` at 32 records and
`evidenceIds` at 64. Anything larger is truncated with a `truncated: true` marker so a
hostile request cannot inflate evidence size.

Free text is bounded too, on every string field a writer fills by hand:
`suppressedReason` at 64, `modIdentity`, `itemId`, and `marker` at 128, `actor` at 128,
`reason` at 512. These are the fields a writer completes by interpolating whatever the game
handed it, and an unbounded string there is the one place a name, a display string, or a
quoted line would sit in a record for its whole retention window. A value that does not fit
is a writer bug, caught at validation rather than stored. Each of the six also carries
the value deny-list, so a platform id or an address interpolated into any of them is
rejected as well.

A reference to another record is an `eventId`, so it is validated as one: `eventId`,
`replaces`, `causeEventIds`, and `evidenceIds` all take the single `evidenceEventId`
pattern declared in the schema's `definitions`, the same reason the deny-list is declared
once. An unparseable reference resolves to nothing, and an operator following it would read
a finding with no cause rather than a broken link.

Value-bag keys are lowercase `snake_case` and carry the `propertyNames` deny-list, so a
detector names a value after the quantity it measured (`dx`, `bound`, `vehicle`) and the
record's own `pseudonym` names the player. A detector whose input is a platform ID
(`protocol.duplicate_session`, spec input `platform_id`) compares HMAC pseudonyms, not raw
IDs, and names the value for what it counted. Keys that could hold a raw identity, a player
name, a contact or network address, or a credential are rejected at validation. The stems
cover a platform id by every spelling it is written (`steam`, `xuid`, `platform`, `guid`)
and a display name by its family (`name`, `nick`, `handle`, `alias`, `ident`, `login`),
because a deny-list that names one spelling of an account is half a control. The
`causeEventIds` and `evidenceIds` lists hold event ids and nothing else: every element
is a UUID, so a name cannot ride in a list whose declared type is an id.

Purge semantics: replacing a record with a `tombstone` keeps `chainPrev`/hash continuity so
the chain still verifies. Purge of a `finding` also purges its referenced `cause` records in
the same operation, and the operation is written as an `audit` record.

## Per-detector config manifest (config-manifest v1)

The `thresholds.<detectorId>.<key>` keys are not free-form: each detector declares the
threshold keys it accepts, with type, range, and a placeholder default, so the strict config
loader can reject unknown or out-of-range threshold keys with the same rule as top-level
keys. A threshold declared `type: int` carries integer range bounds and an integer default,
and every numeric range bound and default is finite: a fractional value would truncate on
load, and `NaN` or an infinity would compare false against every bound and never fire. The
doccheck gate rejects both. The manifest is **generated** from the canonical detector spec
(`tools/detector_spec.yaml`) into `config/detector-config-manifest.json` by
`tools/render_detectors.py --manifest` (`make detectors`); edit the YAML, never the JSON.
Every detector entry carries `detectorId`, `phase`, `ceiling`, `defaultMode`, and `seam`;
a detector that declares no thresholds has no `thresholds` key, and one that has a Hard
ceiling also carries `hardCondition`. The excerpt below is two detectors trimmed to
`config/detector-config-manifest.json`, and the doccheck gate validates every JSON excerpt
in this document against the schema it documents, so it cannot drift into a shape the
loader would reject.

```json
{
  "manifestVersion": 1,
  "detectors": [
    {
      "detectorId": "movement.displacement",
      "phase": 5,
      "ceiling": "Strong",
      "defaultMode": "observe",
      "seam": "NetPackageEntityPosAndRot, NetPackageEntityRelPosAndRot, NetPackageEntityPhysics, NetPackagePlayerStats",
      "thresholds": [
        { "key": "max_speed_mps", "type": "float", "range": [0.5, 100.0], "default": 10.0, "unit": "m/s", "note": "placeholder; sprint band" },
        { "key": "max_accel_mps2", "type": "float", "range": [0.0, 100.0], "default": 20.0, "unit": "m/s2", "note": "placeholder" },
        { "key": "latency_window_ms", "type": "int", "range": [0, 5000], "default": 200, "unit": "ms" },
        { "key": "jitter_allowance_m", "type": "float", "range": [0.0, 50.0], "default": 1.0, "unit": "m" },
        { "key": "credit_cap_m", "type": "float", "range": [0.0, 200.0], "default": 20.0, "unit": "m", "note": "unused budget cap" },
        { "key": "debt_grace_m", "type": "float", "range": [0.0, 200.0], "default": 10.0, "unit": "m", "note": "over-budget grace" }
      ]
    },
    {
      "detectorId": "availability.cost",
      "phase": 4,
      "ceiling": "Strong",
      "defaultMode": "observe",
      "seam": "package decode counters across all census types",
      "thresholds": [
        { "key": "tiny", "type": "int", "range": [1, 1000], "default": 1 },
        { "key": "play", "type": "int", "range": [1, 1000], "default": 2 },
        { "key": "state", "type": "int", "range": [1, 1000], "default": 5 },
        { "key": "expensive", "type": "int", "range": [1, 1000], "default": 20 }
      ]
    }
  ]
}
```

Rules: the config loader rejects any `thresholds.<id>.<key>` not declared here. Threshold
defaults are placeholders until Phase 10 calibration; changing a default in the manifest is a
config-schema change, not a code edit, and bumps the effective-config hash.

## Hook manifest (manifest v1)


Machine-readable JSON emitted by Phase 1 tooling, consumed by `HookRegistry` at startup and
by the metadata-contract tests (TEST_PLAN.md Layer 3). One entry per hook:

```json
{
  "manifestVersion": 1,
  "buildId": "3.2.0-b9",
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
`reason` (free text, required), `evidenceIds` (bounded), `chainPrev`. Retention: 1 year
([PRIVACY.md](../PRIVACY.md)).

## Health report (health v1)

Periodic `health` record plus a live console summary. Per detector: `detectorId`,
`version`, `mode`, `hookResolved` (bool), `state` (`active` / `self-disabled` /
`fail-open` / `off`), `faults`, `findingsThisEpoch`. Record-level: `configHash`. Global: `queueDepth`,
`drops`, `uptimeS`, `epochs`. The health record is the input to the "detector-health report"
on shutdown (ARCHITECTURE.md -> Runtime lifecycle).

## Metrics naming

Counters compatible with `7dtd-server-apm` collectors; Prometheus-style dotted names, no player
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

- Bump `schemaVersion` when a field's meaning changes incompatibly. v1 pins the version to
  an exact integer, so an incompatible change ships a new `vN` schema file rather than a
  marker inside v1; a `1.1` document is refused by every consumer today.
- Evidence replay (TEST_PLAN.md Layer 4) refuses a trace whose `schemaVersion` or
  `build.hookManifestHash` does not match the replaying build, and reports instead of
  guessing. `buildId` and `configHash` are evidence-record fields, not trace fields.
- Config upgrade rules: `schemaVersion` must match exactly; unknown keys are an error. A
  config migration tool (Phase 10 packaging) rewrites old configs to the new schema and
  prints the diff before writing.
