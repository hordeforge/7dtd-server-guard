# Architecture

## Decision

Use one small server mod DLL with separated collection, validation, scoring, evidence, and
response layers. Keep the hot path allocation-bounded. Perform no network calls on the game
thread. The first release is deterministic and rule-based; statistical models are offline-only
until a labeled dataset demonstrates calibration and false-positive behavior. Hooks are
pinned to the single supported build (7 Days to Die dedicated V3.1.0 (b14)) and fail open
on any resolution mismatch (see [POLICY.md](POLICY.md)).

## Runtime pipeline

```text
ModEvents and narrowly pinned Harmony hooks
  -> normalized observations (readonly structs in pooled ring buffers, not per-event heap objects)
  -> per-player bounded state machines and ledgers
  -> context providers (latency, tick health, buffs, vehicle, admin, teleport)
  -> hard invariant validators and soft behavioral detectors
  -> independent evidence aggregation
  -> append-only evidence writer and counters
  -> observe, correct, quarantine, kick, or operator review
```

## Components

| Component | Responsibility | Thread rule |
|---|---|---|
| `HookRegistry` | Resolve exact type, method, signature, token; report unavailable hooks | Startup only |
| `ObservationAdapter` | Copy minimum primitives from a hook into a normalized event | Calling thread, no IO |
| `PlayerSessionRegistry` | Map entity ID to stable platform identity and session epoch | Main thread |
| `ContextSnapshot` | Ping, server frame debt, vehicle, buffs, stance, death, spawn, teleport, admin | Main thread |
| `MovementLedger` | Last accepted samples, distance budget, grace windows | Main thread |
| `CombatLedger` | Weapon, ammo, reload, cadence, target, ray geometry, damage result | Main thread |
| `InventoryLedger` | Item quantities and authorized causes, including container transactions | Main thread |
| `WorldActionLedger` | Block, claim, wire, turret, vehicle, drone, and entity actions | Main thread |
| `ProtocolState` | Join/auth/spawn ordering and per-package token buckets | Network observation only; enqueue decisions |
| `InvariantEngine` | Hard predicates that can safely reject impossible requests | Main thread |
| `BehaviorEngine` | Windowed scores with uncertainty and peer/baseline context | Worker over copied data |
| `EvidenceStore` | JSONL segments, hash chain, retention, redaction, rotation | Dedicated writer thread |
| `ResponseCoordinator` | Cooldowns, corrections, quarantine, kick; no permanent auto-ban | Main thread action queue |
| `Metrics` | Detector cost, queue depth, drops, flags, corrections, false-positive labels | Lock-free counters |

## Source layout and naming

Planned tree (created as scaffolding in Phase 2; directories carry a README until then):

```text
src/ServerGuard/                  net48 class library, namespace ServerGuard.*
├── ServerGuardMod.cs             ModEvents lifecycle entry point
├── Config/                       strict config load/validate/reload (SCHEMAS.md config v1)
├── Hooks/                        HookRegistry, exact resolution, fault guard, build pin
├── Observations/                 ObservationAdapter, normalized event structs, ring buffers
├── Protocol/                     ProtocolState, per-package token buckets, join/auth state machine
├── Ledgers/                      MovementLedger, CombatLedger, InventoryLedger, WorldActionLedger
├── Detection/                    InvariantEngine (Hard predicates), BehaviorEngine (windowed scores)
├── Evidence/                     EvidenceStore: JSONL segments, hash chain, tombstones, rotation
├── Response/                     ResponseCoordinator, action adapters, correction cooldowns
├── Metrics/                      lock-free counters, APM-compatible naming (SCHEMAS.md)
└── Api/                          public cause-API and teleport-cause API for other mods

tests/ServerGuard.Tests/          unit + property tests (TEST_PLAN.md layers 1-2)
tests/ServerGuard.MetadataTests/  metadata-contract tests against the pinned build (layer 3)
tests/ServerGuard.Replay/         offline replay harness, seeded traces (layer 4)
tools/surface_inventory/          Mono.Cecil probe emitting hook manifest v1 (Phase 1)
config/                           server-guard.example.json and schema documentation
```

Naming rules (binding, from the workspace rules): a config key, detector ID, C# field, or
function parameter must state its true behavior so a reader infers it without the docs. No
name whose plain reading is the opposite of, or broader than, what it controls. Detector IDs
are the registry keys in [DETECTORS.md](DETECTORS.md); the config, evidence stream, metrics,
and fixtures all use the same ID string.

Module map (component -> planned file):

| Component (components table) | Planned home | Notes |
|---|---|---|
| `HookRegistry` | `Hooks/` | Consumes hook manifest v1; emits health status |
| `ObservationAdapter` | `Observations/` | Copies primitives only; allocation-bounded |
| `PlayerSessionRegistry` | `ServerGuardMod.cs` + `Protocol/` | Session epochs, disconnect cleanup |
| `ContextSnapshot` | `Detection/` | Aggregates context providers per tick |
| `MovementLedger` / `CombatLedger` / `InventoryLedger` / `WorldActionLedger` | `Ledgers/` | One file per ledger; double-entry helpers shared |
| `ProtocolState` | `Protocol/` | Network observation only; enqueue decisions |
| `InvariantEngine` / `BehaviorEngine` | `Detection/` | Hard predicates vs windowed scoring |
| `EvidenceStore` | `Evidence/` | Single writer thread; hash chain |
| `ResponseCoordinator` | `Response/` | Action adapters behind one interface |
| `Metrics` | `Metrics/` | Counter names from SCHEMAS.md |

## Hook policy


Prefer typed `ModEvents` for lifecycle and identity: `PlayerLogin`, `PlayerJoinedGame`,
`PlayerSpawning`, `PlayerSpawnedInWorld`, `PlayerDisconnected`, `SavePlayerData`,
`EntityKilled`, `GameMessage`, and `ChatMessage`. Use Harmony only when the event surface lacks
the authoritative decision point. Every Harmony hook must specify the complete signature,
record its metadata token at startup, have a fixture test, and disable itself on mismatch.

Candidate authoritative seams to verify in Phase 1 include `NetPackage*.ProcessPackage`,
server combat resolution, both damage paths (`EntityAlive.DamageEntity` and
`NetPackageRangeCheckDamageEntity`), item/inventory mutation methods, container transaction
processing, block damage/change application, crafting completion, vehicle movement, teleport,
entity spawning, and permission/console execution. Hook the narrowest method that still sees
pre-state, request, decision, and post-state.

Startup pinning is not the whole fail-open story. Every prefix/postfix body runs inside an
exception guard; a hook that resolves but throws at runtime increments a per-hook fault
counter and self-disables past a small limit, reverting that detector to unavailable rather
than risking the connection's package loop. Rejecting via prefix skip-original suppresses the
vanilla body that other mods' patches may depend on, so each reject seam documents its
co-patching behavior and the compatibility run exercises rejects, not just coexistence.

## Input authority

Every validator declares whether each of its inputs is **server-derived** (originates in
state the server controls) or **client-declared** (any path allows a client package to
influence it). The rule: a validator with any client-declared input is capped below `Hard`
regardless of how many server-derived inputs it also checks (see [POLICY.md](POLICY.md) →
Severity).

Examples to verify in Phase 1:

- Server-derived: item base damage from XML, the server clock, entity ownership
  (`OwnedEntity`), the permission registry, block material hardness, the world chunk map,
  an operator console action.
- Client-declared: claimed hit body part, reported swing strength, reported
  position/rotation, claimed item stack, a fired-weapon animation event (only damage
  *application* is server-authoritative), a client-pushed XP or skill-level value.

Phase 1 records the authority class of every input against the pinned build and publishes
the result in the hook manifest; the Phase 6 exit gate re-checks every combat validator.

## Evidence model

Each finding contains schema version, event ID, UTC and monotonic time, server build,
session epoch, pseudonymous platform ID, entity ID, detector ID/version, severity,
confidence, mode, server tick health, latency context, named exemptions, observed values,
expected bounds, contributing event IDs, action taken, and review disposition.

Evidence stores keyed HMAC identifiers at rest, not only on export; the raw platform ID exists
only in the separate permission-restricted identity map. Hash-chain JSONL records and rotate by
size and day. A purge or redaction replaces the record payload with a tombstone that preserves
the record hash, so the chain still verifies after erasure. The chain detects tampering by
anyone without the evidence key; it is not proof against the keyholder, so appeal evidence is
exactly as trustworthy as the operator holding it. Never put passwords, auth tickets, full
packet bodies, or inventory names supplied by a client into logs without normalization.

## Scoring and response

- Hard invariant: a game rule with exact authoritative inputs. May reject in `Correct` mode.
  Every validator declares the authority class of each input (server-derived or
  client-declared); a validator that consumes any client-declared input is capped below Hard
  (see [SIGNALS.md](SIGNALS.md)).
- Strong signal: near-impossible alone but still needs repeated evidence before kick.
- Weak signal: behavioral anomaly. Never enforces alone.
- Score decay is per detector. Independent categories combine; repeated copies of the same
  root cause do not multiply confidence.
- Suppress soft scoring during server stalls, join/spawn, teleport, death, chunk starvation,
  packet-loss bursts, and externally applied impulses (knockback, explosion, ragdoll).
  Preserve the raw finding with `suppressedReason` for tuning.
- Quarantine means temporarily restrict damage, container/trade access, or world mutation
  while allowing communication and operator review. Each restriction must be separately enabled.
- A kick message names the violated server rule and evidence ID. No secret threshold details.

## Runtime lifecycle and failure modes

Startup, in order:
1. Load the strict versioned config; reject on unknown keys or invalid ranges.
2. Resolve every hook against the pinned build: type, full signature, parameter role, return
   type, metadata token. Record the hook manifest and build fingerprint; report unresolved hooks.
3. Register lifecycle `ModEvents` and start per-session epochs.
4. Start the main-thread action queue, evidence writer, and metrics counters.
5. Only then raise detectors to their configured modes; the default is observe-only.

Shutdown: stop accepting observations, flush and close the current evidence segment, unpatch
every hook, and log the final detector-health report.

| Failure | Behavior | Guarantee |
|---|---|---|
| Hook resolution mismatch at startup | That detector is disabled and reported | Fail-open; observe mode unchanged |
| Hook body throws at runtime | Per-hook fault counter; self-disable past a small limit | Connection package loop never breaks |
| InvariantEngine reject | Single transition rejected at the seam; co-patching documented; rate-limited | No correction loops |
| BehaviorEngine window overflow | Drop soft observations, increment the drop counter | Game thread never blocks |
| Evidence queue full | Drop soft observations first | Bounded memory |
| Config invalid | Refuse startup | No silently relaxed config |
| Crash mid-write | Segment recovery on next start; truncation detected | Hash chain re-verifies |
| Emergency global disable | All detectors revert to observe without restart | Operator override wins |

## Ledger design details

### Movement envelope

The server receives client-reported positions with network latency rather than true
positions. The movement detector integrates the maximum legal speed and acceleration over
the server-clock interval since the last accepted sample, then adds a latency-uncertainty
window:

| Variable | Formula |
|---|---|
| `legal_distance` | `max_speed × Δt_server + max_acceleration × ½(Δt_server)²` |
| `uncertainty` | `max_speed × latency_window + jitter_allowance` |
| `bound` | `legal_distance + uncertainty` |

When the reported displacement fits within `bound`, the position is accepted and the budget
is consumed. When it exceeds, the position is clamped to the envelope edge and the excess is
tracked as a violation. Credit (unused budget, capped) and debt (over-budget within a grace
margin) accumulate per tick and reset on named discontinuities: teleport, death, spawn,
vehicle enter/exit, knockback, admin correction, and stock `EntityTeleport` for >8 m deltas.
High ping widens `latency_window`, not physical speed; jitter bursts add `jitter_allowance`.
States the server does not model (mod-added movement types, unknown buffs) widen the
uncertainty window rather than triggering violations.

Sampled position history for review replay: record position, tick, and envelope state every
20 ticks (~1 s at 20 Hz) plus on every discontinuity. Retain at most 3600 samples per player
(~1 hour), expired by wall clock at 7 days.

### Inventory reconciliation

On server restart or crash recovery, the inventory ledger reconciles against the durable
save: it reads the last saved item snapshot, replays any pending committed transactions from
the evidence segment, and diffs the computed state against the world. Unexplained deltas are
logged with the causal event IDs and a reconciliation marker in the evidence stream; they
are **never** attributed to a player. The ledger resets its in-memory state from the
reconciled snapshot and resumes. Disconnect and rollback periods are handled the same way:
the connection epoch closes, outstanding transactions are flushed, and the next epoch opens
clean.

### Correction-loop prevention

A corrective action on a single entity may fire at most once per server tick. Each entity
carries a correction cooldown counter: if corrections within a short window exceed a small
limit, that entity's corrective responses are suspended and the detector reports the
suppression. This prevents a borderline legitimate state (low-credibility signal, unlucky
jitter pattern) from being hammered into a false-correction spiral.

## Performance budget

At 64 players, target under 0.5 ms p95 added main-thread time per tick, under 1 percent CPU
on worker threads, bounded queues, and zero steady-state allocations in movement sampling.
The two expected cost dominators get their own sub-budgets and per-detector counters: the
swept no-clip voxel test (per-sample world queries; cap samples per tick and defer the rest)
and full-inventory diffing on inventory syncs (cap diffs per tick, diff lazily on change
signal). The p95 gate is measured during a 64-player bloodmoon damage burst, not idle load.
If a queue is full, drop soft observations first, increment a drop counter, and never block the
game thread. Validate overhead with `7dtd-apm` under identical `7dtd-loadgen` scenarios.

