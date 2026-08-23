# Execution plan

This document turns the design contract into the next executable work. It owns priority and
integration order; [TODO.md](../TODO.md) remains the phase ledger, and its Phase 0 review
still blocks enforcement code. Nothing here marks a phase complete.

## Delivery order

| Order | Outcome | Exit evidence |
|---:|---|---|
| 1 | Independent Phase 0 review | Every review checkbox resolved with objections and dispositions recorded |
| 2 | Phase 1 metadata inventory | Reproducible build fingerprint and hook manifest with full signatures, authority, thread, state, reject capability, cost, and fallback |
| 3 | Authority-gap decisions | Craft, trader, damage paths, teleport origins, progression awards, container atomicity, and vehicle authority promoted, demoted, or deferred with reasons |
| 4 | Shared runtime primitives | Property-tested epoch state machine, capability store, conservation ledger, correlation graph, geometry budget, work meter, queues, and dependency health |
| 5 | First vertical slice | `inventory.stack` runs end to end in observe mode with deterministic replay, evidence, review, and overhead results |
| 6 | Additional detector families | Only after their authoritative seams and primitive dependencies are healthy |

More detector proposals do not outrank these outcomes. They remain in
[PROPOSALS.md](PROPOSALS.md) until Phase 1 evidence satisfies the promotion gate.

## Phase 0 review exercise

The reviewer must try to falsify, not merely approve, the contract. For each TODO Phase 0
checkbox, record reviewer, date, result (`accepted`, `change-requested`, or `blocked`), the
specific counterexample attempted, and the resulting document change or rationale. Required
exercises include:

- construct two correlated findings from one root cause and verify they do not satisfy the
  independent-evidence gate;
- walk every action through reversal, owner, player notice, and appeal;
- compare each retained evidence field with PRIVACY.md retention and purpose;
- remove one authoritative input from a Hard detector and verify its ceiling or availability
  drops;
- compare scope exclusions across AGENTS.md, README.md, SECURITY.md, and THREAT_MODEL.md.

The review artifact contains policy reasoning only and must not contain player evidence.

## Phase 1 inventory contract

The surface probe emits one entry per candidate hook with:

| Field | Requirement |
|---|---|
| Build identity | Executable/module hashes, game version, Mono/runtime identity, probe version |
| Method identity | Assembly, full type, method, generic arity, return type, full parameter types, metadata token |
| Detector use | Detector ID, observation or rejection role, required pre-state and post-state |
| Authority | Every input's server-derived/client-declared class and observed/decision role |
| Runtime | Calling thread, expected rate, allocation risk, downstream fan-out |
| Safety | Reject capability, co-patch behavior, failure behavior, fallback event |
| Verification | Probe result, smoke-test result, reviewer, and manifest-entry hash |

The probe studies installed stock assemblies in `../7dtd-engine-research/` and emits only metadata
facts here. It never copies game assemblies or reverse-engineering narratives into this repo.

### Questions resolved first

1. Craft completion, ingredient consumption, workstation queue, and cancellation.
2. Trader price, currency spend, stock mutation, and transaction commit.
3. Common and alternate damage paths, including shared sinks and bypasses.
4. Every stock, admin, event, and mod teleport origin.
5. XP, skill, respec, party-share, event, admin, and mod progression awards.
6. Container versioning, locking, transaction atomicity, disconnect, and save boundaries.
7. Vehicle physics-master delegation and what the server can actually bound.

An unresolved question causes explicit demotion or deferral. Observability alone is not an
authoritative decision point.

## Primitive implementation order

1. `EpochState`: bounded session/save epochs, injected monotonic clock, stale-event rejection.
2. `CapabilityStore`: typed one-use capabilities with issuer, subject, scope, expiry, and
   atomic consumption.
3. `ConservationLedger`: double-entry transfers, typed sources/sinks, reconciliation without
   player attribution.
4. `CorrelationWindow`: bounded causal edges with initiator and recipient separated.
5. `GeometryBudget`: `clear`/`blocked`/`unknown`, per-tick query cap, no unloaded-as-air result.
6. `WorkBudget`: measured downstream work, per-principal and global shedding, availability-only
   findings.
7. `ActionQueue` and `EvidenceQueue`: bounded, never block the game thread, drop soft work first.
8. `DependencyHealth`: downward-only mode changes when required hooks or primitives are unhealthy.

Each primitive receives property tests for duplicate and reordered delivery, epoch rollover,
numeric overflow, missing context, bounded memory, and exhausted work budgets before a
detector consumes it.

## Dependency and safe-demotion model

A detector declares required hooks, primitives, context providers, and evidence categories.
Each dependency reports `healthy`, `degraded`, or `unavailable` plus a reason. Effective mode
is the lower of configured mode and dependency-safe mode.

| Condition | Required automatic behavior |
|---|---|
| Hook mismatch or runtime self-disable | Dependent rejection unavailable; report health; fail open |
| Required context unknown-rate exceeds its reviewed bound | Return dependent detector to observe |
| Required causal evidence is dropped | Disable rejection that needs that causal chain |
| Correction burst limit reached | Suspend correction for that subject and report health |
| Build, config, hook-manifest, or mod-stack drift | Require renewed validation and explicit opt-in |
| Dependency recovers | Remain at the lower mode until operator review; never raise automatically |

Detector count does not establish evidence independence. Dependencies and evidence categories
must preserve the root cause so correlated findings cannot multiply confidence.

## First vertical slice: inventory stack

The first slice is deliberately narrow:

```text
authoritative inventory transaction seam
  -> immutable observation
  -> session/container epoch check
  -> authoritative item stack limit
  -> inventory.stack finding in observe mode
  -> chained evidence
  -> replay expectation and operator disposition
  -> measured per-event and per-tick cost
```

Acceptance criteria:

- normal moves at and below the stack limit produce no finding;
- a claimed destination quantity above the authoritative limit produces exactly one
  `inventory.stack` finding attributed to the requester;
- replay and stale epochs do not apply the transition twice;
- concurrent mutations use a version check rather than last-write-wins;
- admin or mod item origin does not exempt an impossible stack shape;
- observe mode produces no gameplay action under any failure;
- the fixture declares and stays within a deterministic work budget;
- emitted evidence validates against evidence v1 and contains no raw identity.

The checked sample at `tools/fixtures/traces/inventory/stack.v1.sample.json` exercises the
normal and violation contract now. It is a design/test vector, not proof of a live hook.

## Cross-repository scenario contract

`7dtd-loadgen` owns scenario execution; `7dtd-server-apm` owns overhead collection. This repository
owns the inputs and outputs it requires from them.

| Producer | Required contract |
|---|---|
| `7dtd-loadgen` | Scenario ID/version, seed, pinned build, config/mod-stack hash, actor roles, event clock, expected legal/violation labels, disconnect-at-step controls |
| Server Guard | Hook-manifest/config hashes, findings/actions, detector health, queue drops, per-detector work counters, replay export |
| `7dtd-server-apm` | Host identity class, warmup/duration, p50/p95/p99 tick delta, worker CPU, allocations, memory, queue depth, disconnect count, confidence intervals |

First loadgen additions are container split/merge and concurrent moves, disconnect at every
transaction step, save rollback, trader purchase, and craft start/cancel/complete. Performance
runs pair the same seed, world, clients, duration, and collectors with Server Guard disabled
and observe-only.

## Generated coverage view

Phase 2 should generate one row per detector:

```text
detector -> verified hook -> input authority -> primitive dependencies -> context fixtures
         -> evidence category -> state bound/expiry -> overload behavior -> readiness
```

The generator must fail when a registered detector lacks a required field, references an
unknown context/fixture, claims conditional Hard without satisfied evidence, or is configured
above dependency-safe mode. Before Phase 2, `make check` validates the current spec, fixture
declarations, schemas, and the executable replay-contract sample.

## Stop conditions

Stop and update the design before proceeding when:

- the live seam cannot see complete pre-state before mutation;
- a required callback performs IO or unbounded work on the game thread;
- a legal context cannot be represented without a global threshold increase;
- evidence needed for attribution can be dropped while rejection remains enabled;
- a detector cannot explain its finding in original game units;
- a cross-repository scenario cannot be reproduced from its recorded seed and hashes.
