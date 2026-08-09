# Validation primitives

This document owns reusable validation mechanics. The generated
[detector registry](DETECTORS.md) owns detector identity, seams, inputs, algorithms, state,
contexts, thresholds, and fixtures. [POLICY.md](POLICY.md) owns what findings may justify.
This split is intentional: a primitive is a building block, not a detector and never an
enforcement reason by itself.

All numeric values remain placeholders until calibrated on the pinned build. Missing state
produces `unknown`, not `false`; uncertainty widens an envelope or suppresses a finding. A
threshold crossing is evidence, not proof of a particular program.

## Primitive contract

Every validator composes the same six parts:

| Part | Requirement |
|---|---|
| Observation | The smallest immutable copy of the event; client-declared fields stay labeled as such |
| Decision state | Server-derived state needed to decide the rule, sampled at the authoritative seam |
| Context | Named legal exceptions and uncertainty sources, never an undocumented global tolerance |
| Predicate | Deterministic result: `pass`, `violation`, or `unknown` |
| Attribution | The principal that initiated the invalid transition; never merely its target |
| Cost | A bounded per-event budget and explicit behavior when that budget is exhausted |

Input authority and input role determine the severity ceiling. Client-declared observations
may be checked, but a client-declared decision input caps the result below `Hard` unless the
registry records a reviewed completeness condition. See [POLICY.md](POLICY.md) and D-15 in
[DECISIONS.md](DECISIONS.md).

## Causal capabilities

A capability is a short-lived, one-use server record authorizing a future state transition.
It contains a cause, subject, issue event, expiry, optional amount or destination, and the
calling mod identity when issued through the public API. Consumption is atomic and produces
a causal edge in evidence.

Use capabilities where a later observation is legitimate only because an earlier server
action occurred:

- teleport origin -> position discontinuity;
- item source -> positive inventory delta;
- impulse source -> otherwise-impossible movement;
- progression award -> XP or skill delta;
- spawn authorization -> entity creation.

Capabilities do not turn incomplete observation into a Hard invariant. If legitimate
issuers cannot be enumerated, an absent token yields `unknown` or a lower-severity finding.
Expired and duplicate consumption are distinct from a never-issued capability so operators
can distinguish lag, replay, and coverage gaps.

## Conservation ledger

For a conserved quantity `q`, maintain an opening balance, typed sources, typed sinks,
transfers, and a closing balance:

```text
expected_close(q) = open(q) + sources(q) - sinks(q) + transfers_in(q) - transfers_out(q)
residual(q)       = observed_close(q) - expected_close(q)
```

Transfers use one transaction ID and two entries; applying either entry twice is illegal.
The primitive applies to items, currency, ammunition, durability, XP, and bounded entity
counts. It does not assume every mismatch belongs to a player. Save rollback, crash recovery,
disconnect, an unknown mod writer, or an incomplete seam produces an unattributed
reconciliation residual and resets the epoch from durable state.

Required properties:

- idempotency is scoped to session and durable-save epochs;
- slot/container versions make concurrent moves compare-and-swap operations;
- sources and sinks are typed, not free-form strings;
- unknown server-origin changes never accuse a player;
- retained state is bounded and expires with the evidence contract.

## Time-budget envelope

Use the server monotonic clock and integrated budgets for rate-limited physical or logical
actions. Never divide a delta by a single packet interval and enforce on that result.

For movement:

```text
legal_distance = max_speed * dt + 0.5 * max_acceleration * dt^2
uncertainty    = max_speed * latency_window + jitter_allowance
bound          = legal_distance + uncertainty + bounded_credit - debt
```

The same pattern applies to attack cadence, block actions, XP awards, and request cost:
accumulate legal budget, cap unused credit, charge observed work, and decay bounded debt.
Server stalls pause or widen time-based checks. Named discontinuities reset only the state
they invalidate; they do not erase unrelated evidence.

## State machine and epoch

Protocol, reload, crafting, container, spawn, and save flows are state machines. Each
transition declares allowed predecessor states, the principal, an epoch, idempotency key,
timeout, and cleanup behavior. A reconnect creates a new session epoch; stale messages from
an older epoch cannot mutate the new session.

Reject only at a seam with complete pre-state and an authoritative decision. If observation
occurs after mutation, record the inconsistency and reconcile rather than attempting an
unsafe rollback.

## Geometry with uncertainty

Reach, visibility, no-clip, and interaction checks query server geometry through a shared,
budgeted service. Queries return `clear`, `blocked`, or `unknown`. Unloaded or ungenerated
chunks always return `unknown`, never empty space.

Geometry checks must declare:

- the time at which attacker, target, and world state are sampled;
- hit-volume and interpolation tolerance;
- legal penetration or swept-volume rules;
- maximum voxel/ray queries per tick;
- behavior when the query budget is exhausted.

Deferred work may support review evidence but cannot retroactively reject an action.

## Cost and amplification budget

Availability protection meters estimated server work, not only packet count. Each decoded
request receives a cost based on measured CPU, allocation, world queries, fan-out, and queued
work. A per-connection token bucket plus a global per-tick budget contains both one noisy
client and coordinated load.

Initial cost classes are deliberately coarse and stay configurable until profiled:

| Class | Typical work | Initial relative weight |
|---|---|---:|
| Tiny | keep-alive, acknowledgement, basic metrics | 1 |
| Play | movement, rotation, damage request, item reload | 2 |
| State | block, inventory, tile-entity, wire mutation | 5 |
| Expensive | chunk, map, POI, inventory snapshot, dynamic mesh | 20 |

```text
balance = min(burst, balance + refill_per_second * dt) - measured_cost_class
```

Requests that exhaust the budget are delayed or shed according to a documented safe policy.
Bucket exhaustion produces availability evidence only and never contributes to gameplay
enforcement. Source-prefix state stays in memory; persisted records contain pseudonyms and
cost classes, not IP addresses.

## Correlation graph

Events form a bounded causal graph: request -> authorization -> mutation -> side effects ->
evidence -> response. Correlation IDs expose orphan effects, duplicate effects, and one
request producing an illegal fan-out without pretending that packet order alone is trusted.

Keep only the minimum edges needed by the detector's window. Graph nodes expire by epoch and
time; cross-player edges record initiator and recipient separately. This prevents knockback,
explosion, container-race, and vehicle interactions from assigning a victim's resulting state
to the attacker or vice versa.

## Behavioral residuals

After hard rules and named context are removed, residual series may support weak review
signals such as edge-of-envelope motion, aim regularity, repetitive routing, or implausible
efficiency. They run on copied bounded data off the game thread.

Behavioral residuals never enforce alone. They require build- and context-specific baselines,
minimum sample sizes, holdout evaluation, and an explanation in original game units. Do not
persist raw high-frequency trajectories when aggregated features suffice.

## Composition rules

1. Prefer one shared primitive over detector-specific copies of ledger, epoch, geometry, or
   token-bucket logic.
2. Independence is based on root cause and authoritative seam, not detector count. Two
   findings derived from one movement sample remain one evidence category.
3. A primitive failure disables dependent rejection paths and reports detector health; it
   does not fail closed.
4. Every primitive has property tests for bounds, overflow, epoch reset, duplicate delivery,
   missing context, and budget exhaustion.
5. New detector ideas begin in [PROPOSALS.md](PROPOSALS.md) and enter the registry only after
   their seam, authority, privacy cost, and fixture plan are credible.
