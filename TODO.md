# TODO

The checkboxes are the project ledger. Complete phases in order. A phase closes only when its
artifacts and exit criteria are recorded.

## Phase map and dependencies

Phases run mostly in order, but the dependencies below are the hard constraints; a phase may
start its *design* work any time its inputs exist. Detector registry:
[DETECTORS.md](docs/DETECTORS.md). Data contracts: [SCHEMAS.md](docs/SCHEMAS.md).
Reasoning trail: [DECISIONS.md](docs/DECISIONS.md).

```text
Phase 0 policy review (blocking gate for everything)
  -> Phase 1 surface inventory (feeds 3, 4, 5, 6, 7, 8 authority classes)
     -> Phase 2 scaffold (needs 1's manifest to stub hooks; needs 0 review)
        -> Phase 3 evidence foundation (needs 2)
           -> Phase 4 protocol invariants (needs 3)
           -> Phase 5 movement (needs 3; calibration gate: 100 player-hours)
           -> Phase 6 combat (needs 3; authority gate per validator)
           -> Phase 7 inventory/economy (needs 3; needs loadgen extension)
           -> Phase 8 world/entity/automation (needs 3)
     -> Phase 9 response/operations (needs 4-8 enforcement candidates)
        -> Phase 10 calibration and release (needs 9)
```

Two phase notes: Phase 2 and Phase 3 are foundational and everything depends on them; Phase 7
additionally depends on `7dtd-loadgen` gaining container/trader/craft scenarios (its current
golden set covers only movement, damage, and login). Any phase may defer a detector to a later
phase if Phase 1 finds no authoritative seam; the detector registry records the deferral.

## Phase 0: policy and project contract

- [x] Define server-observable anti-cheat scope and explicit non-goals.
- [x] Record EAC-off limitation and reject claims of client memory integrity.
- [x] Define observe, correct, quarantine, kick, review, and ban boundaries (`docs/POLICY.md`, mode ladder vs action set).
- [x] Choose license (AGPL-3.0, `LICENSE`), disclosure policy (`SECURITY.md`), maintainer, security contact, and appeal owner (all maci / maci.stgn@gmail.com; see `docs/POLICY.md` roles table).
- [x] Write player-facing privacy/monitoring notice and retention schedule (`PRIVACY.md`).
- [x] Decide supported server builds; initially pin V3.1.0 (b14) only (`docs/POLICY.md`).
- [x] Define severity vocabulary, evidence confidence, and operator override semantics (`docs/POLICY.md`).
- [ ] Exit: policy reviewed before any enforcement code is written. (Docs drafted; human review pending.)

Review checklist for the Phase 0 exit (whoever reviews: tick each item or return the doc with
the objection). The review is the gate; nothing in later phases starts until it passes.

- [ ] Modes vs actions are not conflated anywhere (spot check POLICY.md, README.md, THREAT_MODEL.md, ARCHITECTURE.md).
- [ ] The severity ceilings in THREAT_MODEL.md and DETECTORS.md match POLICY.md (Hard -> `correct`; Strong needs two independent categories for kick; Weak is `record` only).
- [ ] Every action in the action set has a reversal path and an owner (POLICY.md -> Action set).
- [ ] Enforcement gates cannot be gamed by repeated copies of one root cause (POLICY.md -> Confidence and combination).
- [ ] Privacy notice and retention schedule match what the evidence schemas actually store (PRIVACY.md vs SCHEMAS.md evidence v1).
- [ ] Out-of-scope lists agree across THREAT_MODEL.md, SECURITY.md, README.md, and AGENTS.md.
- [ ] The at-risk seams in TODO.md and SIGNALS.md name a Phase 1 action for each.
- [ ] The Phase 1 exit criteria can be checked mechanically (hook manifest v1 in SCHEMAS.md is the machine-readable output).
- [ ] Docs quality gate passes: `make check` is green.


## Phase 1: authoritative surface inventory

- [ ] Create a Mono.Cecil metadata probe under `tools/surface_inventory`.
- [ ] Inventory full signatures for connection/auth/join/spawn/disconnect processors.
- [ ] Inventory movement, teleport, vehicle, stance, buff, stamina, and correction methods.
- [ ] Inventory attack initiation, hit resolution, damage application, ammo, reload, and item actions.
- [ ] Inventory inventory/container/craft/loot/trader/drop/pickup/save transaction methods.
- [ ] Inventory block damage/change/place/repair/upgrade, claim, lock, wire, turret, drone, vehicle,
  explosion, entity spawn, quest reward, and admin/console methods.
- [ ] For each candidate record authority, thread, pre-state, post-state, overload, metadata token,
  expected call rate, reject capability, compatibility risk, and fallback event.
- [ ] Confirm which client values the vanilla server already validates or overwrites.
- [ ] Classify every planned validator input as server-derived or client-declared; a
  client-declared input caps that validator below Hard.
- [ ] Resolve the at-risk seams flagged in `docs/SIGNALS.md`: craft transactions, trader
  pricing, and the second damage path (`NetPackageRangeCheckDamageEntity`).
- [ ] Enumerate every server-side teleport origin (trader ejection, quests, respawn, console,
  game events, mods) for the teleport capability-token model.
- [ ] Generate a build fingerprint and machine-readable hook manifest (hook manifest v1, [SCHEMAS.md](docs/SCHEMAS.md)).
- [ ] Exit: every planned detector maps to a verified authoritative decision point or is deferred.

## Phase 2: scaffold and safe runtime

- [ ] Add `net48` solution, `ServerGuard` source project, test project, `ModInfo.xml`, and Makefile.
- [ ] Wire CI to run `make ci` (docs gate now; TEST_PLAN.md layers 1-4 on every change once tests exist).
- [ ] Reference installed assemblies by configurable path; never copy game DLLs.
- [ ] Implement strict versioned config with unknown-key and invalid-range rejection (config v1, [SCHEMAS.md](docs/SCHEMAS.md)); scaffold one stub per [DETECTORS.md](docs/DETECTORS.md) row, with threshold keys from the generated [detector config manifest](config/detector-config-manifest.json) (`make detectors`).
- [ ] Implement exact hook resolver, status report, fail-open startup, and clean unpatch/shutdown.
- [ ] Wrap every hook body in an exception guard with a per-hook fault counter and runtime
  self-disable; a throwing hook must never break the connection's package loop.
- [ ] Register lifecycle `ModEvents`; add per-session epochs and disconnect cleanup.
- [ ] Add bounded main-thread action queue and dedicated evidence writer.
- [ ] Add allocation and timing counters compatible with `7dtd-apm`.
- [ ] Ship observe-only defaults and an emergency global disable.
- [ ] Exit: empty detector set loads/unloads and survives 64-client soak within overhead budget.

## Phase 3: evidence foundation

- [ ] Define versioned observation, finding, action, review, and detector-health schemas (evidence v1, [SCHEMAS.md](docs/SCHEMAS.md)).
- [ ] Implement HMAC pseudonyms, key rotation, local identity map, file permissions, and redaction.
- [ ] Implement append-only JSONL, hash chain, crash-safe segment close, rotation, retention, export.
- [ ] Add detector version/config hash, server build, session epoch, context, and causal event IDs.
- [ ] Add console commands for health, player findings, evidence export, review labels, and reload.
- [ ] Add WebDashboard plugin only after authentication and permission checks are tested.
- [ ] Never log auth tickets, passwords, raw packet bodies, or full chat by default.
- [ ] Exit: tamper, truncation, injection, retention, and privacy tests pass.

## Phase 4: protocol and permission invariants

- [ ] Implement join/auth/spawn state machine and entity ownership validation.
- [ ] Implement numeric/domain validation before expensive processing.
- [ ] Implement cost-weighted per-connection and global token buckets.
- [ ] Validate console/debug/admin actions at execution time, not request time only.
- [ ] Enumerate debug capabilities (godmode buff, spectator, creative menu, flight flag) as
  explicit permission checks with admin-level exemptions.
- [ ] Add duplicate session and replay evidence with reconnect grace.
- [ ] Observe for one week, tune retry/order exceptions, then enable safe rejects individually.
- [ ] Exit: malformed/flood loadgen corpus is contained without rejecting legal joins.

## Phase 5: movement ledger

- [ ] Capture contextual movement state and server tick/latency uncertainty.
- [ ] Implement integrated speed/acceleration budget with bounded credit and debt.
- [ ] Implement teleport capabilities and discontinuity reset rules; treat client
  `EntityTeleport` packages (stock >8 m delta escalation) as discontinuities, not violations,
  and expose a teleport-cause API for other mods alongside the item cause API.
- [ ] Implement vertical/hover, swept no-clip, and vehicle-specific detectors.
- [ ] Add all legal movement fixtures listed in `docs/TEST_PLAN.md`.
- [ ] Keep a retention-bounded sampled position history per player for review timeline replay.
- [ ] Observe and label at least 100 player-hours before correction is considered.
- [ ] Enable server correction before kick; rate-limit corrections and prevent correction loops.
- [ ] Exit: no false correction in legal matrix and performance gate passes.

## Phase 6: combat ledger

- [ ] Correlate item action, ammo/reload, attack, hit, damage, death, and explosion IDs.
- [ ] Hook both damage paths (`EntityAlive.DamageEntity` and
  `NetPackageRangeCheckDamageEntity`); a validator on one path only protects nothing.
- [ ] Implement cadence, held-item/ammo, state, target-set, and repeat-damage invariants.
- [ ] Reconstruct allowed damage from item, quality, mods, buffs, armor, difficulty, and hit zone.
- [ ] Validate reach and line of interaction using server geometry at the authoritative seam.
- [ ] Record aim/visibility time series as weak, review-only signals with sampling controls.
- [ ] Build weapon/action-family fixture catalog; test PvE, PvP, turret, vehicle, explosive, DOT.
- [ ] Exit: every combat validator declares each input's authority class from the Phase 1
  inventory; any validator with a client-declared input is demoted below Hard and stays
  observe-only.

## Phase 7: inventory and economy conservation

- [ ] Implement double-entry item ledger and typed authorized cause tokens.
- [ ] Cover player inventory, toolbelt, equipment, containers, vehicles, drones, drops, death bags.
- [ ] Cover crafting/workstations, repair, upgrade, consume, ammo, quests, traders, admin/mod grants.
- [ ] Add transaction idempotency and container version/ownership checks.
- [ ] Reconcile snapshots, save epochs, disconnects, crash recovery, and rollback without accusation.
- [ ] Expose a documented API for other trusted mods to register server-origin causes; verify it
  against CPM/ServerTools admin item grants as first consumers.
- [ ] Baseline inventory at first sight per session epoch; flag creative-only or unobtainable
  items that appear without an authorized cause.
- [ ] Record calling-mod identity on every cause-API invocation in the evidence stream.
- [ ] Extend `7dtd-loadgen` to drive container, trader, and craft traffic; its current golden
  set covers only movement, damage, and login, which cannot exercise this phase.
- [ ] Run concurrency and disconnect-at-every-step dupe corpus.
- [ ] Exit: conservation holds for legal traces and known exploit fixtures are safely rejected.

## Phase 8: world, entity, and automation detectors

- [ ] Implement block/claim/lock/reach/tool/material/cadence/world-bound invariants.
- [ ] Implement wire/power, turret, drone, vehicle, explosion, and entity-spawn authorization.
- [ ] Validate client-pushed progression (`NetPackageEntityAddExpServer`,
  `NetPackageEntitySetSkillLevelServer`): XP rate bounds, skill prerequisites, stat maxima.
- [ ] Add cost limits for chunk/map/inventory and high-fan-out requests.
- [ ] Add repetitive movement/action and impossible-efficiency features as weak review signals.
- [ ] Keep spam content moderation separate from anti-cheat; share only rate-limit infrastructure.
- [ ] Exit: hard actions are protected; behavioral automation never enforces alone.

## Phase 9: response, operations, and appeals

- [ ] Implement per-detector modes and dry-run diff showing what would have happened.
- [ ] Implement correction, granular quarantine, kick, and temporary local ban adapters.
- [ ] Require independent evidence categories, decay, cooldown, and minimum observation windows.
- [ ] Add permissioned console/WebDashboard review with timeline and contextual values.
- [ ] Add review disposition, unban, evidence purge, false-positive regression export, and audit log.
- [ ] Add Prometheus/JSON metrics without player identity labels.
- [ ] Add optional operator alert sink (webhook/Discord) sending evidence IDs off the game
  thread; no raw player identity in the payload.
- [ ] Validate and finalize the incident runbook, threshold rollout, rollback, appeal, and disclosure procedures drafted in [docs/OPERATIONS.md](docs/OPERATIONS.md).
- [ ] Exit: operators can explain, reverse, and audit every action.

## Phase 10: calibration and release

- [ ] Establish clean baselines by game build, server config, mods, biome, player count, and latency.
- [ ] Use `7dtd-loadgen` for deterministic legal/adversarial scenarios and `7dtd-apm` for A/B cost.
- [ ] Conduct shadow deployment, moderator labeling, threshold tuning, and holdout evaluation.
- [ ] Publish precision, recall where labels permit, false-positive confidence interval, and blind spots.
- [ ] Red-team malformed packets, races, evasion, identity churn, evidence injection, and resource abuse.
- [ ] Package source, DLL, config schema, checksums, install/uninstall, compatibility table, and changelog.
- [ ] Compatibility matrix names the common stack explicitly: Alloc's fixes, CPM, ServerTools,
  CSMM/telnet managers, Botman-style telnet bots.
- [ ] Require explicit operator opt-in for each enforcement family after upgrade.
- [ ] Exit: release candidate passes functional, fidelity, privacy, performance, and rollback gates.

## Known at-risk seams

Consolidated from [SIGNALS.md](docs/SIGNALS.md) and the phases above; revisit each when new
evidence lands:

- **Craft transactions:** no craft/recipe/workstation-queue package surfaced in the census;
  backpack crafting looks client-local and workstations sync as opaque tile-entity blobs.
  Expected to degrade to unexplained-delta (Strong) unless Phase 1 finds a seam.
- **Trader pricing:** purchases look like client-side inventory edits against synced trader
  state; verify an authoritative price/currency decision point in Phase 1 or defer like craft.
- **Second damage path:** `NetPackageRangeCheckDamageEntity` must be hooked together with
  `EntityAlive.DamageEntity`; a validator on one path only protects nothing (Phase 6).
- **Vehicle envelopes:** physics-master vehicles are client-simulated; reconstructed
  terrain-aware limits stay Weak until validated, then Strong (SIGNALS.md → Movement).
- **Loadgen coverage:** the `7dtd-loadgen` golden set covers only movement, damage, and login;
  Phase 7 must extend it to container, trader, and craft traffic or the ledger phase cannot be
  exercised (Phase 7).
- **Build delta:** all surfaces were inventoried against V3.0.1 (b4); Phase 1 re-verifies the
  pinned V3.1.0 (b14) before any hook is written.

