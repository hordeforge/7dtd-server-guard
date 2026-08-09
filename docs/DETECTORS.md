# Detector registry

This is the canonical registry of every planned detector. The signal catalog
([SIGNALS.md](SIGNALS.md)) describes *what* to watch, the policy contract
([POLICY.md](POLICY.md)) defines *how* a signal may act, and this registry names each
detector with a stable ID so config, evidence, fixtures, metrics, and phases all refer to
the same thing. Add a detector to `tools/detector_spec.yaml` first and re-render
(`make detectors`); Phase 2 scaffolding, the per-detector config manifest
([SCHEMAS.md](SCHEMAS.md) -> Per-detector config manifest), and the fixture catalog
([TEST_PLAN.md](TEST_PLAN.md) -> Layer 4) are all generated from the same YAML.

Rules for the registry:

- A detector ID is `family.subject`, lowercase, unique, and permanent once shipped. A
  renamed detector is a new ID plus an evidence-schema migration, never an in-place edit.
- `Severity ceiling` is set by input authority (POLICY.md -> Severity): a detector is
  `Hard` only when every *decision* input is server-derived, meaning server state fully
  determines the verdict. A client-declared *observed* quantity (the thing being checked)
  is allowed; a client-declared *decision* input caps the detector below `Hard` unless a
  `hard_condition` documents complete server-side determination. See DECISIONS.md D-15.
  Phase 1 publishes each input's authority class and role in the hook manifest.
- Default mode is always `observe`. A detector may only be raised to `correct` or
  `enforce` after its phase exit criteria and the policy gates pass.
- `Contexts` are named exemptions that must suppress or widen the detector; every context
  named here needs a fixture family in TEST_PLAN.md.

The machine-readable spec behind every row lives in
[`tools/detector_spec.yaml`](../tools/detector_spec.yaml): per-detector input roles
(observed vs decision), algorithm sketch, state, threshold keys, contexts, and fixtures.
The tables below are rendered from that file by `tools/render_detectors.py`; edit the YAML,
not the tables. The per-detector config manifest
([SCHEMAS.md](SCHEMAS.md) -> Per-detector config manifest) is generated from the same file.

<!-- REGISTRY:START -->

## Protocol and identity (Phase 4)

| ID | What it validates | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `protocol.stage_order` | Package type is legal for the connection's current join/auth/spawn/play stage. | all decision inputs server-derived | Hard | stock-reconnect-resume |
| `protocol.entity_owner` | The entity ID in a request belongs to the requesting connection. | all decision inputs server-derived | Hard | physics-master-delegate, server-originated-relay |
| `protocol.permission` | Debug, creative, godmode, spectator, and console actions require permission, checked at execution time, not request time. | all decision inputs server-derived | Hard | admin-principal, automation-principal |
| `protocol.duplicate_session` | A platform identity has only one live session; duplicate logins are evidence, not proof. | all decision inputs server-derived | Strong | stale-disconnect, reconnect-grace |
| `protocol.malformed` | Decoded values are in domain: enum in range, no NaN/infinity, coordinates, stack sizes, and lengths bounded. | all decision inputs server-derived | Hard | none |
| `protocol.flood` | Per-connection and global cost-weighted token buckets contain floods; throttle is availability protection and never counts toward enforcement. | all decision inputs server-derived | Strong (availability) | server-retry, packet-loss-burst |

## Movement (Phase 5)

| ID | What it validates | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `movement.displacement` | Reported displacement stays within an integrated speed/acceleration envelope plus a latency-uncertainty window. | decision inputs include client-declared reported_position; capped below Hard unless the hard condition holds | Strong | teleport, death, spawn, vehicle-enter-exit, knockback, ragdoll, server-stall, packet-loss-burst, mod-movement, unknown-buffs, admin-correction |
| `movement.flight` | Sustained unsupported vertical state without a valid flight context. | decision inputs include client-declared reported_position; capped below Hard unless the hard condition holds | Strong | jetpack, parachute, elevator, helicopter, mod-flight, server-stall |
| `movement.vertical_accel` | Vertical velocity deltas are explainable by jump, gravity, fall, impact, explosion, or buff impulses. | decision inputs include client-declared reported_position_series; capped below Hard unless the hard condition holds | Strong | knockback, explosion, ragdoll, server-hitch, mod-buffs |
| `movement.noclip` | Swept capsule/voxel path crosses solid blocks without a valid state transition. | decision inputs include client-declared reported_position_series; capped below Hard unless the hard condition holds | Strong | vehicle, buffs, unloaded-chunks, server-stall |
| `movement.teleport_token` | Position discontinuities are backed by a one-use server-issued teleport token; stock EntityTeleport for >8 m deltas is an ordinary discontinuity, not a violation. | all decision inputs server-derived; hard condition: Hard only after Phase 1 enumerates every server-side teleport origin; otherwise Strong (see DECISIONS.md D-12) | Hard (conditional) | trader-ejection, quests, respawn, console, mods, chunk-stall |
| `movement.vehicle` | Vehicle speed/acceleration against reconstructed terrain-aware limits. | decision inputs include client-declared reported_vehicle_position; capped below Hard unless the hard condition holds | Weak | vehicle-physics, collision, passenger-motion, server-stall |
| `movement.edge_distribution` | Distribution of normalized movement-budget consumption is unusually edge-clustered. | all decision inputs server-derived | Weak | all movement discontinuity contexts |

## Combat (Phase 6)

| ID | What it validates | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `combat.cadence` | Fire/use cadence at damage application is not faster than the item action permits. | all decision inputs server-derived; hard condition: Hard if reload/chamber and modifier state is fully server-known for the item family; otherwise Strong | Hard (conditional) | buffs, mods, reload-state, server-stall |
| `combat.held_item_ammo` | An attack requires a valid held item and ammunition in the authoritative inventory/chamber ledger. | all decision inputs server-derived | Hard | server-originated-item-grant |
| `combat.reach` | Attacker origin to target hit volume at resolved time is within weapon reach. | decision inputs include client-declared attacker_origin; capped below Hard unless the hard condition holds | Strong | moving-target, vehicle, ragdoll, high-latency |
| `combat.damage` | Applied damage is consistent with the recomputed allowed range from item, quality, mods, buffs, armor, difficulty, and hit zone. | decision inputs include client-declared claimed_hit_zone, claimed_strength; capped below Hard unless the hard condition holds | Strong | armor, buffs, difficulty, headshot, dot, explosive, vehicle |
| `combat.geometry` | Damage does not pass through solid geometry beyond weapon penetration rules. | decision inputs include client-declared attacker_origin; capped below Hard unless the hard condition holds | Strong | unloaded-chunks, high-latency |
| `combat.state` | Damage is not applied during death, spawn protection, stun, reload, or a disallowed animation state. | all decision inputs server-derived | Strong | spawn-protection, buffs, vehicle, turret, explosion |
| `combat.target_set` | Multi-target or repeat damage matches weapon rules and the attack correlation ID. | all decision inputs server-derived | Strong | turret, explosion, dot, vehicle |
| `combat.aim` | Aim snap, low reaction time, and abnormal angular tracking as review-only evidence. | decision inputs include client-declared rotation_series; capped below Hard unless the hard condition holds | Weak | skilled-play, accessibility-device, interpolation, pve |
| `combat.acquisition` | Target acquisition before the server could expose the target; nearly unobservable in vanilla, low priority. | all decision inputs server-derived | Weak | pve |

## Progression (Phase 8)

| ID | What it validates | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `progression.xp_rate` | Client-pushed XP gain rate stays within the maximum earnable from legitimate causes. | all decision inputs server-derived | Strong | quests, kills, server-events, mod-grants |
| `progression.skill_prereq` | A client-pushed skill/attribute level is legal under the server progression rules. | all decision inputs server-derived; hard condition: Hard only if the server progression rules (points, prerequisites, maxima) are recomputable; otherwise Strong | Hard (conditional) | mod-skill-grants |
| `progression.health_stamina` | Reported health/stamina cannot exceed attribute-derived maxima. | all decision inputs server-derived | Hard | buffs, mods |

## Inventory and economy (Phase 7)

| ID | What it validates | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `inventory.delta` | Every positive item delta is explained by an authorized cause in the double-entry ledger. | all decision inputs server-derived | Strong | all authorized causes, rollback, disconnect, mod-grants, reconciliation |
| `inventory.stack` | A stack cannot exceed the authoritative item definition's stack limit. | all decision inputs server-derived | Hard | container-stacks, vehicle, drone |
| `inventory.craft` | Craft output is backed by ingredients, time, station, and recipe. | all decision inputs server-derived; hard condition: Hard only if Phase 1 finds an authoritative craft/recipe/workstation-queue seam; otherwise degrades to inventory.delta (Strong) | Hard (conditional) | workstation, craft-cancellation |
| `inventory.replay` | A transaction ID is applied at most once per session epoch. | all decision inputs server-derived | Hard | reconnect, container-move, craft, trader |
| `inventory.container_race` | Concurrent container moves resolve atomically; a second player's race never grants an item. | all decision inputs server-derived | Hard | concurrent-moves, split-merge, second-player-race |
| `inventory.quality` | Item quality/mod/durability combinations are possible under item definitions and crafting rules. | all decision inputs server-derived | Hard | mod-item-quality |
| `inventory.trader` | Trader transactions match server-computed price and currency. | all decision inputs server-derived; hard condition: Hard only if Phase 1 finds an authoritative trader price/currency seam; otherwise degrades to inventory.delta (Strong) | Hard (conditional) | trader-state-sync |
| `inventory.rollback` | Disconnect/rollback gains are reconciled against the durable save epoch. | all decision inputs server-derived | Strong | crash-recovery, disconnect, save-rollback |

## World and entity (Phase 8)

| ID | What it validates | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `world.block` | Block changes respect reach, tool, material, claim, cadence, and world bounds. | all decision inputs server-derived; hard condition: Hard only for the authorization subset (claims, locks, ownership, allowlist, overflow); positional and cadence subchecks consume client-declared position and stay Strong | Hard (conditional) | falling-blocks, explosion, quests, allies, parties, admin |
| `world.claim` | Locked-container and claim access is authorized. | all decision inputs server-derived | Hard | allies, parties, admin |
| `world.wire` | Wire endpoints, powered tile ownership, and lock state are valid. | all decision inputs server-derived | Hard | turret, drone, vehicle, power-tools |
| `world.entity_spawn` | Client-requested entity classes are on the server allowlist with a valid spawn source. | all decision inputs server-derived | Hard | mod-spawns |
| `world.explosion` | Explosion inventory consumption and damage bounds are consistent with the explosive used. | all decision inputs server-derived | Strong | explosives, barrels, vehicles |
| `world.budget` | Per-player action budgets bound high-fan-out requests. | all decision inputs server-derived | Strong (availability) | mod-batched-actions |

## Availability (Phases 4 and 8)

| ID | What it validates | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `availability.cost` | Decoded bytes, package count and cost, malformed decodes, exceptions, and queued work are bounded per identity and source prefix (in-memory only). | all decision inputs server-derived | Strong (availability) | server-retry, packet-loss-burst |
| `availability.churn` | Reconnect churn and join storms are bounded; never an accusation. | all decision inputs server-derived | Strong (availability) | stale-disconnect, reconnect-grace |

## Fixture coverage

X marks the fixture families a detector must ship in TEST_PLAN.md Layer 4;
declared per detector in `tools/detector_spec.yaml`. A detector is not considered for a mode
raise until its declared fixture set is green in observe mode.

| ID | normal | violation | latency-stall | reconnect-duplicate-session | teleport-vehicle-death | admin-mod-origin | rollback | induced-finding |
|---|---|---|---|---|---|---|---|---|
| `protocol.stage_order` | X | X |  | X |  |  |  |  |
| `protocol.entity_owner` | X | X |  |  |  | X |  |  |
| `protocol.permission` | X | X |  |  |  | X |  |  |
| `protocol.duplicate_session` | X | X |  | X |  |  |  | X |
| `protocol.malformed` | X | X |  |  |  |  |  |  |
| `protocol.flood` | X | X | X |  |  |  |  |  |
| `movement.displacement` | X | X | X |  | X |  |  | X |
| `movement.flight` | X | X | X |  | X |  |  |  |
| `movement.vertical_accel` | X | X | X |  |  |  |  | X |
| `movement.noclip` | X | X | X |  |  |  |  |  |
| `movement.teleport_token` | X | X | X |  | X |  |  |  |
| `movement.vehicle` | X | X |  |  | X |  |  |  |
| `movement.edge_distribution` | X | X | X |  |  |  |  |  |
| `combat.cadence` | X | X | X |  |  |  |  |  |
| `combat.held_item_ammo` | X | X |  |  |  | X |  |  |
| `combat.reach` | X | X | X |  |  |  |  |  |
| `combat.damage` | X | X |  |  |  | X |  |  |
| `combat.geometry` | X | X |  |  |  |  |  |  |
| `combat.state` | X | X |  |  |  |  |  |  |
| `combat.target_set` | X | X |  |  |  |  |  |  |
| `combat.aim` | X | X |  |  |  |  |  |  |
| `combat.acquisition` | X | X |  |  |  |  |  |  |
| `progression.xp_rate` | X | X |  |  |  | X |  |  |
| `progression.skill_prereq` | X | X |  |  |  | X |  |  |
| `progression.health_stamina` | X | X |  |  |  |  |  |  |
| `inventory.delta` | X | X |  |  |  | X | X | X |
| `inventory.stack` | X | X |  |  |  |  |  |  |
| `inventory.craft` | X | X |  |  |  |  | X |  |
| `inventory.replay` | X | X |  | X |  |  |  |  |
| `inventory.container_race` | X | X |  |  |  |  |  | X |
| `inventory.quality` | X | X |  |  |  |  |  |  |
| `inventory.trader` | X | X |  |  |  |  | X |  |
| `inventory.rollback` | X | X |  | X |  |  | X |  |
| `world.block` | X | X |  |  |  | X |  |  |
| `world.claim` | X | X |  |  |  | X |  |  |
| `world.wire` | X | X |  |  |  |  |  |  |
| `world.entity_spawn` | X | X |  |  |  | X |  |  |
| `world.explosion` | X | X |  |  |  |  |  |  |
| `world.budget` | X | X |  |  |  |  |  |  |
| `availability.cost` | X | X | X |  |  |  |  |  |
| `availability.churn` | X | X |  | X |  |  |  |  |

## Seam map (V3.1.0 census candidates)

Candidate authoritative seams from `7dtd-research/il/netpackages-v3.1.0/INDEX.md`
(193 types) and the protocol narratives; every seam is verified in Phase 1 before
a hook is written. Declared per detector in `tools/detector_spec.yaml`.

| Detector | Candidate seam |
|---|---|
| `protocol.stage_order` | NetPackage*.ProcessPackage stage gating (ConnectionManager.ProcessPackages) |
| `protocol.entity_owner` | process-time ownership resolution; NetPackageOwnedEntitySync |
| `protocol.permission` | NetPackageConsoleCmdClient/Server, NetPackageDebug, NetPackageModifyCVar execution seams |
| `protocol.duplicate_session` | NetPackagePlayerLogin, NetPackageRequestToEnterGame handlers |
| `protocol.malformed` | NetPackage read/decode boundaries across all census types |
| `protocol.flood` | ConnectionManager.ProcessPackages intake; cost classes per package |
| `movement.displacement` | NetPackageEntityPosAndRot, NetPackageEntityRelPosAndRot, NetPackageEntityPhysics, NetPackagePlayerStats |
| `movement.flight` | NetPackageEntityPosAndRot, NetPackageEntityRelPosAndRot, NetPackageEntityPhysics |
| `movement.vertical_accel` | NetPackageEntityVelocity, NetPackageEntityAddVelocity, NetPackageEntityPosAndRot |
| `movement.noclip` | NetPackageEntityPosAndRot/RelPosAndRot plus voxel sweep |
| `movement.teleport_token` | NetPackageEntityTeleport (client discontinuity), NetPackageTeleportPlayer (server origin) |
| `movement.vehicle` | NetPackageVehicleDataSync, NetPackageVehiclePositions |
| `movement.edge_distribution` | ledger output; no direct seam |
| `combat.cadence` | NetPackageDamageEntity, NetPackageRangeCheckDamageEntity |
| `combat.held_item_ammo` | NetPackageHoldingItem, NetPackageItemReload plus damage application seam |
| `combat.reach` | damage application seam plus server geometry |
| `combat.damage` | NetPackageDamageEntity, NetPackageRangeCheckDamageEntity |
| `combat.geometry` | damage application seam plus voxel ray test |
| `combat.state` | entity state at NetPackageDamageEntity/RangeCheck process |
| `combat.target_set` | NetPackageDamageEntity correlation; NetPackageEntityAwardKillServer |
| `combat.aim` | NetPackageEntityRotation (quantized rotation series) |
| `combat.acquisition` | NetEntityDistribution / NetPackageEntitySpawn visibility history |
| `progression.xp_rate` | NetPackageEntityAddExpServer |
| `progression.skill_prereq` | NetPackageEntitySetSkillLevelServer |
| `progression.health_stamina` | NetPackageEntityStatChanged, NetPackageEntityStatsBuff, NetPackageGameStats |
| `inventory.delta` | NetPackageInventoryTransactionRequest/Response, NetPackagePlayerInventory, NetPackageDropItemsContainer, NetPackageItemDrop, NetPackageBag |
| `inventory.stack` | NetPackageInventoryTransactionRequest, NetPackagePlayerInventory |
| `inventory.craft` | craft/recipe/workstation-queue seam (at risk: no craft package in the V3.1.0 census) |
| `inventory.replay` | NetPackageInventoryTransactionRequest (transaction idempotency) |
| `inventory.container_race` | NetPackageInventoryTransactionRequest (atomic slot check) |
| `inventory.quality` | NetPackageInventoryTransactionRequest, NetPackagePlayerInventory |
| `inventory.trader` | NetPackageTraderData (sync only; no price/currency transaction package in the census) |
| `inventory.rollback` | save epoch / NetPackagePlayerDisconnect / reconnect handlers |
| `world.block` | NetPackageSetBlock, NetPackagePickupBlock, NetPackageAnimateBlock, NetPackageLandClaimRepair |
| `world.claim` | NetPackageLockRequest/Response plus claim database at access seam |
| `world.wire` | NetPackageWireActions, NetPackageWireToolActions |
| `world.entity_spawn` | NetPackageRequestToSpawnEntity, NetPackageEntitySpawn/Response, NetPackageQuestEntitySpawn |
| `world.explosion` | NetPackageExplosionInitiate, NetPackageExplosionClient |
| `world.budget` | NetPackageMapChunks, NetPackagePOIAround, NetPackageChunk, NetPackageWorldInitInfoRequest (fan-out classes) |
| `availability.cost` | package decode counters across all census types |
| `availability.churn` | NetPackagePlayerLogin, NetPackageRequestToEnterGame |

<!-- REGISTRY:END -->

## Lifecycle

1. Phase 1 records the authoritative seam, input authority classes and roles, and hook manifest entry
   for a candidate detector. If no authoritative seam exists, the detector is deferred or
   demoted (for example `inventory.craft` -> `inventory.delta`).
2. Phase 2 scaffolding generates the config keys, the per-detector config manifest
   ([SCHEMAS.md](SCHEMAS.md) -> Per-detector config manifest), hook stub, evidence fields,
   and metrics counters from this table.
3. Phase 4+ fixture work adds the normal, violation, and context families from TEST_PLAN.md
   Layer 4 for every row; a detector is not considered for mode raise until its fixture set
   is green in observe mode.
4. Phase 10 calibrates thresholds; placeholder thresholds in SIGNALS.md never gate anything.
