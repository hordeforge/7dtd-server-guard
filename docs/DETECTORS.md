# Detector registry

This is the canonical registry of every planned detector. The signal catalog
([SIGNALS.md](SIGNALS.md)) describes *what* to watch, the policy contract
([POLICY.md](POLICY.md)) defines *how* a signal may act, and this registry names each
detector with a stable ID so config, evidence, fixtures, metrics, and phases all refer to
the same thing. Add a detector here first; Phase 2 scaffolding, config schema
([SCHEMAS.md](SCHEMAS.md) -> Config schema), and the fixture catalog
([TEST_PLAN.md](TEST_PLAN.md) -> Layer 4) are generated from this table.

Rules for the registry:

- A detector ID is `family.subject`, lowercase, unique, and permanent once shipped. A
  renamed detector is a new ID plus an evidence-schema migration, never an in-place edit.
- `Severity ceiling` is set by input authority (POLICY.md -> Severity): any client-declared
  input caps the detector below `Hard`, regardless of how many server-derived inputs it
  also checks. Phase 1 publishes each input's authority class in the hook manifest.
- Default mode is always `observe`. A detector may only be raised to `correct` or
  `enforce` after its phase exit criteria and the policy gates pass.
- `Contexts` are named exemptions that must suppress or widen the detector; every context
  named here needs a fixture family in TEST_PLAN.md.

## Protocol and identity (Phase 4)

| ID | Validation (SIGNALS.md) | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `protocol.stage_order` | Package type against `ProtocolState` before auth/join stage | Server state + package type | Hard | Stock reconnect/resume; never an independent evidence category (vanilla already checks `AllowedBeforeAuth`) |
| `protocol.entity_owner` | Entity ID belongs to the connection at process time | Server ownership map | Hard | Server-originated relays, physics-master delegates (driven vehicles, ragdolls, owned turrets/drones) |
| `protocol.permission` | Debug/creative/godmode/console action checked at execution point | Server permission registry | Hard | Admin and automation principals |
| `protocol.duplicate_session` | Duplicate live identity or session epoch | Platform ID + server epoch | Strong | Stale disconnect, reconnect grace |
| `protocol.malformed` | Invalid enum, NaN, infinity, coordinate, stack size, length | Decode + domain bounds | Hard | None; fail the request safely |
| `protocol.flood` | Per-connection and global cost-weighted token buckets | Server decode cost | Strong (availability) | Server retry behavior, packet loss; `throttle` never counts toward enforcement |

## Movement (Phase 5)

| ID | Validation (SIGNALS.md) | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `movement.displacement` | Integrated speed/acceleration envelope over elapsed server time plus latency window | Client-declared position vs server clock | Strong | Teleport, death, spawn, vehicle enter/exit, knockback, ragdoll, server stall, packet-loss burst, mod movement types, unknown buffs |
| `movement.flight` | Unsupported vertical state over a time window with voxel/ladder/water/vehicle checks | Client-declared position vs server geometry | Strong | Jetpack, parachute, elevator, helicopter, mod flight states |
| `movement.vertical_accel` | Delta velocity vs jump, gravity, fall, impact, explosion, buff impulses | Client-declared position vs server impulse ledger | Strong | Knockback, explosion, ragdoll, server hitch |
| `movement.noclip` | Swept capsule/voxel path crossing solid blocks without a valid transition | Server voxel world; unloaded chunks yield "unknown", never "air" | Strong | Unloaded/generated chunks, vehicle, buffs |
| `movement.teleport_token` | One-use teleport token tied to cause and expiry; client `EntityTeleport` without a token | Server-issued capability token | Hard once all origins enumerated, else Strong | Trader ejection, quests, respawn, console, mods; stock >8 m deltas are ordinary discontinuities |
| `movement.vehicle` | Reconstructed terrain-aware vehicle speed/acceleration limits | Client-simulated physics-master; no server envelope | Weak until reconstruction validated, then Strong | Vehicle physics, collision, passenger motion |
| `movement.edge_distribution` | Distribution of normalized budget consumption | Ledger statistics | Weak | All discontinuity contexts |

## Combat (Phase 6)

Both damage paths (`EntityAlive.DamageEntity` and `NetPackageRangeCheckDamageEntity`) must be
hooked for every combat detector; a validator on one path only protects nothing.

| ID | Validation (SIGNALS.md) | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `combat.cadence` | Fire/use cadence faster than item action permits | Server clock + item action definition | Hard if complete, else Strong | Buffs, mods, reload state, server stall |
| `combat.held_item_ammo` | Attack without valid held item or ammunition | Pre-action authoritative inventory and chamber/reload ledger | Hard | Server-originated item grants |
| `combat.reach` | Attacker origin to authoritative target hit volume at resolved time | Server geometry at the seam | Strong | Moving targets, vehicles, ragdolls |
| `combat.damage` | Recompute allowed base, quality, mods, buffs, target armor, difficulty, hit zone | Mixed: base damage server-derived, hit zone and strength client-declared | Hard if every input authoritative, else Strong | Armor, buffs, difficulty, headshots, DOT, explosive |
| `combat.geometry` | Attack through solid geometry; server ray/voxel line test with penetration rules | Server voxel world | Strong | Weapon penetration rules, unloaded chunks |
| `combat.state` | Damage during death, spawn protection, stun, reload, disallowed animation state | Authoritative state machine | Strong | Spawn protection, buffs, vehicles |
| `combat.target_set` | Multi-target or repeat damage outside weapon rules | Attack correlation ID and target set | Strong | Turrets, explosions, DOT, vehicles |
| `combat.aim` | Aim snap, low reaction time, abnormal angular tracking | Client-declared rotation time series; quantized ~1.4 deg, change-gated | Weak | Skilled players, accessibility devices, interpolation; review-only |
| `combat.acquisition` | Target acquisition before server could expose target | Distance-based entity distribution, no LOS culling | Weak | PvE predictability; review-only, low priority |

## Progression (Phase 8)

| ID | Validation (SIGNALS.md) | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `progression.xp_rate` | XP gain rate beyond any legitimate source | Client-pushed `NetPackageEntityAddExpServer` vs server-earnable causes | Strong | Quests, kills, server events, mod grants |
| `progression.skill_prereq` | Skill/attribute level without spent points or prerequisite | Client-pushed `NetPackageEntitySetSkillLevelServer` vs server rules | Hard if rules recomputable | Mods that grant skills |
| `progression.health_stamina` | Health/stamina beyond attribute maximum | Server attribute-derived bounds | Hard | Buffs, mods |

## Inventory and economy (Phase 7)

| ID | Validation (SIGNALS.md) | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `inventory.delta` | Unexplained positive item delta in the double-entry ledger | Server ledger minus authorized causes | Strong | All authorized causes; reconciliation never accuses |
| `inventory.stack` | Stack exceeds item definition | Authoritative item definition | Hard | Container stacks, vehicles, drones |
| `inventory.craft` | Craft output without ingredients/time/station/recipe | Craft transaction seam; **at risk** (see SIGNALS.md) | Hard only if a seam exists | Workstations, craft cancellation; expected to degrade to `inventory.delta` |
| `inventory.replay` | Duplicate transaction ID or replay | Session-scoped idempotency cache | Hard | Reconnect, container move, craft, trader |
| `inventory.container_race` | Atomic ownership/version check and post-transaction conservation | Server-side atomic slot ownership | Hard | Concurrent moves, split/merge, second-player races |
| `inventory.quality` | Impossible quality/mod/durability combination | Item definition + crafting rules | Hard | Mods that add item quality |
| `inventory.trader` | Trader price or currency mismatch | Trader seam; **at risk** (see SIGNALS.md) | Hard only if a seam exists | Trader state sync; expected to degrade to `inventory.delta` |
| `inventory.rollback` | Disconnect/rollback gain | Durable save epoch + pending transfers | Strong | Crash recovery, disconnect at every step |

## World and entity (Phase 8)

| ID | Validation (SIGNALS.md) | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `world.block` | Block reach, tool, material, cadence, world-bound invariants | Server voxel world + item definitions | Hard for authorization | Falling blocks, explosions, quests |
| `world.claim` | Claim/lock access, allies, parties, protected areas | Server claim database | Hard | Allies, parties, admin |
| `world.wire` | Wire endpoints, powered tile ownership, lock state | Server tile-entity state | Hard | Turrets, drones, vehicles, power tools |
| `world.entity_spawn` | Client-requested entity classes on allowlist, spawn source | Server spawn authorization | Hard | Mods that spawn entities |
| `world.explosion` | Explosion inventory consumption, damage bounds | Server explosion resolution | Strong | Explosives, barrels, vehicles |
| `world.budget` | Per-player action budgets for high-fan-out requests | Server cost accounting | Strong (availability) | Mods that batch actions |

## Availability (Phases 4 and 8)

| ID | Validation (SIGNALS.md) | Authority note | Ceiling | Contexts |
|---|---|---|---|---|
| `availability.cost` | Decoded bytes, package count and cost, fan-out, exceptions | Server decode/process cost | Strong (availability) | Server retry behavior, packet loss; `throttle` never counts toward enforcement |
| `availability.churn` | Reconnect churn, join storms | Server session registry | Strong (availability) | Stale disconnect, reconnect grace; never an accusation |

## Lifecycle

1. Phase 1 records the authoritative seam, input authority classes, and hook manifest entry
   for a candidate detector. If no authoritative seam exists, the detector is deferred or
   demoted (for example `inventory.craft` -> `inventory.delta`).
2. Phase 2 scaffolding generates the config keys, hook stub, evidence fields, and metrics
   counters from this table.
3. Phase 4+ fixture work adds the normal, violation, and context families from TEST_PLAN.md
   Layer 4 for every row; a detector is not considered for mode raise until its fixture set
   is green in observe mode.
4. Phase 10 calibrates thresholds; placeholder thresholds in SIGNALS.md never gate anything.
