# Signal catalog

This catalog describes *what* each signal family validates and how. The canonical list of
detectors with stable IDs, severity ceilings, and contexts is the
[detector registry](DETECTORS.md); config, evidence, metrics, and fixtures all use the
registry IDs. All thresholds are placeholders until recorded from the exact game build. Detectors consume
authoritative state and explicit context. A threshold is not a proof. Severity terms
(Hard/Strong/Weak) and what each may justify are defined in the [policy contract](POLICY.md).
A signal's ceiling is set by its inputs' authority and role: any validator whose
*decision* inputs include a client-declared value is capped below `Hard` unless a hard
condition documents complete server-side determination (see [POLICY.md](POLICY.md) →
Severity and DECISIONS.md D-15). Observed quantities may be client-declared. Phase 1
records each validator input's authority class and role; the detector spec
([DETECTORS.md](DETECTORS.md)) declares both, and `make check` enforces the ceiling rule.

## Identity, authorization, and protocol

| Signal | Validation | Strength | Required exclusions |
|---|---|---:|---|
| Package before auth/join stage | Package type against `ProtocolState` | Hard | Stock reconnect/resume paths. Vanilla already checks `AllowedBeforeAuth`; this is defense in depth and never counts as an independent evidence category |
| Entity ID does not belong to connection | Resolve connection owner at process time | Hard | Server-originated relays; physics-master delegated entities (driven vehicles, ragdolls, owned turrets/drones) that clients legitimately simulate |
| Privileged/debug action without permission | Check server permission at execution point | Hard | Admin and automation principals |
| Duplicate live identity/session | Platform ID plus session epoch | Strong | Stale disconnect and reconnect grace |
| Join, chat, command, inventory, or expensive package flood | Per-connection token buckets by cost class | Strong | Server retry behavior, packet loss |
| Invalid enum, NaN, infinity, coordinate, stack size, or length | Decode and business-domain validation | Hard | None; fail request safely |

## Movement

Maintain accepted position, velocity, grounded state, stance, encumbrance, buffs, stamina,
water, ladder, jump, fall, knockback, ragdoll, death, spawn, teleport, vehicle seat, vehicle
limits, jetpack, parachute, elevator, helicopter flight, last server correction, ping/jitter,
missing-sample interval, and server frame debt. Vanilla V3 exposes jetpack, parachute, and
elevator states; movement mods on EAC-off servers add more. Unknown flight states must widen
uncertainty, not accuse.

| Signal | Method | Strength |
|---|---|---:|
| Excess horizontal displacement | Integrate maximum speed and acceleration over elapsed server time plus a bounded latency envelope | Strong |
| Flight or hover | Unsupported vertical state over a time window with voxel/ladder/water/vehicle checks | Strong |
| Impossible vertical acceleration | Compare delta velocity with jump, gravity, fall, impact, explosion, and buff impulses | Strong |
| No-clip | Swept capsule/voxel path crosses solid blocks without a valid state transition; unloaded or ungenerated chunks along the path yield "unknown", never "air" | Strong |
| Teleport request without server-issued capability | One-use teleport token tied to cause and expiry. The stock protocol emits `NetPackageEntityTeleport` for any >8 m positional delta (rubber-banding, chunk stalls), so a client teleport package is an ordinary discontinuity, not a violation. Server-side origins (trader ejection, quests, respawn, console, mods) go through `NetPackageTeleportPlayer` and must all issue tokens | Hard once all origins are enumerated, else Strong |
| Vehicle speed/acceleration violation | Vehicle physics is client-simulated under the physics-master scheme; the server holds no authoritative envelope. Reconstructed terrain-aware limits only | Weak until reconstruction is validated, then Strong |
| Repeated edge-of-limit motion | Distribution of normalized budget consumption | Weak |

Do not divide distance by one packet interval and ban. Accumulate a debt/credit envelope,
cap credit, and reset on named discontinuities. High ping widens uncertainty, not physical speed.

## Combat

The V3 damage frame carries client-computed strength, hit body part, hit direction, and
critical flag; the server applies rather than derives them. Two damage paths exist and both
must be hooked: the primary damage request `NetPackageDamageEntity` and the range-check path
`NetPackageRangeCheckDamageEntity` (both confirmed in the V3.1.0 census;
[RESEARCH.md](RESEARCH.md) finding 9). Melee misses and
cosmetic action/reload broadcasts are omittable by a hostile client, so cadence is observable
only at damage application. Consequently most combat validators bound client claims rather
than recompute them, and "Hard" applies only where every decision input is
server-authoritative.

Cadence bound: for a weapon family with item-action interval `T_action` and reload/chamber
state fully server-known, consecutive damage applications from the same connection are
legal when `dt_damage >= T_action - cadence_tolerance_ms`; a shorter interval is a cadence
finding. `T_action` comes from the item XML action definitions; `cadence_tolerance_ms`
absorbs tick quantization (default 100 ms placeholder). Because damage application is the
only reliably observable event (fires, reloads, and misses can be omitted by a hostile
client), the bound is computed at damage application only.

| Signal | Validation | Strength |
|---|---|---:|
| Fire/use cadence faster than item action permits | Server clock, item action, modifiers, reload state | Hard if complete, else Strong |
| Attack while no valid held item or ammunition | Pre-action authoritative inventory and chamber/reload ledger | Hard |
| Reach violation | Attacker origin to authoritative target hit volume at resolved time | Strong |
| Impossible damage | Recompute allowed base, quality, mods, buffs, target armor, difficulty, hit zone | Hard if complete |
| Attack through solid geometry | Server ray/voxel line test with weapon penetration rules | Strong |
| Damage during death, spawn protection, stun, reload, or disallowed animation state | Authoritative state machine | Strong |
| Multi-target or repeat damage outside weapon rules | Attack correlation ID and target set | Strong |
| Aim snap, low reaction time, abnormal angular tracking | Rotation time series plus visible target geometry | Weak |
| Target acquisition before server could expose target | Interest/visibility history where observable | Weak |

Aim and ESP signals only create review evidence. Skilled players, accessibility devices,
network interpolation, PvE target predictability, and missing client input make automatic bans unsafe.
Client rotation reaches the server quantized to ~1.4 degrees, change-gated, and unevenly
sampled, so aim time series have low fidelity. Entity distribution is distance-based with no
server-side line-of-sight culling, so "target acquired before exposure" has almost no
observable surface in vanilla; both stay Weak and low priority.

## Progression

Clients push XP and skill-level values to the server (`NetPackageEntityAddExpServer`,
`NetPackageEntitySetSkillLevelServer`). Health and stamina sync the same way.

| Signal | Validation | Strength |
|---|---|---:|
| XP gain rate beyond any legitimate source | Bound per-tick and windowed XP against maximum earnable causes | Strong |

XP envelope: accumulate pushed XP per player per tick and per rolling window
(`window_minutes`); a finding fires when `xp_in_window > max_xp_per_minute * window_minutes`
or `xp_in_tick > max_xp_per_tick`. The bounds are placeholders derived in Phase 8 from the
maximum legitimate earn rate (kills, quests, events, mod grants); because the server cannot
enumerate every mod earn source, the envelope stays Strong. `NetPackageEntityAddExpServer`
is validated at the execution seam.
| Skill/attribute level without spent points or prerequisite | Server-side progression rule check | Hard if rules recomputable |
| Health/stamina beyond attribute maximum | Authoritative attribute-derived bounds | Hard |

## Inventory, economy, crafting, and loot

Use a double-entry item ledger. Every positive or negative delta needs an authorized cause:
loot transfer, craft input/output, repair, consume, fire, drop, pickup, quest reward, trader,
death backpack, admin grant, mod action, vehicle/drone/container move, or rollback reconciliation.

| Signal | Validation | Strength |
|---|---|---:|
| Unexplained positive item delta | Snapshot delta minus authorized causes | Strong |
| Stack exceeds item definition | Authoritative stack limit | Hard |
| Craft output without ingredients/time/station/recipe | Craft transaction state machine. **At risk:** the V3.1.0 census shows no craft/recipe/workstation-queue package; `NetPackageInventoryTransactionRequest` is a transaction package whose craft coverage is the Phase 1 question. Expected to degrade to unexplained-delta (Strong) unless a seam is found | Hard only if a seam exists |
| Duplicate transaction ID or replay | Session-scoped idempotency cache | Hard |
| Container race/dupe | Atomic ownership/version check and post-transaction conservation | Hard |
| Impossible quality/mod/durability combination | Item definition and crafting rules | Hard |
| Trader price or currency mismatch | Server-computed transaction. **At risk:** the census shows `NetPackageTraderData` sync only, no price/currency transaction package; purchases look like client-side inventory edits against synced trader state. Verify an authoritative decision point in Phase 1 or defer with craft | Hard only if a seam exists |
| Disconnect/rollback gain | Reconcile durable save epoch and pending transfers | Strong |

The ledger must account for other mods through a registered server-origin cause API. Every
registered cause invocation records the calling mod's identity in the evidence stream, so a
buggy or over-broad cause is auditable instead of silently blinding the ledger. Unknown
server-origin changes are logged separately and do not accuse a player.

## World and entity actions

Validate block reach, line of interaction, tool, stamina, claim permission, block damage,
repair/upgrade material, action cadence, placement support, world bounds, protected areas,
wire endpoints, powered tile ownership, lock state, turret/drone/vehicle ownership, entity type,
spawn source, explosion inventory consumption, and per-player action budgets.

Hard rejection candidates include unauthorized locked-container access, claim violations,
invalid wire endpoints, out-of-bounds blocks, client-requested entity classes not on an allowlist,
negative/overflow damage, and duplicate transaction replay. Mining speed, perfect hidden-loot
routing, repetitive paths, and unusually efficient farming are weak review signals only.

## Availability signals

Track decoded bytes, package count and cost, malformed decode count, request fan-out, exceptions,
chunk/map requests, inventory snapshots, chat/command frequency, reconnect churn, and work queued
per identity and source prefix (in-memory only; persisted flood evidence carries pseudonym and
cost class, never IPs). Enforcement uses the `throttle` action defined in the policy contract:
cost-weighted token buckets with global load shedding, recorded but never counting toward any
enforcement gate.

Cost classes define per-package weight in the token buckets (placeholders until profiled
against the pinned build):

| Class | Example packages (V3.1.0 census names) | Weight |
|---|---|---|
| Tiny | `NetPackageInfo`, `NetPackageMeasure`, `NetPackageNetMetrics`, keep-alive/ack | 1 |
| Play | `NetPackageEntityPosAndRot`, `NetPackageEntityRelPosAndRot`, `NetPackageEntityRotation`, `NetPackageDamageEntity`, `NetPackageItemReload` | 2 |
| State | `NetPackageSetBlock`, `NetPackageInventoryTransactionRequest`, `NetPackageTileEntity`, `NetPackageWireActions`, `NetPackagePickupBlock` | 5 |
| Expensive | `NetPackageChunk`, `NetPackageMapChunks`, `NetPackagePOIAround`, `NetPackageWorldInitInfoRequest`, `NetPackageInventoryDataRequest/Response`, `NetPackageDynamicMesh` | 20 |

Each connection starts with a burst allowance and refills at a fixed per-second rate
(per-class or global, configurable). Global load shedding caps the cross-connection
aggregate cost per tick. Flood evidence records carry pseudonym and cost class only.

Token bucket math (placeholders until profiled against the pinned build): a connection's
balance `b` starts at `burst` and updates each tick (`dt` at 20 TPS = 50 ms) as
`b = min(burst, b + refill_per_second * dt) - cost(package)`, where `cost` is the package's
class weight. A package that would make `b < 0` is shed or delayed (`throttle`) instead of
processed. Global load shedding sums `cost(package)` across connections per tick and sheds
the excess beyond `global_cost_per_tick`. Bucket state is in-memory only and never
persisted; flood evidence records carry pseudonym and cost class, never IPs.

Network-level volumetric attacks belong in the firewall, not the game thread.

## Where each family is implemented

| Signal family | TODO phase |
|---|---|
| Identity, authorization, and protocol | Phase 4 |
| Movement | Phase 5 |
| Combat | Phase 6 |
| Inventory, economy, crafting, and loot | Phase 7 |
| Progression | Phase 8 |
| World and entity actions | Phase 8 |
| Availability | Phases 4 and 8 |

Thresholds in this catalog are placeholders until calibrated in Phase 10.

