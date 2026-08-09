# Threat model

## Protected outcomes

1. Fair player movement, combat, looting, crafting, trading, and building.
2. Conservation of items, currency, ammunition, durability, health, stamina, and XP.
3. World integrity: blocks, containers, claims, vehicles, drones, turrets, and entities.
4. Account and permission integrity across Steam, EOS, cross-platform identity, and reconnects.
5. Server availability under malformed, repeated, or adversarial requests.
6. Evidence quality sufficient for a moderator to reproduce and review a decision.

The table below maps each outcome to the detector families that protect it and the strongest
response those signals may justify alone:

| Outcome | Detector families (DETECTORS.md) | Severity ceiling | Strongest response alone |
|---|---|---|---|
| 1 Movement and combat fairness | Movement, Combat | Strong (Hard only where every decision input is server-authoritative) | `correct` (Hard); record/review otherwise |
| 2 Conservation | Inventory and economy, Progression | Hard where authoritative, else Strong | `correct`; cause-token ledger |
| 3 World integrity | World and entity, Inventory | Hard for authorization | `correct`, `quarantine` |
| 4 Account and permission integrity | Protocol, Progression | Hard | reject at execution point |
| 5 Server availability | Availability | Not an accusation | `throttle` |
| 6 Evidence quality | All detectors + EvidenceStore | n/a | `record`, hash chain, review |

## Adversaries

- A modified client that sends validly encoded but impossible or unauthorized requests.
- A client that manipulates movement, timing, fire cadence, reach, inventory, crafting, or loot.
- A bot that automates repetitive gameplay while remaining within individual hard limits.
- A player abusing a vanilla duplication, rollback, disconnect, or transaction race.
- A stolen or shared account. Identity history is evidence, not proof of the human operator.
- A malicious mod or administrator. The DLL cannot defend against code with equal server trust.
- A packet flood or join churn. Host firewall and rate limiting remain part of defense in depth.
- A player weaponizing the anti-cheat itself: inducing findings against a victim (container
  races, explosion knockback, session games) to trigger corrections or enforcement on them.
- An attacker targeting the review surface: dashboard authentication bypass or session theft,
  and interception of webhook alert endpoints.

Each adversary is implemented as at least one fixture in TEST_PLAN.md → Adversarial scenarios.

## Attack scenarios

Concrete narratives; each maps to an adversary above and a detector family in DETECTORS.md.

| Scenario | Exploit | Signal and response |
|---|---|---|
| Teleport skip | During a chunk stall, a client sends `EntityTeleport` to cover ground it never moved | Movement: teleport without a server-issued capability token. Hard once all origins are enumerated, else Strong; stock >8 m deltas remain ordinary discontinuities |
| Stack overflow | Client claims a stack of 100 for an item whose authoritative stack limit is 50 | Inventory: stack exceeds item definition (Hard, `correct`) |
| Replayed transaction | Client replays a container move twice | Inventory: session-scoped idempotency (Hard); the second application is a no-op |
| Induced findings | Attacker repeatedly knocks a victim to push movement debt onto them | Attribution: impulses initiate on the attacker; findings attribute to the initiator or suppress, never the victim |
| Flood and join churn | High-fan-out or malformed request flood to starve the game thread | Availability: cost-weighted token buckets, `throttle`; never counts toward enforcement |
| Privilege reuse | Debug/creative/godmode action without admin permission | Protocol: permission checked at execution point (Hard) |
| Review-surface theft | Stolen dashboard session or spoofed webhook alert | Review-surface: authenticated dashboard, evidence IDs only, alert sink off the game thread |

## Attack surface introduced by Server Guard

Reviewers should weigh the surfaces this mod itself adds, all fail-open by design:

- Harmony hooks on pinned seams: full signature and token resolution, runtime fault guard.
- Config files: strict versioned schema, invalid input refuses startup.
- Evidence store and identity map: permission-restricted local files, tombstone redaction.
- Console commands: permissioned and audited.
- WebDashboard: ships only after authentication and permission checks are tested (Phase 3).
- Operator webhook: evidence IDs only, sent off the game thread.
- Cause API for other mods: records calling-mod identity in the evidence stream.

## Trust boundaries

Trusted: dedicated-server process, authoritative world state, server clock, installed mod
configuration, locally written evidence keys, and explicit operator actions.

Untrusted: all client-supplied position, rotation, claimed hit, item stack, action timing,
display name, chat, reconnect state, and network ordering outside the server's validated state.

Conditionally trusted: game APIs and other mods. Every hook is build-pinned and fail-open in
observe mode. Compatibility exceptions must be named and measured, never hidden in a global
threshold increase.

## Out of scope

- Client memory, process, module, screenshot, input-device, or kernel inspection.
- Deobfuscating or bypassing EAC.
- Preventing information disclosure already sent by the stock game protocol.
- Automatically proving aimbot, ESP, or wallhack use from behavioral coincidence.
- Moderating ordinary chat content. Spam rate can be availability evidence; content policy is separate.
- Protecting against a compromised host, malicious server admin, or malicious same-process DLL.
