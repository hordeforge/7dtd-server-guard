# Research and constraints

Research date: 2026-07-21. Local target: 7 Days to Die dedicated V3.1.0 (b14), Unity Mono
(the pinned build; see [POLICY.md](POLICY.md)). The `7dtd-research` narratives under Local
evidence now include **V3.1.0** regenerable dumps (`il/netpackages-v3.1.0/`,
`il/dedi-complete-v3.1.0/`, `il/deep-v3.1.0/`, `il/loop-complete-v3.1.0/`); older narrative
text was produced against V3.0.1 (b4). Phase 1 still re-verifies every surface against the
pinned build before any hook is written, but the build delta risk is partially de-risked.

## Findings

1. Valve recommends authoritative servers that control state and validate position and other
   gameplay state. Steam game bans require publisher access and game integration; a community
   server mod cannot issue publisher game bans. Local kick/ban policy is the realistic boundary.
2. Steam requires clear notice and understandable reasons when players are excluded. Evidence IDs,
   operator review, and appeal metadata are product requirements, not optional polish.
3. Harmony supports prefix, postfix, transpiler, finalizer, and reverse patches. Runtime security
   hooks should prefer prefixes/postfixes on exact methods. Transpilers add compatibility risk and
   are excluded from the initial anti-cheat design.
4. Server-side behavioral research supports time-series and multi-signal analysis, but reported
   false-positive rates remain material. Statistical aim/bot models must not directly ban players.
5. Security logging guidance emphasizes consistent event data, tamper resistance, restricted
   sensitive data, secure transport, and avoiding alert fatigue. The evidence design follows that.
6. This installed server exposes lifecycle hooks through `ModEvents`, including player login,
   join, spawn, disconnect, save, entity kill, game message, and chat events.
7. The installed assembly also exposes EAC authorization/encryption types and `NetPackageEAC`.
   Server Guard will not patch or emulate them. A code mod runs with EAC disabled in this workspace.
8. The V3 protocol includes authoritative processing surfaces for movement, damage, inventory,
   transaction, wire, teleport, player, and entity packages. Exact hook viability must be verified
   from metadata and smoke tests for every supported game build.
9. The V3.1.0 netpackage census (193 types, `il/netpackages-v3.1.0/INDEX.md`) names the seams:
   `NetPackageDamageEntity` and `NetPackageRangeCheckDamageEntity` are the two damage paths;
   `NetPackageEntityPosAndRot`/`RelPosAndRot`/`EntityPhysics`/`PlayerStats` carry movement;
   `NetPackageEntityTeleport` (client) vs `NetPackageTeleportPlayer` (server) split the
   teleport story; `NetPackageInventoryTransactionRequest/Response` is a real transaction
   package (craft and trader price/currency transactions still have no package in the
   census); `NetPackageEntityAddExpServer` and `NetPackageEntitySetSkillLevelServer` are the
   client-pushed progression seams; `NetPackageConsoleCmdClient/Server` are the console
   seams; `NetPackageSetBlock`, `NetPackageWireActions`, `NetPackageExplosionInitiate`, and
   `NetPackageRequestToSpawnEntity` are the world/entity seams. Every detector's declared
   seam in `tools/detector_spec.yaml` cites these candidates; Phase 1 verifies them.

## Where findings landed

Each finding is implemented in the design contract section named below, so new evidence
updates the owning document, not just this one:

| Finding | Owning document section |
|---|---|
| 1 (publisher game bans) | POLICY.md → Action set |
| 2 (notice and reasons) | PRIVACY.md; POLICY.md → Roles and appeals |
| 3 (prefix/postfix over transpilers) | ARCHITECTURE.md → Hook policy |
| 4 (statistical models) | POLICY.md → Severity; SIGNALS.md → Combat |
| 5 (logging guidance) | ARCHITECTURE.md → Evidence model |
| 6 (ModEvents surface) | ARCHITECTURE.md → Hook policy |
| 7 (EAC types) | THREAT_MODEL.md → Out of scope; SECURITY.md → Out of scope |
| 8 (authoritative processing surfaces) | TODO.md → Phase 1; TEST_PLAN.md → Layer 3 |
| 9 (V3.1.0 census names the seams) | DETECTORS.md → seam fields; tools/detector_spec.yaml; TODO.md → Phase 1 |

## Community landscape (surveyed 2026-07-21)

Existing server-side tools, what they detect, and how they respond:

| Tool | Approach | Anti-cheat surface | Response model |
|---|---|---|---|
| [CSMM](https://docs.csmm.app/) + [CPM](https://docs.csmm.app/en/prismacore/cpmsettings) | Web manager + server mod (PrismaCore) | Flying by trigger height, godmode/spectator by admin level, damage threshold (default 5000), level-jump detection, location tracker | Configurable command per detection (kick/ban/etc.), admin-level exemptions |
| [Botman](https://botman.nz/features) | External bot driving telnet | Teleport and duping detection from telnet logs, inventory blacklist for new players, movement/inventory logging with replay | Timeout (50 km skyward), exile/prison zones, automatic ban for teleport hackers |
| [ServerTools](https://github.com/dmustanger/7dtd-ServerTools) | Server mod | Fly/no-clip, speed, spectator, godmode, invalid items/stacks/buffs, dupe log, infinite ammo, player stats, family-share accounts, damage threshold, X-ray screen blackout | Automatic ban on most detectors, configurable kick/alert, strike-based jail system |
| [NAIWAZI-AntiCheat](https://github.com/Naiwazi/NAIWAZI-AntiCheat) | Server mod, Harmony + packet validation | 12 categories: inventory/container contraband, godmode, invisibility, stack overflow, block/entity damage anomalies, mass block removal, attribute/skill/damage anomalies | Ban, warn, or destroy item; fly detection shipped disabled as experimental |
| [Dedicated Server anti-cheating](https://www.nexusmods.com/7daystodie/mods/10298) | Server mod, closed feature bundle | 66 modules: packet inspection, server-side damage verification, fly/speed/noclip/god, range mining, stack/dupe checks, spawn limits, chat spoofing, territory protection | Blocking and bans per module |
| [Taco Anti Cheat](https://7daystodiemods.com/taco-anti-cheat/) | Server mod, hardening only | Randomizes debug/creative/kill command names per boot, strips admin items from creative menu | Prevention, no detection |
| [Multiplayer Anticheat](https://www.nexusmods.com/7daystodie/mods/3212) | XML-only (EAC stays on) | Removes creative/spawn menu items, throttles enclosed vehicle speed, hardens loot/trader economy against dupers | Prevention, no detection |

Implications adopted into this design:

1. Every surveyed detector is a single-threshold trigger with an immediate response
   (ServerTools and Botman auto-ban on first fly/teleport detection). None separates
   observation from enforcement, so false-positive stories are common in their forums. The
   observe → correct → enforce ladder and two-independent-categories kick gate remain the
   main differentiator.
2. Admin-level exemptions (CPM) and fully-spawned checks (CPM flying fix) confirm the need
   for named context exemptions: spawn-in, teleport, admin, vehicle.
3. NAIWAZI shipping fly detection disabled as experimental, and Botman breaking when other
   mods swallow telnet teleport lines, both support pinning authoritative hooks over log
   scraping and failing open per detector.
4. Inventory contraband lists, family-share policy, and X-ray screen tricks are operator
   policy or client-visual mitigations, not integrity invariants; they stay out of scope.
5. No surveyed tool provides tamper-evident evidence, pseudonymization, appeal flow, or a
   false-positive regression corpus. These are unique value, keep them first-class.
6. Command-name hardening (Taco) is complementary and cheap; consider a config option that
   validates privileged commands at execution time (already Phase 4) rather than renaming.

## Open research questions

These questions block or downgrade specific detectors; each is resolved by the Phase 1 surface
inventory against the pinned build, unless noted otherwise.

| Question | If unresolved | Resolved by |
|---|---|---|
| Is there a craft/recipe/workstation-queue seam the server can hook? | Craft detector degrades to unexplained-delta (Strong). The V3.1.0 census shows no craft package; whether `NetPackageInventoryTransactionRequest` covers craft transactions is the Phase 1 question | Phase 1, Phase 7 |
| Is there an authoritative trader price/currency decision point? | Trader detector degrades to unexplained-delta (Strong). The census shows `NetPackageTraderData` sync only, no price/currency transaction package | Phase 1, Phase 7 |
| Which client values does the vanilla server already validate or overwrite? | Duplicate validation, wrong authority class | Phase 1 |
| Does the movement envelope hold against server-authoritative state on the pinned build? | Movement stays Strong, never Hard | Phase 1, Phase 5 |
| Do `EntityAlive.DamageEntity` and `NetPackageRangeCheckDamageEntity` cover the same attack surface? | One path leaves a bypass | Phase 1, Phase 6 |
| Can vehicle physics-master limits be reconstructed server-side? | Vehicle signals stay Weak | Phase 5 |
| Which seams changed between V3.0.1 (b4) and V3.1.0 (b14)? | Hooks misresolve; fail-open limits the damage, coverage gaps remain | Phase 1 re-verification |

## Primary references

- Valve, [Steamworks anti-cheat and game bans](https://partner.steamgames.com/doc/features/anticheat)
- Valve, [Anti-Cheat Integration](https://partner.steamgames.com/doc/features/anticheat/vac_integration)
- Harmony, [Patching](https://harmony.pardeike.net/articles/patching.html)
- OWASP, [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- OWASP, [Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)
- Kang et al., [Multimodal game bot detection using user behavioral characteristics](https://pmc.ncbi.nlm.nih.gov/articles/PMC4844581/)
- Mitterhofer, Kruegel, Kirda, Platzer, [Server-side bot detection in massively multiplayer online games](https://www.eurecom.fr/en/publication/2860) (IEEE Security & Privacy, 2009)
- Yeung and Lui, [Dynamic Bayesian approach for detecting cheats in multi-player online games](https://research.cuhk.edu.hk/en/publications/dynamic-bayesian-approach-for-detecting-cheats-in-multi-player-on-2/)

## Local evidence

- `../../7dtd-research/il/netpackages-v3.1.0/INDEX.md`: V3.1.0 netpackage census (193 types) with read/write/process sizes; the seam source for `tools/detector_spec.yaml`.
- `../../7dtd-research/docs/managers.md`: `ModEvents` inventory.
- `../../7dtd-research/docs/inventories/netpackages.md`: network package inventory and complexity.
- `../../7dtd-research/docs/protocol-frames.md`: decoded movement and damage frame structure.
- `../../7dtd-research/docs/inventories/gaps.md`: EAC and authoritative method surface inventory.
- `../AGENTS.md`: workspace EAC, runtime, build, and evidence constraints.

These local files are regenerable metadata narratives. No game assembly is copied into this project.

