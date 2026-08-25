# 🛡️ Landclaim (7DTD ServerGuard)

> **Part of [HordeForge](https://github.com/hordeforge)**: High-Performance Systems Engineering for 7 Days to Die.

![CI](https://github.com/hordeforge/7dtd-server-guard/actions/workflows/ci.yml/badge.svg)
![license](https://img.shields.io/github/license/hordeforge/7dtd-server-guard)
![release](https://img.shields.io/github/v/release/hordeforge/7dtd-server-guard)
![languages](https://img.shields.io/github/languages/count/hordeforge/7dtd-server-guard)
![top language](https://img.shields.io/github/languages/top/hordeforge/7dtd-server-guard)

Server-side behavioral anti-cheat and exploit mitigation for 7 Days to Die dedicated servers. The target is the locally installed dedicated V3.1.0 (b14) Mono server.

## Scope

Server Guard observes facts the dedicated server can verify: authenticated identity,
network request order, movement, combat, inventory conservation, crafting, loot,
world interaction, entity creation, and privileged operations. It produces compact,
explainable evidence and can reject actions that violate hard game invariants.

It does not scan client processes, drivers, files, overlays, or memory. It cannot prove
that a player uses an aimbot or wallhack from one event. A C# mod requires an EAC-off
server, so this project complements server administration on modded servers and is not
a replacement for Easy Anti-Cheat.

## 📚 Modding Best Practices

See the canonical **[HordeForge 7DTD Modding Best Practices Guide](https://github.com/hordeforge/.github/blob/main/MODDING_BEST_PRACTICES.md)** for engine load order rules, EAC-off requirements, `ModInfo.xml` specifications, and V3.1.0 compatibility notes.

## Safety defaults

Detector **mode** (Observe/Correct/Enforce) and the **actions** those modes may take are defined
canonically in the [policy contract](docs/POLICY.md); the summary below defers to it.

- `Observe`: record evidence only. This is the initial and default mode.
- `Correct`: reject or correct only impossible state transitions with tested Hard invariants.
- `Enforce`: quarantine or kick only after the enforcement gates in the policy (independent
  signals or a repeated hard invariant) and operator opt-in.
- Permanent bans are never automatic. Steam VAC / publisher game bans are out of scope.
- Admins, teleports, deaths, respawns, vehicles, buffs, quests, high latency, server stalls,
  and other mods are explicit contexts, not afterthoughts.
- Raw packet payloads, chat text, IP addresses, and secrets are not retained by default.

## Planned deliverable

The mod will be a `net48` DLL installed as `Mods/7dtd-server-guard/7dtd-server-guard.dll`,
using the stock `0_TFP_Harmony` runtime plus stable `ModEvents` where available. Vanilla
clients can join an EAC-off server without installing the mod.

## Documents

Start at the [design contract index](docs/INDEX.md) for reading order and ownership.

- [Design contract index](docs/INDEX.md) (reading order, canonical owners, repo layout)
- [Detector registry](docs/DETECTORS.md) (stable detector IDs, severity ceilings, contexts)
- [Policy and governance contract](docs/POLICY.md) (modes, actions, severity, gates, appeals)
- [Threat model](docs/THREAT_MODEL.md)
- [Architecture](docs/ARCHITECTURE.md) (components, hook policy, ledgers, budget, source layout)
- [Schemas](docs/SCHEMAS.md) (config v1, evidence v1, hook manifest v1, metrics naming)
- [Validation primitives](docs/SIGNALS.md) (shared ledger, capability, geometry, and budget mechanics)
- [Detector proposal incubator](docs/PROPOSALS.md) (non-binding ideas and promotion gate)
- [Execution plan](docs/EXECUTION.md) (next evidence, primitive order, and first vertical slice)
- [Research and constraints](docs/RESEARCH.md)
- [Verification plan](docs/TEST_PLAN.md)
- [Methodology](docs/METHODOLOGY.md) (calibration, labeling, mutation, A/B, red-team)
- [Decision log](docs/DECISIONS.md)
- [Operations and incident runbook (draft)](docs/OPERATIONS.md)
- [Detailed work plan](TODO.md)

## Design contract

The documents in `docs/`, the phase gates in `TODO.md`, and `AGENTS.md` are the project's
design contract: update them when evidence changes an assumption, and keep them consistent
with the policy contract in [docs/POLICY.md](docs/POLICY.md).

## Governance

- [Privacy and player-monitoring notice](PRIVACY.md)
- [Security and disclosure policy](SECURITY.md)
- [License: AGPL-3.0](LICENSE)

## Roadmap

Phase 0 (policy, drafted; human review pending) → 1 authoritative surface inventory →
2 scaffold and safe runtime → 3 evidence foundation → 4 protocol and permission invariants →
5 movement ledger → 6 combat ledger → 7 inventory and economy conservation →
8 world, entity, and automation detectors → 9 response, operations, and appeals →
10 calibration and release. Enforcement stays off until each detector passes its phase gates;
the ledger, exit criteria, and known at-risk seams live in [TODO.md](TODO.md).

## Development

Bootstrap (once per clone; needs Python 3.12+, the minor pinned in
[.python-version](.python-version), which CI installs exactly):

- `make setup`: create a project-local `.venv` and install the dependencies declared
  in `requirements.txt`. Nothing is installed globally.

Loop:

- `make check`: docs quality gate (em dashes, internal links, detector spec and ceiling
  rule, registry sync, JSON Schemas, config/schema cross-references). Run before opening
  any change.
- `make detectors`: re-render the detector registry tables and the per-detector config
  manifest from `tools/detector_spec.yaml` (the single source of truth for detectors).
- `make exercise`: validate the design-time replay contract against the sample trace.
- `make test-tools`: run the shipped Python tooling's negative self-tests plus its fuzzers
  (evidence parser, schema validator, replay-trace contract checker).
- `make ci`: everything CI runs, locally in one step (`check` + `test-tools`).

The detector spec, data schemas, and methodology are the design contract; see
[docs/INDEX.md](docs/INDEX.md) for who owns what.

## Project status


Research and design contract only. Phase 0 policy review is the blocking gate; the review
checklist is in [TODO.md](TODO.md). Run `make check` for the docs quality gate. No
enforcement code has been enabled.
