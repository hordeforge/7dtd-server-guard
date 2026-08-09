# Design contract index

Reading order for a new contributor: start here, then [DETECTORS.md](DETECTORS.md) (what is
planned), [POLICY.md](POLICY.md) (what a signal may do), then the document that owns the
part you are changing. Every document defers definitions to the document listed as
canonical; when two documents disagree, the canonical one wins and the disagreement is a
bug to fix in the same change.

| Document | Owns | Canonical for |
|---|---|---|
| [POLICY.md](POLICY.md) | Decision vocabulary: modes, actions, severity, confidence, gates, override, appeals, roles, glossary | `Hard`/`Strong`/`Weak`, mode ladder, action set, enforcement gates, appeal dispositions, glossary terms |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What we protect, who attacks, attack scenarios, trust boundaries, out of scope | Protected outcomes, adversaries, trust boundaries, introduced attack surface |
| [SIGNALS.md](SIGNALS.md) | Shared validation primitives: capabilities, conservation, envelopes, state machines, geometry, cost, correlation | Reusable validation mechanics and composition rules |
| [DETECTORS.md](DETECTORS.md) | Stable detector IDs and per-detector ceilings, contexts, lifecycle | The canonical detector list; config/evidence/fixtures reference IDs from here |
| [PROPOSALS.md](PROPOSALS.md) | Non-binding detector idea incubator, promotion gate, rejected ideas | Candidate status only; never detector identity or enforcement behavior |
| [EXECUTION.md](EXECUTION.md) | Prioritized delivery order, inventory contract, dependency behavior, first vertical slice, cross-repo scenarios | What work happens next and its executable exit evidence |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Runtime pipeline, components, hook policy, input authority, ledgers, performance budget, source layout | Component responsibilities, thread rules, hook policy, ledger math, budget |
| [SCHEMAS.md](SCHEMAS.md) | Concrete data contracts: config v1, evidence v1, hook manifest v1, audit v1, health v1, metrics naming | Field-level schema, strict-versioning rules, config keys |
| [RESEARCH.md](RESEARCH.md) | External findings, community survey, open questions, references | Where findings landed; open questions that block or downgrade detectors |
| [TEST_PLAN.md](TEST_PLAN.md) | Test layers, fixture families, adversarial scenarios, reproducibility, release gates | What must be verified before a phase closes |
| [METHODOLOGY.md](METHODOLOGY.md) | The *how*: calibration, labeling, mutation, A/B statistics, red-team, evidence loop, detector lifecycle | Methods the gates rely on; gate evidence artifacts |
| [DECISIONS.md](DECISIONS.md) | Why the design is this way; alternatives considered and rejected | Decision status and reasoning trail |
| [OPERATIONS.md](OPERATIONS.md) | Operator workflows: rollout, incident response, appeals, upgrade/rollback, disclosure | Requirements the Response/Evidence/console components must support (validated in Phase 9) |
| [TODO.md](../TODO.md) | The phase ledger with exit criteria | What is done, what is next, phase order |
| [PRIVACY.md](../PRIVACY.md) | Player monitoring notice, retention schedule, pseudonymization | Retention, what is/not recorded, operator checklist |
| [SECURITY.md](../SECURITY.md) | Vulnerability reporting, in/out of scope, disclosure | Security contact and report classes |
| [README.md](../README.md) | Project identity, scope summary, roadmap overview | Public entry point |

## Reading paths

- **New contributor:** INDEX -> DETECTORS -> POLICY -> ARCHITECTURE -> SCHEMAS ->
  TEST_PLAN -> METHODOLOGY -> TODO.
- **Starting implementation:** EXECUTION -> TODO Phase 0/1 -> ARCHITECTURE -> TEST_PLAN.
- **Proposing a detector:** start in PROPOSALS.md and satisfy its promotion gate. **Adding a
  detector:** DETECTORS.md lifecycle (1. Phase 1 seam + authority, 2. registry
  row, 3. config keys + hook stub + evidence + metrics from SCHEMAS.md, 4. fixture family
  from TEST_PLAN.md Layer 4, 5. calibration in Phase 10). Record the decision in
  DECISIONS.md.
- **Changing enforcement behavior:** POLICY.md is canonical; check THREAT_MODEL.md
  scenarios, DETECTORS.md ceilings, TEST_PLAN.md release gates, and PRIVACY.md notice text
  in the same change.
- **Evidence or config change:** SCHEMAS.md owns the schema; update the hash-chain and
  strict-versioning tests in TEST_PLAN.md Layers 1-4.

## Repo layout

```text
7dtd-server-guard/
├── AGENTS.md                  workspace and repo boundaries
├── README.md                  public entry point
├── TODO.md                    phase ledger
├── Makefile                   docs quality gates (make check)
├── config/
│   ├── server-guard.example.json     example config v1
│   ├── detector-config-manifest.json generated per-detector thresholds (make detectors)
│   └── schemas/                      JSON Schema: config.v1, config-manifest.v1
├── docs/                      indexed contracts plus the non-binding proposal incubator
├── src/                       planned C# source (net48), see ARCHITECTURE.md -> Source layout
├── tests/                     planned test projects
└── tools/
    ├── detector_spec.yaml     canonical detector spec (single source of truth)
    ├── render_detectors.py    renders DETECTORS.md and the config manifest from the spec
    ├── doccheck.py            docs quality gate (em dashes, links, spec, schemas, chain)
    ├── evidence_check.py      evidence hash-chain verifier (make verify-evidence)
    ├── fixtures/              traces/, regression/, generators/ (empty until Phase 4)
    └── surface_inventory/     Phase 1 Mono.Cecil metadata probe (planned)
```

`docs/` and `TODO.md` are the design contract per AGENTS.md. Everything in `src/`, `tests/`,
`config/`, and `tools/surface_inventory/` is planned scaffolding until its phase starts;
empty directories carry a README stating what goes there.
