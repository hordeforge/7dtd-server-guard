# Methodology

This document owns the *how*: the methods the phase gates and test layers rely on.
[TEST_PLAN.md](TEST_PLAN.md) owns *what* must be verified, [TODO.md](../TODO.md) owns
*when* each phase runs, and [POLICY.md](POLICY.md) owns *what a decision may do*. When a
method changes, update this document and the gate it feeds in the same change.

## 1. Evidence-based design updates (the loop)

Research and live findings update the design contract through one loop, so the reasoning
trail stays intact:

1. A finding or research result contradicts an assumption in the contract.
2. Update the owning document ([INDEX.md](INDEX.md) lists who owns what).
3. Record why in [DECISIONS.md](DECISIONS.md) (new entry or `superseded` on the old one).
4. If it changes a detector, update `tools/detector_spec.yaml` and re-render
   (`make detectors`), then update the affected fixtures in TEST_PLAN.md Layer 4.
5. Re-run `make check`; the doccheck gate fails if the contract is inconsistent.

Boundary: stock-game reverse engineering lives in `../7dtd-research/`, never here; this
repo cites the regenerable dumps (for example the V3.1.0 netpackage census) and records the
design consequence.

## 2. Detector lifecycle

From idea to enforcement, a detector passes through eight steps. Steps 1-3 may run in any
order; 4-8 are gated:

1. **Idea**: record the candidate and promotion evidence in PROPOSALS.md. Put stock-game
   unknowns in RESEARCH.md. If the idea is rejected, keep the reason in PROPOSALS.md and
   record policy or architecture consequences in DECISIONS.md.
2. **Seam and authority**: Phase 1 verifies the candidate seam (the detector spec's `seam`
   field) against the pinned build and publishes each input's authority and role.
3. **Spec**: add the detector to `tools/detector_spec.yaml` (id, family, phase, ceiling,
   default mode, inputs, algorithm, state, thresholds, contexts, fixtures, seam) and
   re-render. The doccheck gate enforces the ceiling rule and the normal+violation fixture
   requirement.
4. **Fixtures**: declare fixture families in the spec; write Layer 4 traces for each
   declared family (TEST_PLAN.md Layer 4).
5. **Observe soak**: run in observe mode on the operator's server for the detector's
   minimum observation window; label findings (section 4).
6. **Calibrate**: Phase 10 threshold selection and metric reporting (section 3).
7. **Mode raise**: POLICY.md gates, dry-run diff review, explicit operator opt-in.
8. **Operate**: incident response and rollback paths in OPERATIONS.md.

A detector may be deferred at any step; the registry records the deferral rather than
deleting the row silently.

## 3. Calibration methodology (Phase 10)

Calibration converts placeholder thresholds into measured operating points.

- **Data**: labeled findings from observe soak (section 4), per detector, with the context
  (latency, vehicle, buffs, admin, teleport) recorded. Include suppressed findings.
- **Splits**: per detector, split by *time* into train, validation, and holdout; never tune
  thresholds on sessions that are later reported as evaluation. A detector's calibration is
  only valid for the build it was measured on.
- **Metrics**: precision, recall, false-positive rate (FPR), and F1 at the chosen operating
  point, reported per detector and per context, with confidence intervals (Wilson for
  proportions; bootstrap for percentile costs). Hard-invariant false positives are the
  worst class: a single legal-context false correction fails the detector's Correct-mode
  gate regardless of F1.
- **Threshold selection**: grid search over the declared threshold keys from the detector's
  config manifest, selecting the point that minimizes a cost-weighted objective
  `w_fp * FPR + w_fn * (1 - recall)` with the operator's weights (defaults: w_fp higher for
  Hard, w_fn higher for Weak review signals). Publish the chosen operating point and the
  curve, not just the chosen point.
- **Drift**: any game update or mod change re-runs calibration on the affected families;
  thresholds are build-scoped and shipped per build.

Worked example (illustrative numbers): `movement.displacement` has two candidate
thresholds, `max_speed_mps` in {9, 10, 11} and `latency_window_ms` in {150, 200, 250}.
The operator's weights are `w_fp = 10` (a Hard-adjacent Strong false positive is
expensive), `w_fn = 1`. Grid search evaluates nine operating points on the validation
split. Point (10 m/s, 200 ms) yields FPR 0.002 and recall 0.93, objective
`10 * 0.002 + 1 * (1 - 0.93) = 0.09`; point (9 m/s, 150 ms) yields FPR 0.001 but recall
0.84, objective `0.01 + 0.16 = 0.17`. The first point wins, is re-checked on holdout,
and ships as the calibrated operating point for the build. The curve and the per-point
metrics are published with the release.

## 4. Labeling methodology (Layer 7, Phase 9)

- **Dispositions**: `confirmed`, `benign`, `uncertain`, `detector bug` (POLICY.md). Every
  finding in the soak window receives exactly one disposition; `uncertain` is a state, not
  a dump.
- **Labelers**: the operator; a second labeler when available. On disagreement, adjudicate
  in a documented session; if two labelers are available, report Cohen's kappa so label
  reliability is visible.
- **Sampling**: stratify by detector, severity, and context; over-sample suppressed
  findings and boundary (near-threshold) findings so the calibration set reflects the
  decision surface, not just the tail.
- **Feedback**: `benign` and `detector bug` export to the regression corpus
  (`tools/fixtures/regression/`) and are replayed by Layer 4; `confirmed` enters the
  calibration set; `uncertain` findings stay labeled until resolved or expire.

## 5. Mutation-testing methodology (Layer 4)

Mutation tests perturb legal traces and assert the expected finding appears (or that the
trace stays legal), so every validator input is exercised.

- **Operators**: per input authority and role. For an *observed* input, perturb the value
  within and outside the domain (boundary, overflow, NaN). For a *decision* input, replace
  it with a value of the wrong authority class (for example client-declared position vs
  server geometry) so the validator's authority handling is exercised, not just its math.
- **Kill criterion**: a mutant is killed when the replayed outcome differs from the
  expected outcome for that trace. Surviving mutants are reviewed: an equivalent mutant is
  noted, a non-equivalent survivor is a coverage gap in the validator or its fixture.
- **Coverage**: every input of every detector (the spec's `inputs`) must be mutated at
  least once; the mutation score is reported per detector with the Layer 4 exit.

## 6. A/B overhead methodology (Layer 6)

- **Design**: paired runs with `7dtd-apm` on the same world, seed, bot count, duration,
  collectors, and config, with and without Server Guard, after a warmup period, across at
  least three seeds. The budget gate is measured during a 64-client bloodmoon damage burst,
  not idle load.
- **Statistics**: report p50/p95/p99 and memory deltas with bootstrap confidence intervals
  over the per-tick samples. The gate fails when the p95 added main-thread time exceeds the
  budget (0.5 ms) with the 95% CI excluding the budget, or when any queue drops or
  disconnect-rate increase is statistically distinguishable from baseline.
- **Run protocol**: at least five paired runs per seed; discard the first run of each
  pair as warmup (world load, caches, chunk generation). Interleave baseline and candidate
  runs to spread host noise. Record host load (other processes) and report outliers rather
  than silently dropping them.
- **Reporting**: record hardware, server config, config hash, and hook manifest hash so the
  A/B is reproducible (SCHEMAS.md).

## 7. Red-team methodology (Phase 10)

Each campaign targets one category and produces a report plus fixtures:

| Category | Objective | Success criterion |
|---|---|---|
| Malformed | Invalid enum, NaN, infinity, coordinate, stack, length inputs | Contained without legal joins rejected or game thread stalls |
| Races | Concurrent container moves, disconnect-at-every-step, replay | No dupe; victim accrues nothing (attribution holds) |
| Evasion | Threshold dithering, impulse misuse, discontinuity abuse | Detector either catches or explicitly records the evasion as a named gap |
| Identity churn | Duplicate sessions, stolen/shared accounts, reconnect games | Findings attribute to the initiating connection only |
| Evidence injection | Forge/truncate/replay evidence, tamper chain | Hash chain detects; no injection into replay path |
| Resource abuse | Floods, join storms, fan-out, expensive-package spam | Throttle effective; never counts toward enforcement |

Every bypass found becomes a fixture and a regression trace before the campaign closes; a
Hard-invariant bypass blocks the release candidate.

## 8. Change checklist

A change is one concern, and every artifact that encodes that concern changes in the same
commit (workspace rule: one lever at a time). The doccheck gate fails when the contract is
inconsistent, so the checklist is mechanical:

| Change | Must change together |
|---|---|
| Add or demote a detector | `tools/detector_spec.yaml`, re-render (`make detectors`), fixture families, RESEARCH.md open question, DECISIONS.md entry, TEST_PLAN Layer 4 traces |
| Threshold value or range | The spec's `thresholds` entry (placeholder until calibration), re-render, config example if it cites the key, SCHEMAS.md excerpt if it shows the key |
| Config schema | `docs/SCHEMAS.md` table, `config/schemas/config.v1.schema.json`, example config, doccheck pattern keys |
| Evidence schema | `docs/SCHEMAS.md` evidence section, `config/schemas/evidence.v1.schema.json`, the sample JSONL, replay fixtures |
| Policy (severity, mode, gate) | POLICY.md, DECISIONS.md, DETECTORS.md ceilings, THREAT_MODEL.md outcome table, PRIVACY.md if notice text changes |
| Method (calibration, labeling, A/B) | METHODOLOGY.md, the TEST_PLAN layer that gates on it, TODO phase that runs it |

A change that touches none of the listed artifacts for its type is incomplete, even if
`make check` passes.

## 9. Release gating



Each release gate (TEST_PLAN.md -> Release gates) must cite the evidence artifact that
satisfies it: a calibration report, a labeling summary with kappa, the mutation score, the
A/B report, the red-team report, a passing `tools/evidence_check.py` run over the release
candidate's evidence directory, and the `make check` + Layer 1-4 CI run. A gate with no
artifact is not closed.

## References

- Wilson, *Probable inference, the law of succession, and statistical inference* (1927);
  the Wilson interval for proportion confidence intervals (precision, recall, FPR).
- Efron and Tibshirani, *An Introduction to the Bootstrap* (1993); bootstrap CIs for
  percentile cost and memory deltas.
- Cohen, *A coefficient of agreement for nominal scales* (1960); inter-rater agreement for
  the labeling methodology.
- Offutt and Untch, *Mutation 2000: Uniting the Orthogonal* (2001); mutation testing
  operators and kill criteria (section 5).
- The workspace evidence loop: `../AGENTS.md` (baseline, one change, compare, soak).
