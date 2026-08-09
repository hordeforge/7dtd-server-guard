# Detector proposal incubator

This is a non-binding queue of detector ideas. Entries here are not registry IDs, config
keys, roadmap commitments, or enforcement candidates. The canonical detector set remains
[DETECTORS.md](DETECTORS.md). An idea moves into `tools/detector_spec.yaml` only through the
promotion gate below and defaults to observe-only.

## Promotion gate

Before promotion, record all of the following:

1. A server-side harm or protected outcome that an existing detector does not cover.
2. A candidate authoritative seam on the pinned build, with pre-state and post-state.
3. Every input's authority and role, plus the resulting severity ceiling.
4. Legal contexts, induced-finding risks, privacy/retention cost, and a bounded work budget.
5. Normal, violation, missing-state, replay, concurrency, and relevant context fixtures.
6. Why extending an existing detector or validation primitive is insufficient.

If Phase 1 cannot find a decision seam, keep the idea here, demote it to review-only, or
drop it. Do not create a detector merely because a packet or metric is observable.

## Near-term candidates

### C-01: Effect-chain completeness

- **Gap:** combat and world effects can arrive through multiple paths; validating each path
  independently may leave an orphan damage, explosion, or block mutation.
- **Mechanism:** build a short-lived correlation graph from authoritative initiation to
  resource spend, target set, mutation, and side effects. Flag an effect with no live parent,
  duplicate consumption of a parent, or fan-out beyond the parent's rule.
- **Likely ceiling:** Strong until every effect origin is enumerated; Hard only for narrowly
  complete subfamilies.
- **Value:** generalizes the existing two-damage-path and repeat-damage requirements and
  catches bypasses created by alternate legal-looking entry points.
- **Main risks:** mod-origin effects, DOT chains, explosions, reflected damage, and memory
  growth. Use bounded TTL state and typed mod-origin capabilities.

### C-02: Progression cause conservation

- **Gap:** a rate envelope can miss slow, unauthorized XP or skill inflation.
- **Mechanism:** issue typed credits for kills, quests, events, admin actions, and mod grants;
  reconcile client-pushed progression deltas against those credits by epoch.
- **Likely ceiling:** Strong while mod sources or vanilla award paths are incomplete; Hard for
  prerequisite and maximum checks that are fully recomputable.
- **Value:** detects low-and-slow inflation without lowering the global XP-rate threshold.
- **Main risks:** double counting awards, respecs, party-shared XP, offline rewards, and mods.

### C-03: Cross-container conservation window

- **Gap:** per-transaction idempotency may miss a dupe spread across several valid container
  operations, disconnect, and save timing.
- **Mechanism:** reconcile the connected component of touched slots, containers, drops, and
  player inventory over a short transaction window; total quantity must conserve across the
  component even when individual moves look legal.
- **Likely ceiling:** Hard only when all component mutations are under one authoritative lock;
  otherwise Strong and unattributed on reconciliation gaps.
- **Value:** targets race and rollback compositions rather than known exploit signatures.
- **Main risks:** large shared containers, death bags, partial saves, and expensive snapshots.

### C-04: Request amplification ratio

- **Gap:** fixed packet weights do not capture a small request that causes unusually large
  world queries, entity fan-out, allocations, or queued work.
- **Mechanism:** meter actual bounded downstream work per request class and compare it with a
  profiled envelope; dynamically charge the token bucket without using player findings.
- **Likely ceiling:** availability-only; never gameplay enforcement.
- **Value:** contains algorithmic-complexity abuse and remains useful when attackers stay
  under packet-count limits.
- **Main risks:** instrumentation overhead and legitimate bloodmoon, chunk, or mod workloads.

### C-05: Capability leak and replay health

- **Gap:** cause and teleport APIs can themselves become bypasses if tokens are over-broad,
  duplicated, never consumed, or issued by a buggy mod.
- **Mechanism:** audit issue-to-consume cardinality, scope, expiry, issuer, and unused-token
  rate by capability type. Treat anomalies as subsystem or calling-mod health first.
- **Likely ceiling:** operational health; a duplicate one-use consumption may support the
  detector that owns the protected transition.
- **Value:** makes the interoperability escape hatch measurable instead of silently trusted.
- **Main risks:** confusing harmless abandoned tokens with abuse; keep player attribution off
  unless the protected transition independently violates a rule.

### C-06: Context-coverage drift

- **Gap:** game updates or other mods can introduce legal states not represented in detector
  context providers, causing a broad rise in suppressed or benign findings.
- **Mechanism:** monitor unknown-context rate, suppression mix, and benign-review rate by
  build/config hash; automatically recommend a detector return to observe when drift exceeds
  a reviewed operational threshold.
- **Likely ceiling:** detector health only.
- **Value:** detects false-positive risk before operators escalate responses.
- **Main risks:** alert fatigue and sparse labels. Require minimum samples and never change a
  mode upward automatically.

## Later research candidates

### C-07: Server-visible-information frontier

Track when an entity first enters the stock server's distribution set and compare that
frontier with target selection. Because vanilla interest management is distance-based and
not line-of-sight secrecy, this can only become weak review context. It must not be described
as proof of ESP or wallhack.

### C-08: Cooperative causality anomalies

Look for repeated multi-account sequences whose combined transfers, aggro, knockback, or
disconnect timing create residuals that no single session owns. This is primarily a replay
and review tool. Shared households, parties, stream events, and public storage make automatic
enforcement unsafe; do not persist a social graph beyond the evidence retention window.

## Rejected ideas

Record rejected concepts so they do not return under a new name without new evidence.

| Idea | Reason |
|---|---|
| Client scanner or screenshot challenge | Outside server-only scope and incompatible with the EAC-off mod boundary |
| Cheat-program fingerprinting from behavior | Behavioral coincidence cannot identify a particular program |
| Automatic permanent ban score | Violates policy, appeal, and false-positive requirements |
| Global peer outlier score | Server population and play style are not a trustworthy ground truth; poor explainability |
| Chat-content model as integrity evidence | Content moderation is a separate product concern; only bounded rate shares availability infrastructure |
