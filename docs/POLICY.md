# Policy and governance contract

This document is the single source of truth for Server Guard's decision vocabulary: detector
**modes**, permitted **actions**, **severity**, **confidence**, operator **override**, and the
**appeal** path. Other documents defer to the definitions here. It closes the Phase 0 items
"define observe/correct/quarantine/kick/review/ban boundaries" and "define severity vocabulary,
evidence confidence, and operator override semantics."

Two axes were previously conflated across docs (a per-detector *mode* and the *action* a decision
produces). They are separated below on purpose.

## Supported build

Server Guard targets exactly one build until a compatibility matrix exists: **7 Days to Die
dedicated V3.1.0 (b14), Unity Mono**. Every Harmony hook is pinned to this build's method
signatures and metadata tokens and fails open on mismatch. Other builds load in observe-only with
all hooks that fail signature resolution disabled.

## Detector mode ladder (per detector)

Mode is configured **per detector**, defaults to `Observe`, and can only be raised by explicit
operator opt-in after the detector's exit criteria are met.

| Mode | May do | May never do |
|---|---|---|
| `Observe` | Record evidence only. | Alter gameplay in any way. This is the initial and default mode. |
| `Correct` | Reject or server-correct a single **impossible** state transition backed by a **Hard** invariant with complete authoritative inputs. | Kick, quarantine, or ban. Act on Strong/Weak signals. |
| `Enforce` | Everything `Correct` may do, plus the **actions** below (quarantine, kick) subject to the gates in "Enforcement gates." | Issue a permanent or automatic ban. |

`Enforce` is a capability level, not an action. The concrete action it takes (quarantine vs kick)
is chosen by the response policy, never implied by the mode name.

## Action set (what a decision produces)

| Action | Meaning | Reversible |
|---|---|---|
| `record` | Append a finding to evidence. Always available in every mode. | n/a |
| `correct` | Reject or clamp one impossible transition (e.g. deny an out-of-bounds block edit). Rate-limited; correction loops are prevented. | Yes (nothing persisted against the player) |
| `quarantine` | Temporarily restrict a **named** capability (damage, container/trade access, or world mutation) while allowing communication and operator review. Each restriction is separately enabled. | Yes (operator lifts) |
| `throttle` | Slow or shed a connection's packets via cost-weighted token buckets, or shed global load. An availability protection, not an accusation: recorded with evidence IDs, never contributes to any enforcement gate. | Yes (pressure ends, throttle ends) |
| `kick` | Disconnect the session, naming the violated rule and evidence ID. No secret thresholds in the message. | Yes (player may rejoin) |
| `temp-ban (local)` | Operator-scoped local ban with an expiry. Requires operator approval. | Yes (expiry or operator unban) |
| `permanent-ban` | **Never automatic.** Only an operator, out of band, using their own admin tools. Server Guard never issues one. | Operator-only |

Steam VAC bans and Steam publisher "game bans" are **out of scope**: they require a Steamworks
partner integration Server Guard does not have. Local kick/ban is the realistic boundary.

## Severity (property of a signal, not a mode)

| Severity | Definition | Strongest action it can justify alone |
|---|---|---|
| `Hard` | A game rule checked with exact, complete authoritative inputs. Impossible-by-construction. | `correct` (in `Correct`/`Enforce` mode) |
| `Strong` | Near-impossible but not proven from a single event. | Nothing alone. Contributes toward `Enforce` only with a second independent category. |
| `Weak` | Behavioral anomaly (aim, cadence distribution, efficiency). | `record` only. Never enforces. |

The ceiling is set by input authority, not ambition: a validator that must consume any
client-declared input is capped below `Hard`, because complete authoritative inputs are a
`Hard` precondition. Phase 1 records each validator's input authority class.

## Confidence and combination

- Confidence is recorded per finding and decays per detector over time.
- **Independent** evidence categories combine; repeated copies of the same root cause do **not**
  multiply confidence.
- Soft scoring is suppressed during server stalls, join/spawn, teleport, death, chunk starvation,
  packet-loss bursts, and externally applied impulses (knockback, explosion, ragdoll). The raw
  finding is preserved with a `suppressedReason` for tuning.

## Enforcement gates (before any `Enforce` action)

A `quarantine` requires at least one **Strong** category with repeated findings across the
minimum observation window. When both quarantine and kick are justified, quarantine is
preferred: it removes the harmful capability while keeping the player reviewable in place.

A `kick` requires **either**:
1. at least two **independent Strong** categories, **or**
2. an operator-approved policy for a repeated **Hard** protocol invariant.

A `temp-ban (local)` requires the kick gate **plus** per-incident operator approval. It is
never automatic. The ban reason and evidence ID are shown at every rejected join attempt.

Findings only count toward a gate when their root cause is attributable to the accused
connection's own requests. Findings another player can induce against a victim (container
races initiated by a second player, duplicate sessions from a stolen account, knockback and
explosion impulses) attribute to the initiating connection or suppress, never to the victim.

Attribution mechanism: every server-processed impulse (knockback, explosion, ragdoll) carries
a damage-source entity owned by the attacker; the resulting movement/combat finding attributes
to that owner, not the recipient. Container-race attempts resolve at the server, which
atomically checks slot ownership; a second player's race never grants the victim an item, so
no finding accrues against the victim. Duplicate sessions attribute findings to the connection
that accepted the second login, not the original session.

Plus, for every enforcement family: a minimum observation window, cooldown, score decay, and a
dry-run diff (what *would* have happened) reviewed before the family is enabled.

## Operator override semantics

- Operators may lower any detector to `Observe`, lift a quarantine, unban, or purge evidence.
- An **emergency global disable** reverts all detectors to `Observe` without a restart.
- Every override is written to the audit log with actor, timestamp, and reason.
- Overrides never silently raise thresholds to accommodate one incompatibility; exceptions are
  named and measured (see AGENTS boundaries).

## Roles and appeals

Roles are **per deployment**. The table below is the reference deployment (this repository's
maintainer running their own server). Any other operator substitutes themselves: only the
operator holds that server's evidence and identity map, so appeals always go to the operator,
never to the mod maintainer.

| Role | Owner |
|---|---|
| Maintainer | maci (maci.stgn@gmail.com) |
| Security contact / disclosure | maci (maci.stgn@gmail.com); see [`../SECURITY.md`](../SECURITY.md) |
| Appeal owner (reviews contested actions) | maci (maci.stgn@gmail.com) |
| Privacy / retention owner | maci (maci.stgn@gmail.com); see [`../PRIVACY.md`](../PRIVACY.md) |

Appeals: a player named in a `kick`, `quarantine`, or local ban may contest it. Every such
action delivers the violated rule and evidence ID to the player (kick message, quarantine
notice in game, ban reason at rejected join). The appeal owner reviews the evidence timeline
and contextual values, records a disposition (confirmed, benign, uncertain, or detector bug),
and any false positive is exported to the regression corpus. On a single-operator deployment
the reviewer also wrote the policy; the mitigations are the dry-run diff before enabling any
enforcement family and the disposition record, which makes every decision auditable after
the fact.

## Glossary

| Term | Meaning | Canonical definition |
|---|---|---|
| Mode | Per-detector capability level: `Observe`, `Correct`, `Enforce` | Detector mode ladder |
| Action | What a decision produces: `record`, `correct`, `quarantine`, `throttle`, `kick`, `temp-ban (local)` | Action set |
| Severity | Property of a signal: `Hard`, `Strong`, `Weak` | Severity |
| Authority class | Whether a validator input is server-derived or client-declared; any client-declared input caps the signal below `Hard` | Severity |
| Ledger | Per-player bounded double-entry state for movement, combat, inventory, or world actions | ARCHITECTURE.md → Components |
| Cause token | Typed, authorized server-origin cause for an inventory delta; calling-mod identity is recorded on every invocation | SIGNALS.md → Inventory; TODO.md → Phase 7 |
| Evidence ID | Identifier on a finding, named in kick/quarantine/ban messages and webhook alerts | ARCHITECTURE.md → Evidence model |
| Session epoch | Per-connection identity epoch separating live from stale state | ARCHITECTURE.md → Components |
| Pseudonym epoch | HMAC key rotation boundary for evidence pseudonyms | PRIVACY.md → Retention schedule |
| `suppressedReason` | Why soft scoring was suppressed for a finding; preserved for tuning | Confidence and combination |
| Dry-run diff | Report of what *would* have happened, required before enabling any enforcement family | Enforcement gates |
| Tombstone | Purge/redaction placeholder that preserves the record hash in the chain | ARCHITECTURE.md → Evidence model |
| Detector ID | Stable `family.subject` identifier for a detector; config, evidence, metrics, and fixtures use the same ID | DETECTORS.md → Detector registry |
| Schema version | `schemaVersion` integer on config, evidence, hook manifest, audit, and health records; consumers refuse or skip unknown versions | SCHEMAS.md → Schema evolution |
| Fail-open | A detector disables itself on hook mismatch or runtime fault rather than risking gameplay | ARCHITECTURE.md → Hook policy |
| Regression corpus | Labeled false-positive and detector-bug fixtures replayed on every change | TEST_PLAN.md → Layer 7 |
| Hook manifest | Machine-readable fingerprint of resolved hooks and metadata tokens for the build | TODO.md → Phase 1; TEST_PLAN.md → Layer 3 |

## License

Server Guard is licensed under **AGPL-3.0** (see [`../LICENSE`](../LICENSE)). A modified server
deployment must make its corresponding source available to its users.
