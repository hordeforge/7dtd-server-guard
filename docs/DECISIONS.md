# Decision log

Why the design is the way it is. Each entry records the decision, the alternatives that
were considered and rejected, and the consequence that binds later phases. The design
contract says "update documents when evidence changes an assumption"; when that happens,
update the owning document *and* add an entry here with status `superseded` and a pointer to
the new decision, so the reasoning trail survives.

Status values: `accepted` (binding), `proposed` (under review), `superseded` (replaced;
see note).

## D-01: Pin one game build and fail open

- **Status:** accepted.
- **Decision:** Target exactly 7 Days to Die dedicated V3.1.0 (b14), Unity Mono. Every
  Harmony hook resolves exact type, full signature, parameter roles, return type, and
  metadata token against that build and self-disables on mismatch. Other builds load in
  observe-only.
- **Alternatives:** Support a range of builds with per-build manifests from day one
  (rejected: doubles Phase 1 surface-inventory work and the compatibility matrix is not yet
  built); version-dispatch at runtime (rejected: complexity with no measured need).
- **Consequence:** Phase 1 must re-verify every surface against the pinned build; the V3.0.1
  evidence in `7dtd-research` is directional only. Hook manifest v1 and build fingerprint
  (SCHEMAS.md) make the pin checkable in CI.

## D-02: Observe -> Correct -> Enforce ladder, never automatic permanent ban

- **Status:** accepted.
- **Decision:** Every detector defaults to `observe`. `correct` requires a Hard invariant
  with complete authoritative inputs. `enforce` actions (quarantine, kick) require the
  policy gates (two independent Strong categories, or operator-approved policy for repeated
  Hard protocol invariants). `permanent-ban` is never issued by the mod.
- **Alternatives:** Single-threshold auto-ban like ServerTools/Botman (rejected: surveyed
  false-positive stories; see RESEARCH.md); ban on first Hard hit (rejected: Hard is
  impossible-by-construction but the *path* must still be proven legal-context-clean first).
- **Consequence:** The policy contract (POLICY.md) owns the ladder; every detector registry
  row (DETECTORS.md) carries a severity ceiling that the ladder references. Surveyed tools
  with immediate auto-ban are explicitly not followed.

## D-03: Prefix/postfix Harmony patches only; no transpilers in the initial design

- **Status:** accepted.
- **Decision:** Runtime security hooks use Harmony prefix/postfix on exact pinned methods.
  Transpilers are excluded from the initial anti-cheat design.
- **Alternatives:** Transpilers for mid-body rewriting (rejected: compatibility risk with
  co-patched mods; RESEARCH.md finding 3).
- **Consequence:** Reject seams that need mid-body interception are not candidates until
  reviewed; every reject seam documents its co-patching behavior (ARCHITECTURE.md -> Hook
  policy).

## D-04: Separate per-detector mode from decision action

- **Status:** accepted.
- **Decision:** Mode (`observe`/`correct`/`enforce`) is a per-detector capability level; the
  action a decision produces (`record`, `correct`, `quarantine`, `throttle`, `kick`,
  `temp-ban (local)`) is chosen by the response policy. These were previously conflated.
- **Alternatives:** One combined "severity -> action" map (rejected: `enforce` implies
  quarantine *or* kick, but which one is a policy choice, not a capability choice).
- **Consequence:** POLICY.md owns both vocabularies; SCHEMAS.md config exposes modes
  per detector and actions as separately enabled switches.

## D-05: Append-only hash-chained JSONL evidence with tombstones

- **Status:** accepted.
- **Decision:** Evidence is append-only JSONL segments, hash-chained per record, rotated by
  size and day, with purge/redaction via tombstones that preserve chain continuity.
- **Alternatives:** SQLite (rejected: heavier dependency, still needs tamper-evidence
  handling, harder crash-safe segment semantics); a binary log (rejected: review tooling and
  exports are easier from JSONL); no chain (rejected: tamper detection is a stated value).
- **Consequence:** SCHEMAS.md evidence v1 fixes the record grammar; TEST_PLAN.md Layer 4
  property tests cover chain, truncation, and tombstone invariants. The chain proves
  tampering by non-keyholders only (ARCHITECTURE.md -> Evidence model).

## D-06: HMAC pseudonyms with a separate identity map and key rotation

- **Status:** accepted.
- **Decision:** Evidence stores keyed HMAC pseudonyms at rest; the raw platform identity
  lives only in a permission-restricted identity map; HMAC key rotation starts a new
  pseudonym epoch and the key is destroyed when the evidence under it expires.
- **Alternatives:** Encrypt-at-rest with a single key (rejected: key compromise
  de-anonymizes everything); raw identities in evidence (rejected: PRIVACY.md contract).
- **Consequence:** PRIVACY.md retention schedule and SCHEMAS.md config keys
  (`identityMap.*`, `hmacKey.*`) are binding; SECURITY.md lists de-anonymization as an
  in-scope report class.

## D-07: Input authority classes cap severity

- **Status:** accepted.
- **Decision:** Every validator input is classified server-derived or client-declared; any
  client-declared input caps the detector below `Hard`, regardless of server-derived inputs
  also checked.
- **Alternatives:** Trust client values when several server checks agree (rejected: an
  attacker controls all client-declared fields together, so agreement among them is
  meaningless); demand full authority without a written class (rejected: unverifiable).
- **Consequence:** POLICY.md -> Severity, ARCHITECTURE.md -> Input authority, DETECTORS.md
  authority notes, and the Phase 6 exit gate all reference this rule.

## D-08: Statistical behavioral models are offline-only until calibrated

- **Status:** accepted.
- **Decision:** The first release is deterministic and rule-based. `BehaviorEngine`
  windowed scoring runs over copied data on a worker and may only inform review evidence;
  statistical aim/bot models never directly ban.
- **Alternatives:** Ship statistical scoring with enforcement from day one (rejected:
  RESEARCH.md finding 4; false-positive rates material; PRIVACY and appeal burdens).
- **Consequence:** Weak signals (aim, acquisition, edge distribution) are review-only in
  DETECTORS.md; Phase 10 publishes precision/recall before any behavioral family can be
  considered for a mode raise.

## D-09: Cause-token API for other mods, with caller identity recorded

- **Status:** accepted.
- **Decision:** Other trusted mods register server-origin inventory causes through a typed
  cause API; every invocation records the calling mod's identity in the evidence stream.
- **Alternatives:** Whitelist mods and trust them silently (rejected: an over-broad or
  buggy cause call would blind the ledger invisibly); no API (rejected: would force
  false findings on modded servers).
- **Consequence:** SIGNALS.md -> Inventory, TODO.md Phase 7 (first consumers CPM /
  ServerTools admin item grants), SCHEMAS.md `cause` record type, and TEST_PLAN.md
  admin/mod-origin fixtures.

## D-10: Availability is protection, not accusation

- **Status:** accepted.
- **Decision:** Flood and cost protection uses cost-weighted token buckets and the
  `throttle` action. Throttle evidence never counts toward any enforcement gate.
- **Alternatives:** Count floods toward kick gates (rejected: DoS victims and shared-IP
  households would be punished); only firewall-level protection (rejected: the game thread
  still needs defense in depth; THREAT_MODEL.md).
- **Consequence:** SIGNALS.md -> Availability; POLICY.md action set; DETECTORS.md
  `protocol.flood`, `availability.cost`, `availability.churn` rows.

## D-11: Bounded main-thread budget with drop-soft-first queues and a dedicated writer

- **Status:** accepted.
- **Decision:** Under 0.5 ms p95 added main-thread time per tick at 64 players, zero
  steady-state allocations in movement sampling; network IO and evidence writes happen off
  the game thread on bounded queues that drop soft observations first.
- **Alternatives:** Write evidence synchronously on the game thread (rejected: IO on the
  game thread violates the workspace and architecture rules); unbounded queues (rejected:
  memory exhaustion is an availability hole).
- **Consequence:** ARCHITECTURE.md -> Performance budget and components' thread rules;
  SCHEMAS.md queue bounds and metrics counters; TEST_PLAN.md Layer 6 gates.

## D-12: Teleport capability tokens; stock >8 m deltas are discontinuities

- **Status:** accepted.
- **Decision:** Server-side teleport origins (trader ejection, quests, respawn, console,
  game events, mods) issue one-use capability tokens with cause and expiry. Client
  `EntityTeleport` packages are ordinary discontinuities, never violations, because the
  stock protocol emits them for any >8 m positional delta.
- **Alternatives:** Treat any client teleport package as a violation (rejected: stock
  rubber-banding after chunk stalls is legal play); require token for every delta (rejected:
  impossible without enumerating all origins).
- **Consequence:** SIGNALS.md -> Movement; DETECTORS.md `movement.teleport_token` is Hard
  only after Phase 1 enumerates every origin; TEST_PLAN.md teleport fixture family.

## D-13: Both damage paths must be hooked together

- **Status:** accepted.
- **Decision:** Combat validators hook both `EntityAlive.DamageEntity` and
  `NetPackageRangeCheckDamageEntity`; a validator on one path only protects nothing.
- **Alternatives:** Hook the common post-damage sink only (rejected: the range-check path
  bypasses the sink; the at-risk seam list names it).
- **Consequence:** RESEARCH.md open question, SIGNALS.md -> Combat, TODO.md Phase 6,
  TEST_PLAN.md adversarial combat coverage.

## D-14: Scope exclusions are product boundaries, not convenience

- **Status:** accepted.
- **Decision:** No client scanning, memory inspection, screenshots, EAC bypass; chat
  content moderation is separate; publisher game bans are out of scope; the mod cannot
  defend against a compromised host or a malicious same-process DLL.
- **Alternatives:** Ship an X-ray screen blackout or client visual mitigation (rejected:
  client mod scope; THREAT_MODEL.md and AGENTS.md boundaries); attempt Steam game bans
  (rejected: requires Steamworks partner integration; RESEARCH.md finding 1).
- **Consequence:** README.md scope, THREAT_MODEL.md out-of-scope list, SECURITY.md
  out-of-scope list, and the workspace boundary rules are binding.

## Decision process

- A decision enters as `proposed`, gets a Phase-0-style review with alternatives, and
  becomes `accepted` when the owning document is updated to match.
- Evidence that contradicts a decision updates the owning document and this log in the same
  change; the log entry keeps the old rationale so the change is reviewable.
- New decisions that add detectors, actions, or schema fields must also update
  DETECTORS.md, SCHEMAS.md, and the fixture plan in TEST_PLAN.md in the same change.
