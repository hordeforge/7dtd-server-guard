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
  authority notes, and the Phase 6 exit gate all reference this rule. Refined by D-15
  (observed vs decision input roles); `make check` enforces the refined rule against the
  detector spec.

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
- **Consequence:** SIGNALS.md -> Causal capabilities and Conservation ledger, TODO.md Phase 7 (first consumers CPM /
  ServerTools admin item grants), SCHEMAS.md `cause` record type, and TEST_PLAN.md
  admin/mod-origin fixtures.

## D-10: Availability is protection, not accusation

- **Status:** accepted.
- **Decision:** Flood and cost protection uses cost-weighted token buckets and the
  `throttle` action. Throttle evidence never counts toward any enforcement gate.
- **Alternatives:** Count floods toward kick gates (rejected: DoS victims and shared-IP
  households would be punished); only firewall-level protection (rejected: the game thread
  still needs defense in depth; THREAT_MODEL.md).
- **Consequence:** SIGNALS.md -> Cost and amplification budget; POLICY.md action set; DETECTORS.md
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
- **Consequence:** SIGNALS.md -> Causal capabilities; DETECTORS.md `movement.teleport_token` is Hard
  only after Phase 1 enumerates every origin; TEST_PLAN.md teleport fixture family.

## D-13: Both damage paths must be hooked together

- **Status:** accepted.
- **Decision:** Combat validators hook both `EntityAlive.DamageEntity` and
  `NetPackageRangeCheckDamageEntity`; a validator on one path only protects nothing.
- **Alternatives:** Hook the common post-damage sink only (rejected: the range-check path
  bypasses the sink; the at-risk seam list names it).
- **Consequence:** RESEARCH.md open question, SIGNALS.md -> Correlation graph, TODO.md Phase 6,
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

## D-15: Input roles (observed vs decision) refine the authority rule

- **Status:** accepted.
- **Decision:** Every validator input carries an authority (server-derived or
  client-declared) and a role (observed or decision). Observed inputs are the quantity
  being checked and may be client-declared; decision inputs are the state the verdict
  depends on and must be server-derived for a `Hard` ceiling. A detector with a
  client-declared decision input is capped below `Hard` unless a `hard_condition` documents
  complete server-side determination.
- **Alternatives:** Keep the unqualified rule "any client-declared input caps below Hard"
  (rejected: it contradicted registry entries that are Hard by fully
  server-side recomputation, and it misclassified `inventory.stack`, whose claimed stack
  is the observed quantity, not trusted input); treat observed inputs as trusted
  (rejected: the observed quantity must still be validated, it just does not set the
  ceiling).
- **Consequence:** POLICY.md -> Severity, ARCHITECTURE.md -> Input authority, the detector
  spec (`tools/detector_spec.yaml`), and the doccheck gate all encode the two roles. The
  hard-condition carve-out is reserved for completeness-of-server-state cases (teleport
  origin enumeration, craft/trader seams) and is reviewed per detector.

## D-16: Separate validation primitives, registered detectors, and proposals

- **Status:** accepted.
- **Decision:** SIGNALS.md owns reusable validation mechanics, the generated detector spec
  owns committed detector contracts, and PROPOSALS.md holds non-binding ideas. A proposal
  must pass a seam, authority, context, privacy, cost, and fixture gate before it receives a
  stable detector ID.
- **Alternatives:** keep a second prose detector catalog (rejected: it duplicated algorithms,
  ceilings, contexts, and thresholds from the generated registry); add every plausible idea
  directly to the registry (rejected: registry membership creates config, fixture, and phase
  obligations before authority is known).
- **Consequence:** New ideas begin in PROPOSALS.md. DETECTORS.md and
  `tools/detector_spec.yaml` remain the only canonical detector list. Shared mechanics are
  implemented once and referenced by detectors instead of copied per family.

## D-17: Replay inputs and evidence outputs use separate contracts

- **Status:** accepted.
- **Decision:** replay-trace v1 represents synthetic input events, authoritative decision
  state, work bounds, and expectations. Evidence v1 represents detector output. Replay
  fixtures are observe-only and cannot assert gameplay actions.
- **Alternatives:** reuse evidence JSONL as replay input (rejected: output findings do not
  represent the pre-state, authoritative snapshot, or negative expectations a deterministic
  replay needs); allow corrective expectations in early replay (rejected: it bypasses live
  authority, legal-context, and co-patching gates).
- **Consequence:** TEST_PLAN.md Layer 4, SCHEMAS.md, and the fixture layout use replay-trace v1.
  `make exercise` checks a synthetic `inventory.stack` normal/violation vector while clearly
  leaving the live hook and detector unimplemented.

## Decision process


- A decision enters as `proposed`, gets a Phase-0-style review with alternatives, and
  becomes `accepted` when the owning document is updated to match.
- Evidence that contradicts a decision updates the owning document and this log in the same
  change; the log entry keeps the old rationale so the change is reviewable.
- New decisions that add detectors, actions, or schema fields must also update
  DETECTORS.md, SCHEMAS.md, and the fixture plan in TEST_PLAN.md in the same change.
