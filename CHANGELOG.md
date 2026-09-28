# Changelog

Notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); each section matches a
release tag.

This is a 0.x project: minor bumps (`0.Y.z`) may change tooling contracts and
command names, patch bumps are expected not to. Releases before 0.3.0 predate
this file and are described only by their git tags.

## [Unreleased]

### Added

- `make fuzz FUZZ=<evidence_check|schema_validate|replay_trace> [ITERATIONS=N] [SEED=S]`
  runs one fuzzer at a short iteration count, with a usage error naming the valid
  harnesses. Every harness already took `--iterations` and `--seed`.
- `CONTRIBUTING.md` states the runnable path: prerequisites, bootstrap, the loop, the
  single-fuzzer target, generated-file regeneration, and what a change must include.
- Replay traces carry a required `determinism` block: `startUtc` and
  `startMonotonicMs` are the virtual clock origin a replay derives event times and
  evidence `utc`/`monotonicMs` from, and `fingerprint` pins the expected outcome
  projection (run header, clock origin, per-case findings, actions, and work units)
  so a diverging replay fails on one digest. `tools/replay_contract_check.py`
  verifies both and rejects a case whose `tick` steps backwards.

### Fixed

- `fuzz_replay_trace.py` built its deep-nesting probe from a mutated trace and then
  indexed `cases[0]["events"][0]`, so a mutant that dropped or replaced either crashed
  the harness with a bare `TypeError`. The probe now copies the pristine sample. The
  default seed happened to survive; `--iterations 50 --seed 1234` did not.
- `make ci` now includes `make exercise`, so the replay contract check gates CI and not
  only a manual run.
- README, RESEARCH, and the 0.4.0 entry described V3.2.0 (b9) as the pinned
  build, which contradicts the shipped `buildPin.buildId` default, the config
  schema, and POLICY.md. The installed build and the supported pin are now
  stated separately, and RESEARCH cites the V3.1.0 census path it actually
  names.
- The V3.2.0 (b9) pin from 0.4.0 now reaches the whole design contract: `docs/POLICY.md`,
  `docs/ARCHITECTURE.md`, `docs/SCHEMAS.md`, `docs/TEST_PLAN.md`, `docs/RESEARCH.md`,
  `docs/METHODOLOGY.md`, `SECURITY.md`, `TODO.md`, the config v1 default, the config and
  evidence samples, and the replay fixture all still named V3.1.0 (b14).
- `docs/DECISIONS.md` records the re-pin as D-18 and marks D-01's build pin superseded; the
  one-build fail-open rule is unchanged.
- The seam map cites the V3.2.0 netpackage census (195 types) instead of the V3.1.0 census
  (193 types), and `world.budget` no longer names `NetPackagePOIAround`, which the V3.2.0
  census does not contain.

## [0.4.1] - 2026-09-20

### Changed

- Tooling and CI upkeep only, all via dependabot: black 25.9.0 to 26.5.1 and
  ruff 0.16.4 to 0.16.6 in the lock, `actions/checkout` 4.2.2 to 7.0.1, and
  `astral-sh/setup-uv` 5.4.2 to 10.0.1 in the workflows. No detector, gate, or
  command behavior changes. Patch bump: `make ci` is green unchanged.

## [0.4.0] - 2026-09-11

### Changed

- `AGENTS.md` states what this repository owns and does not own: server-side
  behavioural validation and anti-cheat evidence here, no client scanners and
  no automatic permanent bans by default, stock RE in `7dtd-engine-research`.
- The research citations point at the grouped `docs/<subsystem>/` tree, and the
  locally installed server (V3.2.0 b9) is now recorded separately from the
  supported pin. The pin itself is still **V3.1.0 (b14)**: the example config,
  the config schema, and POLICY.md were not moved, so any hook written now
  targets b14 and other builds load observe-only.

## [0.3.0] - 2026-08-26

Toolchain and gate release. The design contract (`docs/`, `TODO.md`) is
unchanged apart from the corrections listed below; no detector behavior exists
yet to change.

### Added

- `make lint`: black, ruff, and mypy `--strict` over `tools/`, wired into
  `make ci` and therefore into CI. The tooling is clean under all three.
- `pyproject.toml`, `uv.lock`, `ruff.toml`, and `mypy.ini` declare the tool
  dependencies and the lint and type settings.
- The em-dash gate now reads shipped source files (`tools/*.py`, `Makefile`,
  `config/**.json`, CI workflows, the lint configs), not just markdown.

### Changed

- Python toolchain is uv. `make setup` is `uv sync --frozen` and every tool runs
  through `uv run --frozen`; CI uses `astral-sh/setup-uv` in place of
  `actions/setup-python`. `requirements.txt` is gone, replaced by
  `pyproject.toml` plus a committed `uv.lock`.
- `tools/fuzz_evidence_check.py` writes its temporary segments under `.scratch/`
  instead of the system temp dir, which is tmpfs (RAM) on the dev host.
- The design-contract review prompt moved from the repo root to
  `.github/reviews/design-contract-review.md`.
- `docs/INDEX.md` repo layout lists the top-level files and directories that
  exist on disk; `tools/README.md` covers `fuzz_common.py` and
  `guard_python.py`.

### Fixed

- `tools/replay_contract_check.py` reported "normal case expects findings" when
  a normal case *had* findings, which is the opposite of the rule it enforces.
- `docs/SCHEMAS.md` pointed at a bare interpreter invocation for the evidence
  verifier instead of `make verify-evidence DIR=<dir>`.
