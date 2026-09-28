# Contributing

The runnable path from a fresh clone to a merged change. Prose accuracy in `docs/`
is gated separately by `make check`; this file is the runnable contract.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) 0.12.13, the release `required-version` pins under
  `[tool.uv]` in [pyproject.toml](pyproject.toml) and the release CI installs. uv refuses to
  run against any other release and names the one it wants, so the pin is checked by the
  tool rather than by the reader. It installs the exact interpreter version pinned in
  [.python-version](.python-version) and resolves the locked dependency set, so the local
  toolchain is the CI toolchain.
- `make` and a POSIX shell.
- Network access on the first run, for the uv interpreter and lockfile download.

Nothing is installed globally: `make setup` materializes `.venv/` inside the clone.

## Bootstrap and loop

```
make setup      # uv sync --locked, once per clone
make check      # docs quality gate: run before opening a change
make lint       # black, ruff, mypy over the whole repository
make exercise   # replay contract self-tests plus the design-time trace
make test-tools # self-tests and fuzzers for the shipped tooling (takes minutes)
make sbom       # CycloneDX 1.6 inventory rendered from uv.lock
make ci         # everything CI runs, in one local step
```

`make ci` is the same command CI runs, so a green `make ci` means a green workflow.

Single tool while editing it, without running the minutes-long `make test-tools`:

```
make self-test TOOL=evidence_check           # that tool's negative self-tests
make fuzz FUZZ=evidence_check ITERATIONS=50 SEED=1234
```

The two targets are the two halves of `make test-tools`; a fuzzer run covers only the
fuzzer, so a change to a tool's self-tests needs `make self-test`. Fuzzers are seeded, so
the `seed=` and `iterations=` a failure reported reproduce it exactly. `make help` lists
every target.

## Adding a tool, a self-test, or a fuzzer

`make test-tools` names its fuzzers one line at a time and reaches its self-tests through
the `SELF_TESTS` list, so a new harness has to be registered or it never runs. Both
registries are the Makefile's `FUZZERS` and `SELF_TESTS` variables:

- A new fuzzer is `tools/fuzz_<name>.py`. Add `<name>` to `FUZZERS` and add
  `$(UV) python tools/fuzz_<name>.py` to the `test-tools` recipe, in the same position, so
  `make fuzz FUZZ=<name>` and the CI run address the same harness. `FUZZERS` is ordered
  because the short-run loop re-runs what the full run reported; a different order in the
  recipe and the registry is a gate failure.
- A new negative self-test is a `--self-test` flag on an existing `tools/*.py`. Add the
  tool's stem to `SELF_TESTS`, which is all the `test-tools` loop needs. `replay_contract_check`
  is the one tool the `exercise` recipe runs instead, and that placement is accepted.

`make check` reads `tools/` and the Makefile rather than a hand-copied list, so a harness
or a `--self-test` flag that no target reaches fails the gate instead of passing CI dark.
`tools/fuzz_common.py` is the shared harness library, not a harness, and is exempt.

Copy the structure of an existing one (`tools/fuzz_evidence_check.py` for a fuzzer,
`tools/evidence_check.py --self-test` for a self-test); the shape of both is fixed by the
above and by the arguments the Makefile passes.

## Generated files

`docs/DETECTORS.md` registry tables and `config/detector-config-manifest.json` are
generated from `tools/detector_spec.yaml`. Edit the spec, then:

```
make detectors
```

`make check` fails on a stale generated file, so never hand-edit the rendered tables
or the manifest.

## Releasing

The version policy is the one at the head of [CHANGELOG.md](CHANGELOG.md): this is a 0.x
project, so a minor bump may change tooling contracts and command names and a patch bump is
expected not to. An `Unreleased` section carrying a `Breaking` entry therefore ships as the
next minor, never as a patch.

A release is one commit that edits three places by hand:

1. `[project] version` in [pyproject.toml](pyproject.toml).
2. The `## [Unreleased]` heading in [CHANGELOG.md](CHANGELOG.md) becomes
   `## [x.y.z] - YYYY-MM-DD`, and a fresh empty `## [Unreleased]` takes its place.
3. The tag `v<x.y.z>` on that commit.

`make check` fails when the manifest version and the newest dated changelog section disagree,
when the dated sections are not in descending order, when a release section repeats a
`###` change type or names one outside the Keep a Changelog set, and when a release
carrying a `Breaking` or `Removed` entry is cut as a patch bump. The first two cannot ship
out of sync, and the last is the policy above enforced rather than stated.

The tag is the third hand-edited place and nothing can check it, so tag the release
commit, never a later one, and never move or re-cut a published tag.

## Dependencies

The default is no new dependency. A package that only runs in this repository's
gate (a formatter, a linter, a type checker) belongs in `[dependency-groups] dev` in
[pyproject.toml](pyproject.toml); anything the shipped tools import at runtime belongs
in `[project] dependencies`. The runtime list is one package today (`PyYAML`, for the
detector spec), which is the point: uv.lock is the whole third-party surface, and it
is regenerated with `uv lock` and reviewed like any other change, and every gate runs
uv in `--locked` mode, so a dependency declared without a lock entry stops the run
instead of leaving the old set installed. `make sbom` renders
what the lock holds as CycloneDX 1.6, with each package marked `runtime` or `dev`, so
the blast radius of a release is readable without running uv.

`make check` enforces the other half of that contract: every distribution declared in
`pyproject.toml` is imported by shipped Python or run by a make target, and every
third-party import resolves to a declared distribution. A declaration the code stopped
needing, and an import that only works because something else happens to be installed,
both fail the gate. A distribution whose import name is not its own name
(`PyYAML` imports as `yaml`) records that mapping in `IMPORT_NAME_ALIASES` in
`tools/doccheck.py`; without the entry the used dependency reads as unused.

## Before you open a change

- `make ci` green, and `make detectors` leaves the tree clean.
- A line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) in Keep a Changelog
  form, for anything a user of the tooling would notice.
- Detector changes touch `tools/detector_spec.yaml` first, with a severity ceiling
  and context justified in [docs/DECISIONS.md](docs/DECISIONS.md).

## Where the rules live

[AGENTS.md](AGENTS.md) owns the design contract and what this repository does not
own. [docs/INDEX.md](docs/INDEX.md) is the reading order and the canonical owner per
document. [TODO.md](TODO.md) holds the phase gates. Branch from `main` under
`feat/`, `fix/`, `docs/`, `test/`, or `chore/`.
