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
make setup      # uv sync --frozen, once per clone
make check      # docs quality gate: run before opening a change
make lint       # black, ruff, mypy over the whole repository
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
and when the dated sections are not in descending order, so the first two cannot ship out of
sync. The tag is the third hand-edited place and nothing can check it, so tag the release
commit, never a later one, and never move or re-cut a published tag.

## Dependencies

The default is no new dependency. A package that only runs in this repository's
gate (a formatter, a linter, a type checker) belongs in `[dependency-groups] dev` in
[pyproject.toml](pyproject.toml); anything the shipped tools import at runtime belongs
in `[project] dependencies`. The runtime list is one package today (`PyYAML`, for the
detector spec), which is the point: uv.lock is the whole third-party surface, and it
is regenerated with `uv lock` and reviewed like any other change. `make sbom` renders
what the lock holds as CycloneDX 1.6, with each package marked `runtime` or `dev`, so
the blast radius of a release is readable without running uv.

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
