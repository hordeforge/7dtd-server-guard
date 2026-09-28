# Contributing

The runnable path from a fresh clone to a merged change. Prose accuracy in `docs/`
is gated separately by `make check`; this file is the runnable contract.

## Prerequisites

- [uv](https://docs.astral.sh/uv/). It installs the interpreter minor pinned in
  [.python-version](.python-version) and resolves the locked dependency set, so the
  local toolchain is the CI toolchain.
- `make` and a POSIX shell.
- Network access on the first run, for the uv interpreter and lockfile download.

Nothing is installed globally: `make setup` materializes `.venv/` inside the clone.

## Bootstrap and loop

```
make setup      # uv sync --frozen, once per clone
make check      # docs quality gate: run before opening a change
make lint       # black, ruff, mypy over tools/
make ci         # everything CI runs, in one local step
```

`make ci` is the same command CI runs, so a green `make ci` means a green workflow.

Single harness while editing one tool:

```
make fuzz FUZZ=replay_trace                  # short run, default seed
make fuzz FUZZ=evidence_check ITERATIONS=50 SEED=1234
```

Fuzzers are seeded, so the `seed=` and `iterations=` a failure reported reproduce
it exactly. `make help` lists every target.

## Generated files

`docs/DETECTORS.md` registry tables and `config/detector-config-manifest.json` are
generated from `tools/detector_spec.yaml`. Edit the spec, then:

```
make detectors
```

`make check` fails on a stale generated file, so never hand-edit the rendered tables
or the manifest.

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
