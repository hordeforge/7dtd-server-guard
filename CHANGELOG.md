# Changelog

Notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); each section matches a
release tag.

This is a 0.x project: minor bumps (`0.Y.z`) may change tooling contracts and
command names, patch bumps are expected not to. Releases before 0.3.0 predate
this file and are described only by their git tags.

## [Unreleased]

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
