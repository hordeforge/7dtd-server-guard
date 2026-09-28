"""Docs quality gate for 7dtd-server-guard.

Run from the repo root:  uv run python tools/doccheck.py   (or `make check`)

Checks:
   1. No em dashes (U+2014) in any markdown file or shipped source file (workspace rule).
   2. Every internal markdown link resolves to an existing file or anchor.
   3. TODO.md checkboxes use the canonical `- [ ]` / `- [x]` format.
   4. tools/detector_spec.yaml is well-formed and satisfies the D-07/D-15 ceiling
      rule plus the normal+violation fixture requirement per detector.
   5. docs/DETECTORS.md and config/detector-config-manifest.json match the rendered
      output of render_detectors.py.
   6. Every backticked detector ID token (`family.subject`) used across docs is present in
      the spec; example-config mode keys match the registry both ways and never exceed the
      spec's default mode for a detector.
   7. The generated config manifest matches the spec's phase/ceiling/mode metadata and
      declares exactly the spec's threshold keys; every example-config threshold key
      exists in the manifest and its value satisfies the manifest's type and range.
   8. Every key path in config/server-guard.example.json is declared in the config-schema
      table of docs/SCHEMAS.md, and every key the config schema declares is documented
      there and either defaulted or shown in the example.
   9. The shipped JSON Schemas parse, and the example config, generated manifest,
      evidence sample JSONL, and replay-trace fixture conform to them. Every json
      excerpt in docs/SCHEMAS.md validates against the schema its section names.
  10. The shipped evidence sample verifies as a hash chain (tools/evidence_check.py).
  11. The design-time replay contract vector passes its semantic checks.
  12. Documented folder structure holds: required docs exist and every planned directory
      under src/, tests/, tools/, config/ carries a README.
  13. Every open object in the evidence schema carries the property-name deny-list,
      so no raw identity, contact, network address, or credential can ride along in
      a detector-supplied value bag.
  14. The backup and restore path stays wired: the archive targets exist in the Makefile,
      run under test-tools, and docs/OPERATIONS.md states RPO/RTO and a restore drill.
  15. The release contract holds: pyproject.toml's `[project] version` is the newest dated
      CHANGELOG.md section, and the dated sections descend.
  16. CHANGELOG.md follows Keep a Changelog: one heading per change type per release, from
      the documented set, and no release carrying a `Breaking` or `Removed` entry cut as a
      patch bump.
  17. Every shipped fuzzer and every tool exposing `--self-test` is reachable from a
      make target, and the FUZZERS registry matches the order `make test-tools` runs.
  18. Every third-party action a workflow runs is pinned to a 40-character commit SHA
      and carries a trailing release comment, so a dependabot bump cannot leave the
      workflow claiming a version it no longer runs.
  19. Every declared dependency is used: each distribution in pyproject.toml is
      imported by shipped Python or run by a make target, and every third-party
      import resolves to a declared distribution.
  20. The build toolchain is pinned once and honored: the uv release in ci.yml is the one
      pyproject requires, actions and the runner image are not moving refs, `make setup` and
      every recipe run uv in `--locked` mode, and the Makefile and ci.yml agree on TZ and
      PYTHONHASHSEED.

Exit codes: 0 clean, 1 the gate found issues, 2 usage error. The one-line summary goes to
stdout and the
per-check failure detail to stderr, so a redirected run keeps the verdict on one
stream and the diagnostics on the other.
"""

from __future__ import annotations

import argparse
import ast
import itertools
import json
import math
import pathlib
import re
import subprocess
import sys
import tomllib
from collections import Counter
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import unquote

# Spec loading (and its PyYAML dependency guard) lives in render_detectors; the
# shipped-schema validator is shared with config_check, so it is its own module.
import render_detectors
import report_text
import schema_validate

# A parsed JSON Schema or instance: shape is what the checks below assert, so it
# cannot be narrowed statically.
Json = Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
# tools/fuzz_common.py is the harness library the fuzzers import, not a harness
# the Makefile runs, so it is the one tools/fuzz_*.py that is not a registry entry.
FUZZ_SHARED_MODULES = frozenset({"fuzz_common"})
# Directories that hold nothing this repo ships: version control, the local
# environment, tool caches, and the scratch tree the workspace rules tell
# contributors to work in. Their contents are not docs and must not fail the gate.
SKIP_DIRS = frozenset({".git", ".venv", ".mypy_cache", ".ruff_cache", ".scratch"})
MD_FILES = sorted(
    p for p in ROOT.rglob("*.md") if not (SKIP_DIRS & set(p.parts)) and "third-party" not in p.parts
)
# The em-dash ban covers code comments and CI files, not just prose, so the gate
# reads every text file this repo ships.
SOURCE_FILES = sorted(
    p
    for p in [
        ROOT / "Makefile",
        *ROOT.glob("*.toml"),
        *ROOT.glob("*.ini"),
        *(ROOT / "tools").glob("*.py"),
        *(ROOT / "tools").glob("*.yaml"),
        *(ROOT / "tools").rglob("*.json"),
        *(ROOT / "tools").rglob("*.jsonl"),
        *(ROOT / "config").rglob("*.json"),
        *(ROOT / "config").rglob("*.jsonl"),
        *(ROOT / ".github").rglob("*.yml"),
        *(ROOT / ".github").rglob("*.yaml"),
    ]
    if p.is_file() and "__pycache__" not in p.parts
)

REQUIRED_DOCS = [
    "docs/INDEX.md",
    "docs/DETECTORS.md",
    "docs/POLICY.md",
    "docs/THREAT_MODEL.md",
    "docs/ARCHITECTURE.md",
    "docs/SCHEMAS.md",
    "docs/SIGNALS.md",
    "docs/PROPOSALS.md",
    "docs/EXECUTION.md",
    "docs/RESEARCH.md",
    "docs/TEST_PLAN.md",
    "docs/DECISIONS.md",
    "docs/OPERATIONS.md",
    "docs/METHODOLOGY.md",
    "docs/UPGRADING.md",
    "TODO.md",
    "PRIVACY.md",
    "SECURITY.md",
    "README.md",
    "AGENTS.md",
]

SPEC_FAMILIES = frozenset(render_detectors.FAMILY_ORDER)
SPEC_CEILINGS = {"Hard", "Strong", "Weak"}
SPEC_ROLES = {"observed", "decision"}
SPEC_AUTHORITIES = {"server-derived", "client-declared"}
SPEC_THRESHOLD_TYPES = {"int", "float", "string"}
SPEC_MODES = {"observe", "correct", "enforce"}
NUMERIC_THRESHOLD_TYPES = {"int", "float"}


def in_vocab(value: Json, vocab: frozenset[str] | set[str]) -> bool:
    """Whether a spec value is a member of a string vocabulary.

    Every value reaching these checks comes from YAML, where a nested list or
    mapping can land in any field. `x in vocab` raises on an unhashable x, so a
    malformed spec would crash the gate instead of being reported by it.
    """
    return isinstance(value, str) and value in vocab


# Fixture families are owned by render_detectors.py (they head the registry matrix);
# importing keeps this validator from drifting from the rendered table.
ALLOWED_FIXTURES = frozenset(render_detectors.FIXTURE_FAMILIES)

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
DETECTOR_ID_RE = re.compile(r"`([a-z]+\.[a-z_]+)`")
# An ATX heading (`## Scope`), and the underline of a setext one (`Scope` then
# `-----`). Both are matched against unfenced_lines, since a `#` inside a fenced
# block is a comment or a shell prompt, not a heading.
ATX_RE = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")
SETEXT_RE = re.compile(r"^=+\s*$|^-{2,}\s*$")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
# A TODO.md task marker, in the canonical spelling and in every spelling
# CommonMark still renders as a checkbox.
CANONICAL_CHECKBOX_RE = re.compile(r"^[-*] \[[ xX]\]")
ANY_CHECKBOX_RE = re.compile(r"^(?:[-*+]|\d+[.)])\s*\[[ xX]\]")
# A released changelog section, dated. `## [Unreleased]` carries no version and is
# not a release, so it cannot be compared against the manifest.
RELEASED_SECTION_RE = re.compile(r"^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$", re.MULTILINE)
# The change types a release section may carry, one heading each. `Breaking` is
# not a Keep a Changelog type, it is this project's: the 0.x policy at the head of
# the changelog promises a reader that such a section means a minor bump, which is
# a promise about the version number and not something the format states.
CHANGE_TYPES = (
    "Breaking",
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
)
# A section carrying one of these says the release is not backward compatible.
BREAKING_TYPES = frozenset({"Breaking", "Removed"})


def unfenced_lines(text: str) -> Iterator[tuple[int, str]]:
    """(0-based index, line) for every line outside a fenced code block.

    A fenced block is prose about the markdown, not the markdown itself, so a
    `#` or a `- [ ]` inside one is a comment or an example, not a heading or a
    task marker. The opening and closing marker lines are dropped too.
    """
    fence: str | None = None
    for i, line in enumerate(text.splitlines()):
        if (fence_match := FENCE_RE.match(line)) is not None:
            marker = fence_match.group(1)
            fence = None if fence == marker else marker
            continue
        if fence is None:
            yield i, line


# Key patterns declared in the SCHEMAS.md config table. They share the dotted
# family.subject shape with detector IDs, but rows like actions.correct or
# availability.burst are schema keys, not detectors; placeholder segments such
# as <detectorId> stand in for per-detector subtrees.
SCHEMA_TABLE_RE = re.compile(
    r"^\| `([^`]+)` \| (?:int|bool|string|number|number/string) \|", re.MULTILINE
)


def _schema_table_keys() -> list[str]:
    return SCHEMA_TABLE_RE.findall((ROOT / "docs" / "SCHEMAS.md").read_text(encoding="utf-8"))


CONFIG_SCHEMA_KEYS: frozenset[str] = frozenset(_schema_table_keys())

# A numeric threshold range in the spec is a [min, max] pair.
RANGE_BOUNDS = 2
# Per-check cap on printed failures; the rest are summarized as a count.
MAX_REPORTED = 40


def _is_finite_number(v: Json) -> bool:
    """True for a real number, excluding bool, NaN, and the infinities.

    YAML parses `.nan` and `.inf` into Python floats, and a range bound or
    default carrying one compares false against everything downstream, so the
    spec gate has to name it instead of letting it through.
    """
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, float) and math.isfinite(v)


def _is_int_value(v: Json) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


# Every shipped (JSON Schema, data) pair: gated by check_config_schemas and fuzzed
# by tools/fuzz_schema_validate.py, which imports this list to stay in sync.
SCHEMA_DATA_PAIRS = [
    (
        ROOT / "config" / "schemas" / "config.v1.schema.json",
        ROOT / "config" / "server-guard.example.json",
    ),
    (
        ROOT / "config" / "schemas" / "config-manifest.v1.schema.json",
        ROOT / "config" / "detector-config-manifest.json",
    ),
    (
        ROOT / "config" / "schemas" / "evidence.v1.schema.json",
        ROOT / "config" / "schemas" / "evidence.v1.sample.jsonl",
    ),
    (
        ROOT / "config" / "schemas" / "replay-trace.v1.schema.json",
        ROOT / "tools" / "fixtures" / "traces" / "inventory" / "stack.v1.sample.json",
    ),
]

EVIDENCE_SCHEMA = ROOT / "config" / "schemas" / "evidence.v1.schema.json"
# The one property-name deny-list every open evidence value bag $refs.
PERSONAL_DATA_DENY_LIST = "personalDataDenyList"
DENY_LIST_REF = f"#/definitions/{PERSONAL_DATA_DENY_LIST}"
# The value-shape deny-list every open value bag and every bounded free-text
# field $refs. A key the schema permits is not a value the schema permits.
PERSONAL_DATA_VALUE_DENY_LIST = "personalDataValueDenyList"
VALUE_DENY_LIST_REF = f"#/definitions/{PERSONAL_DATA_VALUE_DENY_LIST}"


def detector_ids_in(text: str) -> set[str]:
    """Collect backticked `family.subject` tokens from a doc for detector families."""
    ids: set[str] = set()
    for m in DETECTOR_ID_RE.finditer(text):
        family = m.group(1).split(".", 1)[0]
        if family in SPEC_FAMILIES and m.group(1) not in CONFIG_SCHEMA_KEYS:
            ids.add(m.group(1))
    return ids


def check_em_dashes() -> list[str]:
    out = []
    for p in MD_FILES + SOURCE_FILES:
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if "\u2014" in line:
                out.append(f"{p.relative_to(ROOT)}:{i}: em dash: {line.strip()[:80]}")
    return out


def _dir_names(
    directory: pathlib.Path, cache: dict[pathlib.Path, frozenset[str]]
) -> frozenset[str]:
    """The entry names of `directory`, listed once per gate run.

    A relative link target is walked one component at a time and every component
    is matched against the containing directory's own entries, so a doc set whose
    links all point into docs/, config/, and src/ re-listed those same three
    directories once per link component. The cache lives as long as one
    `check_links` call, which is the window in which nothing writes to the tree.
    """
    names = cache.get(directory)
    if names is None:
        names = frozenset(entry.name for entry in directory.iterdir())
        cache[directory] = names
    return names


def link_failure(
    start: pathlib.Path, target: str, cache: dict[pathlib.Path, frozenset[str]]
) -> str | None:
    """Why a relative link target does not resolve under `start`, or None when it does.

    `exists()` alone is not the check: on a case-insensitive filesystem (NTFS,
    APFS, or ext4 mounted casefold) a link to `docs/index.md` opens `docs/INDEX.md`,
    so a wrong-case link passes this gate on a contributor's machine and breaks on
    the case-sensitive host CI runs on. Each component is matched against the
    directory's own entries instead, which compares names exactly whatever the
    host filesystem does with case, and a component that only matches when case is
    folded is named as the case error it is.
    """
    current = start
    for part in pathlib.PurePosixPath(target).parts:
        if part == ".":
            continue
        if part == "..":
            current = current.parent
            continue
        if not current.is_dir():
            return "broken link"
        names = _dir_names(current, cache)
        if part not in names:
            return (
                "link target name case does not match the file on disk"
                if any(name.casefold() == part.casefold() for name in names)
                else "broken link"
            )
        current = current / part
    return None if current.exists() else "broken link"


def heading_slugs(text: str) -> set[str]:
    """Every anchor a markdown file offers, as GitHub renders them.

    A link's `#fragment` is its heading lowercased, stripped of punctuation, and
    with spaces turned into hyphens, so `## Scope, in brief` answers to
    `#scope-in-brief`. A heading repeated in one file gets `-1`, `-2`, ... on
    every repeat after the first, which is why the counts are tracked rather
    than the set alone: two `## Notes` sections make one `#notes` and one
    `#notes-1`, and a link to either must resolve.
    """
    slugs: set[str] = set()
    repeats: dict[str, int] = {}
    lines = text.splitlines()
    for i, line in unfenced_lines(text):
        heading: str | None = None
        if atx := ATX_RE.match(line):
            heading = atx.group(1)
        elif i + 1 < len(lines) and line.strip() and SETEXT_RE.match(lines[i + 1]):
            heading = line.strip()
        if heading is None:
            continue
        base = re.sub(r"[^\w\- ]", "", heading.lower()).strip().replace(" ", "-")
        if not base:
            continue
        seen = repeats.get(base, 0)
        slugs.add(base if seen == 0 else f"{base}-{seen}")
        repeats[base] = seen + 1
    return slugs


def check_links() -> list[str]:
    out = []
    dir_names: dict[pathlib.Path, frozenset[str]] = {}
    slugs: dict[pathlib.Path, set[str]] = {}
    for p in MD_FILES:
        text = p.read_text(encoding="utf-8")
        for m in LINK_RE.finditer(text):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:", "../")):
                # "../" links point at sibling repos (7dtd-engine-research etc.), which
                # do not exist in a single-repo checkout; they are audited by
                # the cross-repo link pass, not by this per-repo gate.
                continue
            path_part, _, anchor = target.partition("#")
            if path_part and (reason := link_failure(p.parent, path_part, dir_names)):
                out.append(f"{p.relative_to(ROOT)}: {reason} -> {target}")
                continue
            if not anchor:
                continue
            # A bare `#fragment` names a heading in the linking file itself, so the
            # base is the file when the path half is empty.
            base = p.parent / path_part if path_part else p
            if base.suffix != ".md" or not base.is_file():
                continue
            # Headings are read once per file, not once per link into it: a doc
            # set whose links all carry anchors re-read and re-parsed the same
            # targets for every link, and the anchors of one file are the same
            # answer every time. The cache lives as long as this call, which is
            # the window in which nothing writes to the tree.
            anchors = slugs.get(base)
            if anchors is None:
                anchors = heading_slugs(base.read_text(encoding="utf-8"))
                slugs[base] = anchors
            if unquote(anchor) not in anchors:
                out.append(f"{p.relative_to(ROOT)}: no heading matches the anchor -> {target}")
    return out


def check_todo_format() -> list[str]:
    """TODO.md task markers are the canonical `- [ ]` / `- [x]` list-item form.

    CommonMark renders a task box from any list item whose first token is the
    marker, so `-  [ ] x` and `-[ ] x` become checkboxes too. A gate that only
    rejects the `- [` spelling let those through, and a phase gate that renders
    as an unchecked box on one host and as text on another is not a gate.
    """
    todo = ROOT / "TODO.md"
    out = []
    for i, line in unfenced_lines(todo.read_text(encoding="utf-8")):
        stripped = line.strip()
        if CANONICAL_CHECKBOX_RE.match(stripped):
            continue
        if ANY_CHECKBOX_RE.match(stripped):
            out.append(f"TODO.md:{i + 1}: malformed checkbox: {stripped[:80]}")
    return out


def _changelog_sections(text: str) -> list[tuple[str, list[str]]]:
    """Every `## [...]` section of the changelog with the `###` change types it holds."""
    starts = [(m.start(), m.group(1)) for m in re.finditer(r"^## \[([^\]]+)\]", text, re.MULTILINE)]
    ends = [s for s, _ in starts[1:]] + [len(text)]
    return [
        (title, re.findall(r"^### ([A-Za-z]+)[ \t]*$", text[start:end], re.MULTILINE))
        for (start, title), end in zip(starts, ends, strict=False)
    ]


def semver(version: str) -> tuple[int, int, int]:
    """A `x.y.z` version as the tuple the release rules compare. The callers match it first."""
    major, minor, patch = version.split(".")
    return (int(major), int(minor), int(patch))


def changelog_format_findings(text: str) -> list[str]:
    """One section per change type per release, and a break that says so in the version.

    Keep a Changelog gives each release one heading per change type. Two `### Added`
    blocks under one release render as a single heading, so the second group of
    entries reads as part of the first and a reader cannot tell which entries a
    release added and which it carried over.

    The version check is the same rule the 0.x policy at the head of the changelog
    states: a patch bump is expected not to carry a `Breaking` or `Removed` entry.
    Two hand-edited files carrying the bump is how a breaking change reaches a
    patch tag unnoticed, and the tag is what an operator pins.
    """
    out = []
    released: list[tuple[tuple[int, int, int], str, list[str]]] = []
    for title, names in _changelog_sections(text):
        for name, count in Counter(names).items():
            if name not in CHANGE_TYPES:
                out.append(
                    f"CHANGELOG.md: `## [{title}]` has `### {name}`, not a Keep a Changelog type"
                )
            elif count > 1:
                out.append(
                    f"CHANGELOG.md: `## [{title}]` has {count} `### {name}` sections, not one"
                )
        if re.fullmatch(r"\d+\.\d+\.\d+", title):
            released.append((semver(title), title, names))
    for (newer_v, newer, newer_names), (older_v, older, _) in itertools.pairwise(released):
        breaking = sorted(set(newer_names) & BREAKING_TYPES)
        if breaking and newer_v[:2] == older_v[:2]:
            out.append(
                f"CHANGELOG.md: {newer} carries a {'/'.join(breaking)} entry but is a patch "
                f"bump over {older}"
            )
    return out


def check_changelog_format() -> list[str]:
    """The shipped changelog against the release rules, the document they are written for."""
    return changelog_format_findings((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))


# The heading a release with a breaking change carries in docs/UPGRADING.md:
# `## 0.4.1 to 0.5.0`, oldest first, so it reads as the direction of the upgrade.
UPGRADE_SECTION_RE = re.compile(r"^## (\d+\.\d+\.\d+) to (\d+\.\d+\.\d+)$", re.MULTILINE)


def upgrade_guide_findings(changelog: str, guide: str) -> list[str]:
    """Every released break must name the upgrade step that gets a consumer past it.

    A changelog entry states what changed; an entry that states only that, under a
    heading the reader must already know to look for, leaves the reader with a diff and
    no next action. A config that stops loading, a record that stops validating, and an
    exit code that changes meaning each break an upgrade in a way the operator discovers
    by restarting the server. The changelog rule above forces the entry, this one forces
    the instruction, and both fire on the release commit that carries the break.

    Only dated sections are compared. `## [Unreleased]` is the tree between releases, and
    its section is written under the version it will be cut as, which the heading above
    the comparison says rather than the heading itself.
    """
    released = RELEASED_SECTION_RE.findall(changelog)
    breaking = {
        title
        for title, names in _changelog_sections(changelog)
        if re.fullmatch(r"\d+\.\d+\.\d+", title) and BREAKING_TYPES & set(names)
    }
    covered = set(UPGRADE_SECTION_RE.findall(guide))
    out = []
    for older, newer in itertools.pairwise(reversed(released)):
        if newer in breaking and (older, newer) not in covered:
            out.append(
                f"CHANGELOG.md: {newer} carries a break and docs/UPGRADING.md has no "
                f"`## {older} to {newer}` section"
            )
    return out


def check_upgrade_guide() -> list[str]:
    """The shipped changelog and upgrade guide against the rule above."""
    return upgrade_guide_findings(
        (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
        (ROOT / "docs" / "UPGRADING.md").read_text(encoding="utf-8"),
    )


def check_release_version() -> list[str]:
    """Keep the manifest version and the changelog's newest release the same number.

    A release is a tag, the `[project] version` in pyproject.toml, and a dated
    changelog section, three places edited by hand. Nothing in the build reads the
    other two, so a bump that misses one ships a tag whose manifest still says the
    previous release, and the mismatch is only visible to a consumer reading the
    installed metadata. This gate fails the release commit itself instead.

    Only dated sections are compared. `## [Unreleased]` sits above them while the
    tree is between releases and is expected to be ahead of the last tag.
    """
    manifest = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = manifest["project"]["version"]
    released = RELEASED_SECTION_RE.findall((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
    out = []
    if not released:
        return ["CHANGELOG.md: no dated `## [x.y.z] - YYYY-MM-DD` release section"]
    if version != released[0]:
        out.append(
            f"pyproject.toml: [project] version is {version}, the newest changelog "
            f"release is {released[0]}"
        )
    for newer, older in itertools.pairwise(released):
        if semver(newer) <= semver(older):
            out.append(f"CHANGELOG.md: {older} is not older than the {newer} above it")
    return out


def self_test() -> list[str]:
    """Fire the changelog format rules from changelogs written here, not shipped.

    The shipped changelog is the only document the gate reads, and it is written
    to pass: a rule that stopped firing would leave the tree green. Each case is a
    document the rule has to reject, or accept, and the finding it has to name.
    """
    out: list[str] = []
    cases = [
        (
            "two Added sections",
            "## [Unreleased]\n\n### Added\n\n- a\n\n### Added\n\n- b\n",
            "has 2 `### Added` sections, not one",
        ),
        (
            "unknown change type",
            "## [Unreleased]\n\n### Improvements\n\n- a\n",
            "`### Improvements`, not a Keep a Changelog type",
        ),
        (
            "breaking change in a patch release",
            (
                "## [0.4.2] - 2026-10-01\n\n### Breaking\n\n- a\n\n"
                "## [0.4.1] - 2026-09-20\n\n### Changed\n\n- a\n"
            ),
            "0.4.2 carries a Breaking entry but is a patch bump over 0.4.1",
        ),
    ]
    for label, document, needle in cases:
        found = changelog_format_findings(document)
        if not any(needle in item for item in found):
            out.append(f"changelog format: {label} not reported: expected {needle!r}, got {found}")
    clean = (
        "## [0.5.0] - 2026-10-01\n\n### Breaking\n\n- a\n\n### Added\n\n- b\n\n"
        "## [0.4.1] - 2026-09-20\n\n### Fixed\n\n- b\n"
    )
    out.extend(f"changelog format: {item}" for item in changelog_format_findings(clean))

    breaking_release = (
        "## [0.5.0] - 2026-10-01\n\n### Breaking\n\n- a\n\n"
        "## [0.4.1] - 2026-09-20\n\n### Fixed\n\n- b\n"
    )
    guide_cases = [
        (
            "a break with no upgrade section",
            breaking_release,
            "# Upgrading\n\n## Before any upgrade\n",
            "0.5.0 carries a break and docs/UPGRADING.md has no `## 0.4.1 to 0.5.0` section",
        ),
        (
            "a break whose upgrade section names the wrong pair",
            breaking_release,
            "# Upgrading\n\n## 0.4.0 to 0.5.0\n",
            "has no `## 0.4.1 to 0.5.0` section",
        ),
    ]
    for label, document, upgrade_doc, needle in guide_cases:
        found = upgrade_guide_findings(document, upgrade_doc)
        if not any(needle in item for item in found):
            out.append(f"upgrade guide: {label} not reported: expected {needle!r}, got {found}")
    covered = upgrade_guide_findings(
        breaking_release, "# Upgrading\n\n## 0.4.1 to 0.5.0\n\n- do the thing\n"
    )
    out.extend(f"upgrade guide: {item}" for item in covered)
    no_break = "## [0.4.2] - 2026-10-01\n\n### Fixed\n\n- a\n\n## [0.4.1] - 2026-09-20\n\n"
    out.extend(
        f"upgrade guide: {item}" for item in upgrade_guide_findings(no_break, "# Upgrading\n")
    )
    return out


def parsed_spec() -> list[object]:
    """The spec records, or none when the file does not parse.

    check_spec reports an unparseable spec. The cross-reference checks run in the
    same pass as check_spec, so they read the spec through this accessor rather
    than each raising a traceback on the same file.
    """
    try:
        return render_detectors.load_spec()
    except render_detectors.SpecError:
        return []


def spec_ids() -> set[str]:
    """Registry ids, or an empty set when the spec does not parse (check_spec reports that)."""
    return {did for did, _ in render_detectors.identified(parsed_spec())}


def _range_default_errors(did: str, t: Json, ttype: str) -> list[str]:
    """The numeric checks on one threshold: its [min, max] pair and its default.

    Both must be finite and the default must sit inside the range, because
    render_manifest copies every threshold's default into the shipped manifest
    unconditionally, so a missing or non-numeric one has to be rejected here. A
    YAML `true` is an int in Python, hence the bool exclusion, and a fractional
    value on an `int` threshold is truncated on load, so the value in the spec is
    not the value that runs.
    """
    if ttype not in {"int", "float"}:
        return []
    rng = t.get("range")
    if not isinstance(rng, list):
        return []
    out: list[str] = []
    key = t.get("key")
    default = t.get("default")
    if (
        len(rng) != RANGE_BOUNDS
        or not all(_is_finite_number(b) for b in rng)
        or not rng[0] <= rng[1]
    ):
        out.append(f"{did}: threshold {key} bad range {rng}")
    elif ttype == "int" and not all(_is_int_value(b) for b in rng):
        out.append(f"{did}: threshold {key} int type with fractional range")
    elif not _is_finite_number(default):
        out.append(f"{did}: threshold {key} default {default!r} is not a number")
    elif ttype == "int" and not _is_int_value(default):
        out.append(f"{did}: threshold {key} int type with fractional default")
    elif not rng[0] <= default <= rng[1]:
        out.append(f"{did}: threshold {key} default {default} outside range {rng}")
    return out


def _threshold_errors(did: str, thresholds: Json) -> list[str]:
    """Threshold keys are unique, typed, and carry a sane range and default.

    Every field is read with .get: a hand-edited spec missing a key must be
    reported, not raise out of the gate, and an entry that is not a mapping at
    all is reported the same way instead of being indexed.
    """
    if not isinstance(thresholds, list):
        return [f"{did}: thresholds must be a list, got {type(thresholds).__name__}"]
    out: list[str] = []
    entries = [t if isinstance(t, dict) else {} for t in thresholds]
    if any(not isinstance(t, dict) for t in thresholds):
        out.append(f"{did}: threshold entries must all be mappings")
    keys: list[str] = []
    for t in entries:
        key = t.get("key")
        if not isinstance(key, str) or not key:
            out.append(f"{did}: threshold missing key {key!r}")
            continue
        keys.append(key)
    if len(keys) != len(set(keys)):
        out.append(f"{did}: duplicate threshold keys")
    for t in entries:
        ttype = t.get("type")
        if not isinstance(ttype, str) or not in_vocab(ttype, SPEC_THRESHOLD_TYPES):
            out.append(f"{did}: threshold {t.get('key')} bad type {ttype}")
            continue
        out.extend(_range_default_errors(did, t, ttype))
    return out


def _input_errors(did: str, inputs: object) -> list[str]:
    """Every declared input carries a known authority and role."""
    if not isinstance(inputs, list):
        return [f"{did}: inputs must be a list, got {type(inputs).__name__}"]
    out = [] if inputs else [f"{did}: no inputs"]
    for i in inputs:
        if not isinstance(i, dict):
            out.append(f"{did}: input must be a mapping, got {i!r}")
            continue
        if not in_vocab(i.get("authority"), SPEC_AUTHORITIES):
            out.append(f"{did}: input {i.get('name')} bad authority {i.get('authority')}")
        if not in_vocab(i.get("role"), SPEC_ROLES):
            out.append(f"{did}: input {i.get('name')} bad role {i.get('role')}")
    return out


def _fixture_errors(did: str, fixtures: object) -> list[str]:
    """Fixture names are TEST_PLAN families, and normal and violation are both declared."""
    if not isinstance(fixtures, list):
        return [f"{did}: fixtures must be a list, got {type(fixtures).__name__}"]
    names = {f for f in fixtures if isinstance(f, str)}
    out = [
        f"{did}: fixture {f} outside TEST_PLAN families" for f in sorted(names - ALLOWED_FIXTURES)
    ]
    # TEST_PLAN.md Layer 4: every detector ships normal and violation traces.
    if "normal" not in names or "violation" not in names:
        out.append(f"{did}: must declare normal and violation fixtures (TEST_PLAN Layer 4)")
    return out


def _detector_errors(d: Json) -> list[str]:
    """Required fields, input authority/role vocabulary, fixtures, and the D-07 rule."""
    if not isinstance(d, dict) or not isinstance(d.get("id"), str):
        # Without a usable id nothing below can be attributed to a detector;
        # check_spec reports the record through the structural validator.
        return [f"detector record must be a mapping with a string id, got {d!r}"]
    did = d["id"]
    out = []
    if not in_vocab(d.get("family"), SPEC_FAMILIES):
        out.append(f"{did}: bad family {d.get('family')}")
    if not in_vocab(d.get("ceiling"), SPEC_CEILINGS):
        out.append(f"{did}: bad ceiling {d.get('ceiling')}")
    if not in_vocab(d.get("default_mode"), SPEC_MODES):
        out.append(f"{did}: bad default_mode {d.get('default_mode')}")
    for field, note in (
        ("summary", ""),
        ("algorithm", ""),
        ("seam", " (Phase 1 probe target)"),
        ("state", ""),
    ):
        if not d.get(field):
            out.append(f"{did}: missing {field}{note}")
    inputs = d.get("inputs", [])
    out.extend(_input_errors(did, inputs))
    out.extend(_fixture_errors(did, d.get("fixtures", [])))
    # D-07 rule: Hard requires all decision inputs server-derived, or a hard_condition.
    # An `inputs` that is not a list is already reported by _input_errors; the scan
    # skips it rather than raising, so one malformed record costs its own finding
    # instead of aborting the pass and losing every other detector's errors with it.
    decision_client = (
        [
            name
            for i in inputs
            if isinstance(i, dict)
            and i.get("role") == "decision"
            and i.get("authority") == "client-declared"
            and isinstance(name := i.get("name"), str)
        ]
        if isinstance(inputs, list)
        else []
    )
    if d.get("ceiling") == "Hard" and decision_client and not d.get("hard_condition"):
        out.append(
            f"{did}: ceiling Hard with client-declared decision inputs "
            f"({', '.join(decision_client)}) and no hard_condition (POLICY.md D-07/D-15)"
        )
    return out + _threshold_errors(did, d.get("thresholds", []))


def check_spec() -> list[str]:
    """Validate tools/detector_spec.yaml and the D-07 ceiling rule."""
    try:
        detectors = render_detectors.load_spec()
    except render_detectors.SpecError as exc:
        return [f"tools/detector_spec.yaml {exc}"]

    out = [msg for i, d in enumerate(detectors) for msg in render_detectors.record_errors(i, d)]
    # Entries with no usable id are reported by the structural validator and by
    # _detector_errors; they cannot take part in the duplicate-id comparison.
    ids: list[str] = [
        d["id"] for d in detectors if isinstance(d, dict) and isinstance(d.get("id"), str)
    ]
    if len(ids) != len(set(ids)):
        dups = sorted(i for i, n in Counter(ids).items() if n > 1)
        out.append(f"duplicate detector ids in spec: {dups}")
    for d in detectors:
        out += _detector_errors(d)
    return out


# A gated tool reads and parses files off disk; a run that has not finished in this
# many seconds is stuck, and a gate that waits forever is indistinguishable from a
# gate that passes.
TOOL_TIMEOUT_S = 120


def _run_tool(script: str, *args: str, on_failure: str) -> list[str]:
    """Run a sibling tool as a gate. Returns its output as errors when it exits nonzero.

    A separate process keeps each tool's argparse and exit-code contract as the gated
    surface, instead of importing internals the CLI does not expose. Both streams are
    reported: a tool that prints findings and then dies on an exception writes the
    traceback to stderr, and dropping it hides the crash behind the findings.

    The child's output is decoded as UTF-8 like every other text boundary here: the
    child echoes file names and record content back, and a host whose locale is
    POSIX would otherwise decode that as ASCII and raise out of the gate.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - script names are literals, shell is off
            [sys.executable, str(ROOT / "tools" / script), *args],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            cwd=ROOT,
            check=False,
            timeout=TOOL_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return [f"{' '.join([script, *args])}: no result after {TOOL_TIMEOUT_S}s"]
    except OSError as exc:
        return [f"{script}: could not be run: {exc}"]
    if proc.returncode != 0:
        return [e for e in (proc.stdout.strip(), proc.stderr.strip()) if e] or [on_failure]
    return []


def check_registry_sync() -> list[str]:
    """Both generated files must match a fresh render of the spec: docs/DETECTORS.md
    and the config manifest operators copy thresholds out of."""
    return [
        *_run_tool("render_detectors.py", "--check", on_failure="registry is stale"),
        *_run_tool(
            "render_detectors.py",
            "--manifest",
            "--check",
            on_failure="config manifest is stale",
        ),
    ]


def _thresholds_by_key(thresholds: object) -> dict[str, Json]:
    """Threshold entries keyed by their declared key, skipping unusable entries.

    The cross-references read a spec that may be malformed, and check_spec owns
    the report on the entries that are; this pass only needs the keys.
    """
    if not isinstance(thresholds, list):
        return {}
    return {
        t["key"]: t for t in thresholds if isinstance(t, dict) and isinstance(t.get("key"), str)
    }


def _threshold_keys(thresholds: object) -> set[str]:
    """Declared threshold keys, ignoring entries the spec validator already reported."""
    return set(_thresholds_by_key(thresholds))


def _manifest_errors(example: Json, out: list[str], label: str = "example config") -> None:
    """Manifest metadata must track the spec, and both must cover the example config.

    Like every check here, a hand-edited manifest or spec is reported into the
    caller's error list; nothing is read with [] on a field that may be absent.
    """
    path = ROOT / "config" / "detector-config-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    entries = manifest.get("detectors")
    if not isinstance(entries, list):
        out.append("config/detector-config-manifest.json: detectors must be an array")
        return
    spec_by_id = dict(render_detectors.identified(parsed_spec()))
    # detector id -> that manifest entry's thresholds, keyed by threshold key.
    manifest_keys: dict[str, dict[str, Json]] = {}
    manifest_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("detectorId"), str):
            out.append(f"manifest detector entry without a detectorId: {entry!r}")
            continue
        detector_id = entry["detectorId"]
        manifest_ids.add(detector_id)
        spec_entry = spec_by_id.get(detector_id)
        if spec_entry is None:
            out.append(f"manifest detector {detector_id} not in spec")
            continue
        if (
            entry.get("phase") != spec_entry.get("phase")
            or entry.get("ceiling") != spec_entry.get("ceiling")
            or entry.get("defaultMode") != spec_entry.get("default_mode")
        ):
            out.append(f"manifest metadata drift for {detector_id}; re-run make detectors")
        declared = _threshold_keys(spec_entry.get("thresholds"))
        entry_keys = _thresholds_by_key(entry.get("thresholds"))
        manifest_keys[detector_id] = entry_keys
        out.extend(
            f"manifest threshold {detector_id}.{key} not declared in spec"
            for key in sorted(entry_keys)
            if key not in declared
        )
        out.extend(
            f"manifest is missing threshold {detector_id}.{key} declared in spec; "
            "re-run make detectors"
            for key in sorted(declared - entry_keys.keys())
        )
    out.extend(
        f"manifest is missing detector {d} declared in spec; re-run make detectors"
        for d in sorted(set(spec_by_id) - manifest_ids)
    )
    for did, keys in example.get("thresholds", {}).items():
        known = manifest_keys.get(did, {})
        out.extend(
            f"{label} threshold {did}.{key} not in generated manifest"
            for key in keys
            if key not in known
        )
        out.extend(
            error
            for key, value in keys.items()
            if (threshold := known.get(key)) is not None
            for error in _threshold_value_errors(did, key, value, threshold, label)
        )


def _threshold_value_errors(
    did: str, key: str, value: Json, threshold: Json, label: str = "example config"
) -> list[str]:
    """A configured threshold must satisfy the type and range its manifest entry declares.

    The strict Phase 2 loader enforces exactly this rule (SCHEMAS.md -> Per-detector config
    manifest); the gate enforces it now, so an out-of-range value never ships in the example
    an operator copies. tools/config_check.py runs it over an operator's own config file.
    """
    path = f"{label} threshold {did}.{key}"
    ttype = threshold.get("type")
    if ttype == "int" and (not isinstance(value, int) or isinstance(value, bool)):
        return [f"{path}: {value!r} is not an int"]
    if ttype == "float" and (isinstance(value, bool) or not isinstance(value, (int, float))):
        return [f"{path}: {value!r} is not a number"]
    if ttype == "string" and not isinstance(value, str):
        return [f"{path}: {value!r} is not a string"]
    rng = threshold.get("range")
    if (
        not in_vocab(ttype, NUMERIC_THRESHOLD_TYPES)
        or not isinstance(rng, list)
        or len(rng) != RANGE_BOUNDS
    ):
        return []
    numeric = isinstance(value, (int, float)) and not isinstance(value, bool)
    if not numeric or not rng[0] <= value <= rng[1]:
        return [f"{path}: {value!r} outside declared range {rng}"]
    return []


def check_detector_ids() -> list[str]:
    registered = spec_ids()
    out: list[str] = []
    if not registered:
        # Reporting every doc token and example-config mode as unknown would bury
        # the real cause; the detector spec check reports why the registry is empty.
        return ["tools/detector_spec.yaml yields no detector ids; see the detector spec check"]
    for p in MD_FILES:
        text = p.read_text(encoding="utf-8")
        out.extend(
            f"{p.relative_to(ROOT)}: detector ID not in registry: {tid}"
            for tid in sorted(detector_ids_in(text))
            if tid not in registered
        )

    # Every mode key in the example config must exist in the spec, and every
    # registered detector must have one.
    example = json.loads(
        (ROOT / "config" / "server-guard.example.json").read_text(encoding="utf-8")
    )
    example_modes = set(example.get("modes", {}).keys())
    out.extend(
        f"config example mode key not in registry: {mode_id}"
        for mode_id in sorted(example_modes - registered)
    )
    out.extend(
        f"config example missing mode key for registered detector: {mode_id}"
        for mode_id in sorted(registered - example_modes)
    )
    out.extend(_example_mode_errors(example))
    _manifest_errors(example, out)
    return out


# Detector modes in increasing severity. Raising one is a phase-gated operator decision
# (SCHEMAS.md -> Config schema, POLICY.md -> Enforcement gates), so the shipped example may
# never carry a mode above the one the spec declares as that detector's default.
MODE_SEVERITY = ("observe", "correct", "enforce")


def _example_mode_errors(example: Json) -> list[str]:
    """The example config may not ship a mode above the spec's default for any detector."""
    defaults = {did: d.get("default_mode") for did, d in render_detectors.identified(parsed_spec())}
    out = []
    for mode_id, mode in sorted(example.get("modes", {}).items()):
        if mode not in MODE_SEVERITY:
            continue
        default = defaults.get(mode_id)
        if default in MODE_SEVERITY and MODE_SEVERITY.index(mode) > MODE_SEVERITY.index(default):
            out.append(
                f"config example raises {mode_id} to '{mode}' above its spec default "
                f"'{default}'; phases raise modes through the POLICY.md gates, not the example"
            )
    return out


def _flatten(obj: dict[str, Json], prefix: str = "") -> list[str]:
    """Dotted paths for every leaf in a nested dict."""
    out = []
    for k, v in obj.items():
        path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.extend(_flatten(v, path))
        else:
            out.append(path)
    return out


def _schema_key_patterns() -> list[re.Pattern[str]]:
    """Compiled matchers for the SCHEMAS.md config-table key patterns."""
    return [_pattern_to_regex(pat) for pat in _schema_table_keys()]


def _pattern_to_regex(pat: str) -> re.Pattern[str]:
    """Compile a dotted schema key pattern; `<placeholder>` consumes one or more
    segments (detector IDs are family.subject, so usually two)."""
    parts = (
        ".+" if seg.startswith("<") and seg.endswith(">") else re.escape(seg)
        for seg in pat.split(".")
    )
    return re.compile(r"^" + r"\.".join(parts) + r"$")


def _matches_schema(path: str, patterns: list[re.Pattern[str]]) -> bool:
    """Match an example dotted path against compiled schema key patterns.

    A placeholder segment like <detectorId> consumes one or more dotted
    segments, so modes.<detectorId> matches modes.inventory.stack but not
    modes itself, and thresholds.<detectorId>.<key> matches
    thresholds.inventory.stack.stage_order.
    """
    return any(p.match(path) for p in patterns)


def check_evidence_sample_chain() -> list[str]:
    """The shipped evidence sample must verify as a hash chain."""
    return _run_tool("evidence_check.py", "--sample", on_failure="evidence sample chain broken")


def check_replay_contract() -> list[str]:
    """The design-time vertical-slice vector must satisfy its semantic expectations."""
    return _run_tool("replay_contract_check.py", on_failure="replay contract failed")


def load_instances(data_path: pathlib.Path) -> list[Json]:
    """Parse a data file into validator instances: one per record for JSONL, else one."""
    text = data_path.read_text(encoding="utf-8")
    if data_path.suffix == ".jsonl":
        return [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    return [json.loads(text)]


def _load_instances(data_path: pathlib.Path) -> tuple[list[Json], str | None]:
    """Parsed data documents, with a parse failure returned instead of raised.

    Returns (instances, error); error is None on success.
    """
    try:
        return load_instances(data_path), None
    except Exception as exc:
        return [], str(exc)


def check_config_schemas() -> list[str]:
    """Validate the shipped JSON Schemas parse and the example config and generated
    manifest conform to them."""
    out = []
    for schema_path, data_path in SCHEMA_DATA_PAIRS:
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        except Exception as exc:
            out.append(f"{schema_path.relative_to(ROOT)} unparseable: {exc}")
            continue
        name = data_path.relative_to(ROOT)
        instances, error = _load_instances(data_path)
        if error is not None:
            out.append(f"{name} unparseable: {error}")
            continue
        if data_path.suffix == ".jsonl":
            out.extend(
                f"{name} line {i}: {err}"
                for i, instance in enumerate(instances, 1)
                for err in schema_validate.validate(instance, schema)
            )
        else:
            out.extend(
                f"{name}: {err}"
                for instance in instances
                for err in schema_validate.validate(instance, schema)
            )
    return out


# A `##` heading that names the schema its section documents, and the fenced json
# blocks under it, so an excerpt in the prose is held to the schema it illustrates.
SCHEMA_SECTION_RE = re.compile(
    r"^## .*\((config|config-manifest|evidence|replay-trace) v1\)$", re.MULTILINE
)
JSON_FENCE_RE = re.compile(r"```json\n(.*?)\n```", re.DOTALL)


def check_docs_json_examples() -> list[str]:
    """Every json excerpt in SCHEMAS.md validates against the schema its section names.

    An excerpt is prose, so nothing held it to the schema, and a trimmed one drifts
    into a shape the strict loader would reject while the doc claims the excerpt is
    what the tool generates. Sections whose schema is a record shape with no shipped
    file (hook manifest, audit, health) name no version tag and are skipped.
    """
    text = (ROOT / "docs" / "SCHEMAS.md").read_text(encoding="utf-8")
    out = []
    for match in SCHEMA_SECTION_RE.finditer(text):
        schema_path = ROOT / "config" / "schemas" / f"{match.group(1)}.v1.schema.json"
        if not schema_path.exists():
            continue
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        section = text[match.end() :]
        for fence in JSON_FENCE_RE.finditer(section.split("\n## ", 1)[0]):
            try:
                example = json.loads(fence.group(1))
            except Exception as exc:
                out.append(f"docs/SCHEMAS.md: json excerpt is not valid JSON: {exc}")
                continue
            out.extend(
                f"docs/SCHEMAS.md: json excerpt does not match "
                f"{schema_path.relative_to(ROOT)}: {err}"
                for err in schema_validate.validate(example, schema)
            )
    return out


def _resolve_local_ref(node: Json, root: Json) -> Json:
    """The node a local `#/...` $ref names, or `node` itself when it names none.

    Only a local ref resolves: a remote one names a schema this file does not
    carry, and the gate reads the shipped file alone.
    """
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return node
    target: Json = root
    for part in ref[2:].split("/"):
        if not isinstance(target, dict) or part not in target:
            return node
        target = target[part]
    return target if isinstance(target, dict) else node


def _open_value_bags(
    node: Json,
    path: str = "$",
    root: Json | None = None,
    seen: frozenset[str] = frozenset(),
) -> list[tuple[str, Json]]:
    """Every subschema of `node` that accepts values beyond a declared set.

    Two shapes qualify. An object that does not close itself with
    `additionalProperties: false` takes keys of the author's choosing. An array
    with no `items` at all takes values of any shape, and is the hole an
    object-only walk misses: a bare `"type": "array"` carries no key names at
    all, so no `propertyNames` deny-list can be hung on it, and whatever a
    detector puts in each element reaches the exporter unchecked. An array
    whose `items` is an object is covered by the object rule through the
    recursion below; an `items` of any other type is already closed.

    A local $ref is followed, and `definitions` and an `additionalProperties`
    subschema are walked, because the evidence schema declares its shapes once
    and references them: a bag moved into `definitions` and referenced from a
    property reads to a ref-only walk as a node with no `type`, so the bag would
    pass the gate holding anything. `seen` carries the refs already resolved on
    this path so a pair of definitions that reference each other terminates.
    """
    if not isinstance(node, dict):
        return []
    if root is None:
        root = node
    if isinstance(node.get("$ref"), str):
        ref = node["$ref"]
        if ref in seen:
            return []
        resolved = _resolve_local_ref(node, root)
        if resolved is node:
            return []
        return _open_value_bags(resolved, path, root, seen | {ref})
    out: list[tuple[str, Json]] = []
    node_type = node.get("type")
    types = node_type if isinstance(node_type, list) else [node_type]
    if "object" in types and node.get("additionalProperties") is not False:
        out.append((path, node))
    if "array" in types and "items" not in node:
        out.append((path, node))
    for key in ("properties", "patternProperties"):
        for name, sub in (node.get(key) or {}).items():
            out += _open_value_bags(sub, f"{path}.{key}.{name}", root, seen)
    for name, sub in (node.get("definitions") or {}).items():
        out += _open_value_bags(sub, f"{path}.definitions.{name}", root, seen)
    for i, sub in enumerate(node.get("oneOf") or []):
        out += _open_value_bags(sub, f"{path}.oneOf[{i}]", root, seen)
    extra = node.get("additionalProperties")
    if isinstance(extra, dict):
        out += _open_value_bags(extra, f"{path}.additionalProperties", root, seen)
    return out + _open_value_bags(node.get("items"), f"{path}.items", root, seen)


def check_evidence_personal_data() -> list[str]:
    """Every open value bag in the evidence schema carries the one deny-list.

    Detectors write their observed and expected values into `context`,
    `observations`, `expected`, `actual`, and `replayedFrom`; those bags are the
    one place a detector could hand a raw platform ID, a player name, an
    address, or a credential to the exporter, the operator, and the webhook
    consumer. The deny-list is the machine form of the SCHEMAS.md rule that no
    schema ever carries one. The list is declared once, in `definitions`, and
    every bag must $ref it: a second hand-written copy is where a newly denied
    key would be added to one bag and forgotten in another, and a bag that
    dropped the ref would still pass a presence-only check. An array with no
    `items` is reported too: it holds no key names, so it can carry a value of
    any shape with nothing to validate it against.

    The name list closes the key, so a second pass closes the value. A permitted
    key with a neutral name (`note`, `reason`, `marker`) is where a platform id
    or an address lands the moment a detector interpolates what the game handed
    it, and a name list cannot see it, so every bag must also carry the shared
    value deny-list as its `additionalProperties`. The bounded free-text fields
    are checked the same way and for the same reason: `maxLength` is this
    schema's marker for a field a writer fills by hand, and every one of them
    (`suppressedReason`, `modIdentity`, `itemId`, `marker`, `actor`, `reason`)
    takes free text. Gating on that marker rather than on a name list means a
    free-text field added later is covered without being enumerated here.
    """
    schema = json.loads(EVIDENCE_SCHEMA.read_text(encoding="utf-8"))
    definitions = schema.get("definitions") or {}
    for name in (PERSONAL_DATA_DENY_LIST, PERSONAL_DATA_VALUE_DENY_LIST):
        sub = definitions.get(name)
        if not isinstance(sub, dict) or "pattern" not in sub:
            return [f"evidence schema: definitions/{name} is missing or has no pattern"]
    out = []
    for path, sub in _open_value_bags(schema):
        if "propertyNames" not in sub:
            kind = "array" if sub.get("type") == "array" else "object"
            out.append(f"evidence schema {path}: open {kind} has no propertyNames deny-list")
        elif sub["propertyNames"] != {"$ref": DENY_LIST_REF}:
            out.append(
                f"evidence schema {path}: propertyNames is not the shared "
                f"deny-list ref {DENY_LIST_REF}"
            )
        if sub.get("additionalProperties") != {"$ref": VALUE_DENY_LIST_REF}:
            out.append(
                f"evidence schema {path}: open value bag is not the shared "
                f"value deny-list ref {VALUE_DENY_LIST_REF}"
            )
    for path, sub in _free_text_fields(schema):
        if {"$ref": VALUE_DENY_LIST_REF} not in (sub.get("allOf") or []):
            out.append(
                f"evidence schema {path}: bounded free-text field carries no "
                f"value deny-list ref {VALUE_DENY_LIST_REF}"
            )
    return out


def _free_text_fields(
    node: Json, path: str = "$", root: Json | None = None, seen: frozenset[str] = frozenset()
) -> list[tuple[str, Json]]:
    """Every subschema bounding a string by `maxLength`, wherever the schema reaches it.

    A `maxLength` subschema is a field a writer fills by hand: the schema bounds
    it because it cannot know what the game or an operator will interpolate.
    The walk mirrors `_open_value_bags` so a field moved into `definitions` and
    $ref'd, or reached through `items`, `additionalProperties`, `allOf`, or
    `oneOf`, is still found; a gate that only read the top-level `properties`
    would report a clean tree for a free-text field in any of the others.
    """
    if not isinstance(node, dict):
        return []
    if root is None:
        root = node
    if isinstance(node.get("$ref"), str):
        ref = node["$ref"]
        if ref in seen:
            return []
        resolved = _resolve_local_ref(node, root)
        if resolved is node:
            return []
        return _free_text_fields(resolved, path, root, seen | {ref})
    out: list[tuple[str, Json]] = []
    if "maxLength" in node:
        out.append((path, node))
    for key in ("properties", "patternProperties"):
        for name, sub in (node.get(key) or {}).items():
            out += _free_text_fields(sub, f"{path}.{key}.{name}", root, seen)
    for name, sub in (node.get("definitions") or {}).items():
        out += _free_text_fields(sub, f"{path}.definitions.{name}", root, seen)
    for i, sub in enumerate(node.get("oneOf") or []):
        out += _free_text_fields(sub, f"{path}.oneOf[{i}]", root, seen)
    for i, sub in enumerate(node.get("allOf") or []):
        out += _free_text_fields(sub, f"{path}.allOf[{i}]", root, seen)
    extra = node.get("additionalProperties")
    if isinstance(extra, dict):
        out += _free_text_fields(extra, f"{path}.additionalProperties", root, seen)
    return out + _free_text_fields(node.get("items"), f"{path}.items", root, seen)


def check_folder_structure() -> list[str]:
    """The documented layout (docs/INDEX.md -> Repo layout) must hold: every directory
    under src/, tests/, tools/, config/ carries a README (empty dirs document their
    purpose), and the planned subfolders exist."""
    out: list[str] = []
    root_dirs = ["docs", "config", "src", "tests", "tools"]
    out.extend(
        f"missing documented directory: {name}/" for name in root_dirs if not (ROOT / name).is_dir()
    )
    for base in ["src", "tests", "tools", "config"]:
        for d in sorted((ROOT / base).rglob("*")):
            if not d.is_dir() or "__pycache__" in d.parts:
                continue
            if not any(x.name == "README.md" for x in d.iterdir()):
                out.append(f"directory without README: {d.relative_to(ROOT)}/")
    planned = [
        ROOT / "config" / "schemas",
        ROOT / "tools" / "fixtures" / "traces",
        ROOT / "tools" / "fixtures" / "regression",
        ROOT / "tools" / "fixtures" / "generators",
        ROOT / "tools" / "surface_inventory",
        ROOT / "tests" / "ServerGuard.Tests",
        ROOT / "tests" / "ServerGuard.MetadataTests",
        ROOT / "tests" / "ServerGuard.Replay",
    ]
    out.extend(
        f"missing planned directory: {d.relative_to(ROOT)}/" for d in planned if not d.is_dir()
    )
    return out


def check_config_example_keys() -> list[str]:
    patterns = _schema_key_patterns()
    example = json.loads(
        (ROOT / "config" / "server-guard.example.json").read_text(encoding="utf-8")
    )
    return [
        f"config key '{path}' not declared in SCHEMAS.md config table"
        for path in _flatten(example)
        if not _matches_schema(path, patterns)
    ]


# depth cap for the config-schema walk; the shipped config schema nests four levels.
MAX_CONFIG_DEPTH = 20


def _config_schema_leaves(schema: Json, prefix: str = "", depth: int = 0) -> list[tuple[str, Json]]:
    """Dotted paths and subschemas for every declared leaf under `properties`.

    patternProperties subtrees (per-detector mode and threshold keys) are skipped: their
    keys come from the registry and the manifest, and are covered by the detector-id and
    manifest checks instead.
    """
    if depth > MAX_CONFIG_DEPTH:
        return []
    out: list[tuple[str, Json]] = []
    for key, sub in schema.get("properties", {}).items():
        path = f"{prefix}.{key}" if prefix else key
        if not isinstance(sub, dict) or sub.get("patternProperties"):
            # A pattern-keyed subtree (modes, thresholds) has no leaves of its own: its
            # keys come from the registry and the manifest, checked elsewhere.
            continue
        if sub.get("properties"):
            out.extend(_config_schema_leaves(sub, path, depth + 1))
        else:
            out.append((path, sub))
    return out


def check_config_contract() -> list[str]:
    """Every schema key is documented, and every key without a default is in the example.

    Two drift directions the other checks do not cover: a schema key nobody documented
    (an operator cannot discover it), and a key added to the schema with no default that
    the example never shows (so every operator hits a required key they were never told
    about). config/README.md states both rules; this enforces them.
    """
    schema = json.loads(
        (ROOT / "config" / "schemas" / "config.v1.schema.json").read_text(encoding="utf-8")
    )
    example = json.loads(
        (ROOT / "config" / "server-guard.example.json").read_text(encoding="utf-8")
    )
    patterns = _schema_key_patterns()
    example_keys = set(_flatten(example))
    out = []
    for path, sub in _config_schema_leaves(schema):
        if not _matches_schema(path, patterns):
            out.append(f"config schema key '{path}' not declared in SCHEMAS.md config table")
        if "default" not in sub and path not in example_keys:
            out.append(f"config schema key '{path}' has no default and is missing from the example")
    return out


def check_required_docs() -> list[str]:
    return [d for d in REQUIRED_DOCS if not (ROOT / d).exists()]


def _makefile_registry(makefile: str, name: str) -> list[str]:
    """The whitespace-separated entries of a `NAME := a b c` Makefile variable."""
    match = re.search(rf"^{name}\s*:?=\s*(.*(?:\n[ \t]+.*)*)", makefile, re.MULTILINE)
    return match.group(1).split() if match else []


def _makefile_target(makefile: str, target: str) -> str:
    """A target and its recipe: every line up to the next `name:` line."""
    match = re.search(rf"^{target}:.*(?:\n(?![\w-]+:).*)*", makefile, re.MULTILINE)
    return match.group(0) if match else ""


def _makefile_runs_self_test(makefile: str, tool: str) -> bool:
    """Whether `make test-tools` runs the given tool's `--self-test`.

    The Makefile's SELF_TESTS list is the registry of tools carrying self-tests, and
    test-tools iterates it, so a tool that is in neither, or in a registry the
    target no longer loops over, is a self-test that silently stopped running in CI.
    """
    return tool in _makefile_registry(makefile, "SELF_TESTS") and (
        "$(SELF_TESTS)" in _makefile_target(makefile, "test-tools")
    )


def _harness_registry_issues(
    makefile: str, harnesses: list[str], self_test_tools: list[str]
) -> list[str]:
    """Whether every shipped harness and self-test is reachable from a make target.

    `make test-tools` names its fuzzers one line at a time and `FUZZERS` is the
    registry `make fuzz FUZZ=` addresses, so the two drift apart silently: a new
    harness added to `tools/` and not to the registry passes `make check` and
    `make ci` without ever running, and a fuzzer dropped from the recipe keeps a
    registry entry that re-runs a name the gate no longer covers. A tool that
    grows a `--self-test` flag lands in the same silence when no target calls it.
    """
    registered = _makefile_registry(makefile, "FUZZERS")
    out = [
        f"tools/fuzz_{name}.py is in no FUZZERS registry, so no target runs it"
        for name in harnesses
        if name not in registered
    ]
    out += [
        f"Makefile: FUZZERS lists '{name}', which has no tools/fuzz_{name}.py"
        for name in registered
        if name not in harnesses
    ]
    run_order = re.findall(r"tools/fuzz_(\w+)\.py", _makefile_target(makefile, "test-tools"))
    if run_order != registered:
        out.append(
            "Makefile: `make test-tools` runs "
            f"[{' '.join(run_order) or 'nothing'}] "
            f"against a FUZZERS registry of [{' '.join(registered)}]"
        )
    exercise = _makefile_target(makefile, "exercise")
    out += [
        f"tools/{name}.py exposes --self-test but no target runs it"
        for name in self_test_tools
        if not _makefile_runs_self_test(makefile, name)
        and f"tools/{name}.py --self-test" not in exercise
    ]
    return out


def check_test_harness_registry() -> list[str]:
    """The Makefile's test registries must cover every harness and self-test on disk.

    Read from the tree rather than from a list, so a harness added to `tools/` is
    covered the moment it lands. `fuzz_common.py` is the shared harness library
    the others import, not a runnable harness, so it is not a registry entry.
    """
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    tools = ROOT / "tools"
    harnesses = sorted(
        p.stem.removeprefix("fuzz_")
        for p in tools.glob("fuzz_*.py")
        if p.stem not in FUZZ_SHARED_MODULES
    )
    self_test_tools = sorted(
        p.stem for p in tools.glob("*.py") if '"--self-test"' in p.read_text(encoding="utf-8")
    )
    return _harness_registry_issues(makefile, harnesses, self_test_tools)


# Distribution name -> import name, for a dependency whose import name is not the
# normalized distribution name. A contributor adding one records it here: nothing in
# the tree names the distribution otherwise, so without the entry a used dependency
# reads as unused and the fix would be to delete live code.
IMPORT_NAME_ALIASES = {"pyyaml": "yaml"}

# Stub-only distributions carry type information for a runtime package and are never
# imported by name; mypy resolves them from the normalized distribution name. They
# are exempt from the import side of the check for that reason.
STUB_DIST_PREFIX = "types-"
STUB_DIST_SUFFIX = "-stubs"


def _dist_name(requirement: str) -> str:
    """The distribution name of a PEP 508 requirement, lowercased.

    Everything from the first version specifier, extras marker, or URL on is
    dropped, so `PyYAML>=6,<7` and `black==26.5.1` yield the bare name.
    """
    return re.split(r"[\s\[<>=!~;,@()]", requirement, maxsplit=1)[0].strip().lower()


def _normalized(name: str) -> str:
    """PEP 503 name normalization: case and separator insensitive."""
    return re.sub(r"[-_.]+", "_", name).lower()


def _is_stub_dist(dist: str) -> bool:
    return dist.startswith(STUB_DIST_PREFIX) or dist.endswith(STUB_DIST_SUFFIX)


def _shipped_python() -> list[pathlib.Path]:
    """Every Python file this repo ships, the way the other tree reads do it."""
    return sorted(
        p
        for p in ROOT.rglob("*.py")
        if not (SKIP_DIRS & set(p.parts)) and "__pycache__" not in p.parts
    )


def _imported_top_level(paths: list[pathlib.Path]) -> tuple[set[str], list[str]]:
    """Top-level names bound by an import, and the files that could not be parsed.

    Parsed with `ast` rather than a text scan, so a module named in a docstring or
    a comment is not counted as a dependency's user. A relative `from . import x`
    binds a local module and is skipped, like a package's own submodules.
    """
    names: set[str] = set()
    unreadable: list[str] = []
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            unreadable.append(f"{path.relative_to(ROOT)}: {type(exc).__name__}: {exc}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                names.add(node.module.split(".")[0])
    return names, unreadable


def _dependency_issues(groups: dict[str, list[str]], imports: set[str], makefile: str) -> list[str]:
    """Both directions of the declared-versus-used dependency contract.

    A distribution nothing imports and nothing runs is attack surface the project
    pays install time for; an import no distribution provides is code that works
    only because something else happens to be installed. Neither is visible from
    the tree alone, and neither is what `uv sync --frozen` checks: the lock
    faithfully installs what the manifest declares, including a declaration the
    code stopped needing.

    The Makefile is the usage site for a distribution run as a console script
    (black, ruff, mypy), which is what the import set cannot see. It is matched
    by name anywhere in the text, so a dependency named in a comment counts as
    used: the cost of that miss is a stale declaration surviving one more
    release, against the cost of failing the gate over a run that is still there.
    """
    out: list[str] = []
    provides: set[str] = set()
    for group, dists in groups.items():
        for dist in dists:
            name = IMPORT_NAME_ALIASES.get(dist, _normalized(dist))
            provides.add(name)
            if name in imports or re.search(rf"\b{re.escape(name)}\b", makefile):
                continue
            if _is_stub_dist(dist):
                continue
            out.append(
                f"pyproject.toml: {group} dependency '{dist}' is neither imported by "
                "shipped Python nor run by a make target, so remove it or use it"
            )
    for name in sorted(imports):
        if name in provides:
            continue
        out.append(
            f"shipped Python imports '{name}', which no pyproject.toml distribution "
            "provides; declare it or stop importing it"
        )
    return out


def check_dependency_declarations() -> list[str]:
    """pyproject.toml must declare exactly the third-party code the tree uses."""
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject.get("project", {})
    groups = {
        "runtime": [_dist_name(r) for r in project.get("dependencies", [])],
        **{
            f"dev group '{group}'": [_dist_name(r) for r in dists]
            for group, dists in pyproject.get("dependency-groups", {}).items()
        },
    }
    py_files = _shipped_python()
    imports, unreadable = _imported_top_level(py_files)
    third_party = imports - set(sys.stdlib_module_names) - {p.stem for p in py_files}
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    return _dependency_issues(groups, third_party, makefile) + unreadable


def check_backup_runbook() -> list[str]:
    """The evidence store is the one state an operator cannot regenerate, so the
    archive tooling and the recovery contract must stay in place together: a
    Makefile target with no runbook, or a runbook citing a target that no longer
    exists, is a backup nobody can run. The scheduled run and the restore drill
    are required alongside the archive tools, because an archive nobody drills is
    a hypothesis and a scheduled run nobody checks is a silent miss."""
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    ops = (ROOT / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")
    out = [
        f"Makefile: missing the '{target}' target"
        for target in (
            "export-evidence",
            "verify-archive",
            "backup",
            "backup-status",
            "drill-restore",
        )
        if f"\n{target}:" not in makefile
    ]
    out.extend(
        f"Makefile: test-tools does not run the {tool} self-test"
        for tool in ("evidence_export", "restore_drill", "backup_status")
        if not _makefile_runs_self_test(makefile, tool)
    )
    if "### Restore drill" not in ops:
        out.append("docs/OPERATIONS.md: no restore drill in the backup and restore runbook")
    out.extend(
        f"docs/OPERATIONS.md: backup runbook does not mention {marker!r}"
        for marker in (
            "| RPO | RTO |",
            "make export-evidence",
            "make verify-archive",
            "make backup",
            "make backup-status",
            "make drill-restore",
        )
        if marker not in ops
    )
    return out


def _toolchain_pin_issues(pyproject: str, workflow: str, makefile: str) -> list[str]:
    """Whether the build toolchain is pinned once, in one place, and honored.

    The uv release and the two environment values that decide what a gate prints
    are each named twice: `required-version` in pyproject against the release
    setup-uv installs, and the Makefile exports against the workflow env. Two
    copies drift apart silently, and the drift shows up as a local gate and a CI
    gate of one commit disagreeing, which is exactly what a pinned toolchain is
    supposed to prevent. The lockfile is the third: `--locked` is what makes the
    lock binding, since `--frozen` installs a lock that no longer matches
    pyproject.toml without a word and a bare `uv run` re-resolves it.
    """
    out: list[str] = []
    required = str(
        tomllib.loads(pyproject).get("tool", {}).get("uv", {}).get("required-version", "")
    )
    match = re.fullmatch(r"==(\d+\.\d+\.\d+)", required)
    if not match:
        return [
            (
                "pyproject.toml: [tool.uv] required-version is "
                f"{required or 'unset'}, not an exact ==MAJOR.MINOR.PATCH release pin"
            )
        ]
    pinned = match.group(1)
    installed = re.search(r"^\s*version:\s*\"?(\d+\.\d+\.\d+)\"?\s*$", workflow, re.MULTILINE)
    if installed is None:
        out.append("ci.yml: astral-sh/setup-uv names no uv release to install")
    elif installed.group(1) != pinned:
        out.append(
            f"ci.yml: setup-uv installs uv {installed.group(1)}, "
            f"pyproject.toml requires {pinned}"
        )
    for action in re.findall(r"^\s*-?\s*uses:\s*(\S+)", workflow, re.MULTILINE):
        ref = action.partition("@")[2]
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            out.append(f"ci.yml: {action} is a mutable ref, not a pinned commit SHA")
    out += [
        f"ci.yml: runs-on {runner} is a moving tag, so the ambient toolchain can drift"
        for runner in re.findall(r"^\s*runs-on:\s*(\S+)", workflow, re.MULTILINE)
        if runner.endswith("-latest")
    ]
    if not re.search(r"^UV\s*:?=\s*uv run --locked\s*$", makefile, re.MULTILINE):
        out.append(
            "Makefile: UV is not `uv run --locked`, so a gate runs against a uv.lock that "
            "no longer matches pyproject.toml"
        )
    if not re.search(r"^\s*uv sync --locked\s*$", makefile, re.MULTILINE):
        out.append("Makefile: `make setup` does not `uv sync --locked`, so a stale lock installs")
    for var in ("TZ", "PYTHONHASHSEED"):
        local = re.search(rf"^export {var}\s*:=\s*(\S+)\s*$", makefile, re.MULTILINE)
        ci = re.search(rf"^\s*{var}:\s*\"?(\S+?)\"?\s*$", workflow, re.MULTILINE)
        if local is None:
            out.append(f"Makefile: no `export {var} := ...`, so a local gate is unpinned")
        elif ci is not None and ci.group(1) != local.group(1):
            out.append(f"Makefile exports {var}={local.group(1)}, ci.yml sets {ci.group(1)}")
    return out


def check_toolchain_pins() -> list[str]:
    """The toolchain that resolves the lockfile is named in exactly one place."""
    return _toolchain_pin_issues(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"),
        (ROOT / "Makefile").read_text(encoding="utf-8"),
    )


def _run_check(name: str, check: Callable[[], list[str]]) -> tuple[str, list[str]]:
    """Run one check, reporting an unexpected raise as that check's failure.

    The checks read hand-edited YAML, JSON, and markdown, so a malformed one can
    raise before it can report. Without this the first such check aborts the run
    and the remaining checks never execute, turning a single broken input into a
    gate that reports nothing.
    """
    try:
        return name, check()
    except Exception as exc:
        return name, [f"{type(exc).__name__}: {exc} (check aborted; its input may be malformed)"]


def _harness_registry_self_test() -> list[str]:
    """The registry check must fire on each drift it exists to catch.

    A gate that only ever sees the clean tree proves nothing, so each case below
    breaks one way a registry can drift from the tree and names the issue the
    check is expected to raise for it.
    """
    clean = (
        "FUZZERS := a b\n"
        "SELF_TESTS := t\n"
        "test-tools: guard-python\n"
        "\t@set -e; for tool in $(SELF_TESTS); do \\\n"
        "\t  $(UV) python tools/$$tool.py --self-test; \\\n"
        "\tdone\n"
        "\t$(UV) python tools/fuzz_a.py\n"
        "\t$(UV) python tools/fuzz_b.py\n"
        "\n"
        "exercise: guard-python\n"
        "\t$(UV) python tools/replay_contract_check.py --self-test\n"
    )
    errs: list[str] = []
    # The passing case: both harnesses are registered and run in registry order,
    # and both self-tests are reached, one through the loop and one via exercise.
    if issues := _harness_registry_issues(clean, ["a", "b"], ["t", "replay_contract_check"]):
        errs.append(f"self-test: a consistent registry was reported broken: {issues}")
    # Each case is a label, the makefile it runs against, the harnesses and
    # self-test tools it claims the tree holds, and a fragment the raised issue
    # must carry.
    cases: tuple[tuple[str, str, list[str], list[str], str], ...] = (
        ("a harness in no FUZZERS registry", clean, ["a", "b", "c"], [], "fuzz_c.py"),
        (
            "a FUZZERS entry with no harness",
            clean.replace("a b\n", "a b c\n", 1),
            ["a", "b"],
            [],
            "c",
        ),
        (
            "a fuzzer run out of registry order",
            clean.replace(
                "fuzz_a.py\n\t$(UV) python tools/fuzz_b.py",
                "fuzz_b.py\n\t$(UV) python tools/fuzz_a.py",
            ),
            ["a", "b"],
            [],
            "registry of [a b]",
        ),
        (
            "a --self-test no target runs",
            clean,
            ["a", "b"],
            ["t", "replay_contract_check", "orphan"],
            "orphan",
        ),
    )
    for label, makefile, harnesses, self_tests, expected in cases:
        issues = _harness_registry_issues(makefile, harnesses, self_tests)
        if not any(expected in issue for issue in issues):
            errs.append(f"self-test: {label} went unreported, got {issues}")
    if live := check_test_harness_registry():
        errs.append(f"self-test: this repository's own registry is inconsistent: {live}")
    errs += _action_pin_self_test()
    return errs


_USES_LINE = re.compile(
    r"^\s*(?:-\s+)?uses:\s*(?P<action>[^\s@]+)(?:@(?P<ref>\S*))?\s*(?:#\s*(?P<label>.*))?$"
)
_SHA = re.compile(r"^[0-9a-f]{40}$")
_RELEASE = re.compile(r"^v\d+\.\d+\.\d+$")
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))


def _action_pin_issues(workflow: str, rel: str) -> list[str]:
    """Whether every third-party action a workflow runs is a pinned commit.

    The CI dependency surface is these `uses` lines and nothing else, and a tag or
    branch resolves to whatever the publisher's HEAD is at run time, so an unpinned
    ref lets a new commit execute in the gate. Dependabot rewrites the SHA on a
    bump and leaves the trailing version comment alone, so the comment drifts out
    of date on every update: a missing or malformed one means the workflow no longer
    records which release a commit is, which is the only readable mapping from a
    green gate back to a dependency version.
    """
    out: list[str] = []
    for number, line in enumerate(workflow.splitlines(), 1):
        match = _USES_LINE.match(line)
        if match is None or match["action"].startswith("."):
            continue
        action, ref, label = match["action"], match["ref"] or "", match["label"] or ""
        where = f"{rel}:{number} ({action})"
        if not _SHA.match(ref):
            out.append(f"{where}: action ref '{ref or '<none>'}' is not a pinned commit SHA")
        if not _RELEASE.match(label):
            out.append(f"{where}: no trailing '# vMAJOR.MINOR.PATCH' release comment")
    return out


def check_action_pins() -> list[str]:
    """Every workflow action is SHA-pinned and names the release it pins."""
    return [
        issue
        for path in WORKFLOWS
        for issue in _action_pin_issues(path.read_text("utf-8"), path.name)
    ]


def _action_pin_self_test() -> list[str]:
    """The pin check must fire on each way an action can be unpinned or unlabelled.

    A gate that only ever sees the clean tree proves nothing, so each case below
    breaks one property the check enforces and names the issue it must raise.
    """
    sha = "a" * 40
    clean = f"      - uses: owner/action@{sha} # v1.2.3\n"
    errs: list[str] = []
    if issues := _action_pin_issues(clean, "ci.yml"):
        errs.append(f"self-test: a pinned, labelled action was reported broken: {issues}")
    cases: tuple[tuple[str, str, str], ...] = (
        ("a mutable tag ref", "      - uses: owner/action@v1.2.3\n", "not a pinned"),
        ("a branch ref", "      - uses: owner/action@main\n", "not a pinned"),
        ("a ref with no version at all", "      - uses: owner/action\n", "<none>"),
        ("a missing release comment", f"      - uses: owner/action@{sha}\n", "no trailing"),
        (
            "a mangled release comment",
            f"      - uses: owner/action@{sha} # bump me\n",
            "no trailing",
        ),
    )
    for label, workflow, expected in cases:
        issues = _action_pin_issues(workflow, "ci.yml")
        if not any(expected in issue for issue in issues):
            errs.append(f"self-test: {label} went unreported, got {issues}")
    if local := _action_pin_issues("      - uses: ./.github/actions/local\n", "ci.yml"):
        errs.append(f"self-test: a local action was reported unpinned: {local}")
    if live := check_action_pins():
        errs.append(f"self-test: this repository's own workflows are unpinned: {live}")
    return errs


def _dependency_self_test() -> list[str]:
    """The dependency check must fire on each drift it exists to catch.

    Same shape as the registry self-test: every case below declares or imports
    something the tree does not need, or leaves something the tree needs
    undeclared, and names the issue the check is expected to raise.
    """
    makefile = "lint: guard-python\n\t$(UV) black --check .\n\t$(UV) ruff check .\n"
    errs: list[str] = []
    if issues := _dependency_issues(
        {"runtime": ["pyyaml"], "dev group 'dev'": ["black", "types-pyyaml"]},
        {"yaml"},
        makefile,
    ):
        errs.append(f"self-test: a used dependency set was reported unused: {issues}")
    cases: tuple[tuple[dict[str, list[str]], set[str], str], ...] = (
        # A declaration nothing imports and nothing runs: leftover install surface.
        ({"runtime": ["pyyaml", "requests"]}, {"yaml"}, "'requests' is neither imported"),
        # An import nothing declares: green on a developer's machine, red in CI.
        ({"runtime": []}, {"yaml"}, "imports 'yaml'"),
        # A distribution invoked as a console script, not imported: still in use.
        ({"dev group 'dev'": ["ruff"]}, set(), ""),
    )
    for groups, imports, expected in cases:
        issues = _dependency_issues(groups, imports, makefile)
        if expected and not any(expected in issue for issue in issues):
            errs.append(f"self-test: {expected!r} went unreported, got {issues}")
        if not expected and issues:
            errs.append(f"self-test: a script-run dependency was reported broken: {issues}")
    if live := check_dependency_declarations():
        errs.append(f"self-test: this repository's own dependencies are inconsistent: {live}")
    return errs


_PINNED_PYPROJECT = '[tool.uv]\nrequired-version = "==0.12.13"\n'
_PINNED_WORKFLOW = (
    "jobs:\n"
    "  gate:\n"
    "    runs-on: ubuntu-24.04\n"
    "    env:\n"
    "      TZ: UTC\n"
    '      PYTHONHASHSEED: "0"\n'
    "    steps:\n"
    "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
    "      - uses: astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d # v10.0.1\n"
    "        with:\n"
    '          version: "0.12.13"\n'
)
_PINNED_MAKEFILE = (
    "UV := uv run --locked\n\nsetup:\n\tuv sync --locked\n\n"
    "export TZ := UTC\nexport PYTHONHASHSEED := 0\n"
)


def _toolchain_pin_self_test() -> list[str]:
    """The pin check must fire on each drift it exists to catch.

    A gate that has only ever seen the pinned tree proves nothing, so each case
    breaks one pin and names the issue the check has to raise for it.
    """
    errs: list[str] = []
    if issues := _toolchain_pin_issues(_PINNED_PYPROJECT, _PINNED_WORKFLOW, _PINNED_MAKEFILE):
        errs.append(f"self-test: a consistent toolchain pin was reported broken: {issues}")
    cases: tuple[tuple[str, str, str, str, str], ...] = (
        (
            "CI installs a uv release pyproject does not require",
            _PINNED_PYPROJECT,
            _PINNED_WORKFLOW.replace('"0.12.13"', '"0.12.99"'),
            _PINNED_MAKEFILE,
            "ci.yml: setup-uv installs uv 0.12.99",
        ),
        (
            "a required-version that is not an exact release pin",
            '[tool.uv]\nrequired-version = ">=0.12"\n',
            _PINNED_WORKFLOW,
            _PINNED_MAKEFILE,
            "not an exact ==MAJOR.MINOR.PATCH",
        ),
        (
            "an action on a mutable tag",
            _PINNED_PYPROJECT,
            _PINNED_WORKFLOW.replace("actions/checkout@3d3c42e", "actions/checkout@v7"),
            _PINNED_MAKEFILE,
            "mutable ref",
        ),
        (
            "a moving runner image",
            _PINNED_PYPROJECT,
            _PINNED_WORKFLOW.replace("ubuntu-24.04", "ubuntu-latest"),
            _PINNED_MAKEFILE,
            "moving tag",
        ),
        (
            "a gate that runs against a lock that can drift from pyproject",
            _PINNED_PYPROJECT,
            _PINNED_WORKFLOW,
            _PINNED_MAKEFILE.replace("uv run --locked", "uv run --frozen"),
            "no longer matches pyproject.toml",
        ),
        (
            "a setup that installs a stale lock",
            _PINNED_PYPROJECT,
            _PINNED_WORKFLOW,
            _PINNED_MAKEFILE.replace("uv sync --locked", "uv sync --frozen"),
            "a stale lock installs",
        ),
        (
            "a zone the local gate and CI disagree on",
            _PINNED_PYPROJECT,
            _PINNED_WORKFLOW.replace("TZ: UTC", "TZ: Europe/Berlin"),
            _PINNED_MAKEFILE,
            "Makefile exports TZ=UTC, ci.yml sets Europe/Berlin",
        ),
    )
    for label, pyproject, workflow, makefile, expected in cases:
        issues = _toolchain_pin_issues(pyproject, workflow, makefile)
        if not any(expected in issue for issue in issues):
            errs.append(f"self-test: {label} went unreported, got {issues}")
    if live := check_toolchain_pins():
        errs.append(f"self-test: this repository's own toolchain pins are inconsistent: {live}")
    return errs


def main() -> int:
    report_text.safe_report_streams()
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--self-test", action="store_true", help="run the docs gate self-tests and exit"
    )
    args = ap.parse_args()

    if args.self_test:
        errs = [
            *self_test(),
            *_harness_registry_self_test(),
            *_dependency_self_test(),
            *_toolchain_pin_self_test(),
        ]
        print(f"doccheck self-test: {len(errs)} issue(s)")
        for err in errs:
            print("  " + err, file=sys.stderr)
        return 1 if errs else 0

    checks = [
        ("em dashes", check_em_dashes),
        ("links", check_links),
        ("TODO checkboxes", check_todo_format),
        ("release version", check_release_version),
        ("changelog format", check_changelog_format),
        ("upgrade guide", check_upgrade_guide),
        ("detector spec", check_spec),
        ("registry sync", check_registry_sync),
        ("detector registry coverage", check_detector_ids),
        ("config example vs schema", check_config_example_keys),
        ("config schema vs docs", check_config_contract),
        ("config JSON schemas", check_config_schemas),
        ("docs JSON examples", check_docs_json_examples),
        ("evidence personal data", check_evidence_personal_data),
        ("evidence sample chain", check_evidence_sample_chain),
        ("replay contract", check_replay_contract),
        ("folder structure", check_folder_structure),
        ("backup runbook", check_backup_runbook),
        ("test harness registry", check_test_harness_registry),
        ("CI action pins", check_action_pins),
        ("dependency declarations", check_dependency_declarations),
        ("toolchain pins", check_toolchain_pins),
        ("required docs", check_required_docs),
    ]
    failures = dict(_run_check(name, check) for name, check in checks)
    total = sum(len(v) for v in failures.values())
    print(
        f"doccheck: {total} issue(s) across {len(MD_FILES)} markdown "
        f"and {len(SOURCE_FILES)} source files"
    )
    for name, items in failures.items():
        if items:
            print(f"\n[{name}]", file=sys.stderr)
            for item in items[:MAX_REPORTED]:
                print("  " + item, file=sys.stderr)
            if len(items) > MAX_REPORTED:
                print(f"  ... and {len(items) - MAX_REPORTED} more", file=sys.stderr)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
