"""Exit nonzero unless the running interpreter is exactly the one in .python-version.

The pinned version in .python-version is the single source of truth for the Python
toolchain: uv installs exactly it (uv reads the same file), and local builds enforce
it before any tool runs, so a host on a different patch fails here with a clear
message instead of producing a gate result nobody else can reproduce.
"""

from __future__ import annotations

import pathlib
import sys

import report_text

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSION_FILE = ".python-version"
# The pin must carry major, minor, and patch: a partial pin lets the patch float,
# so two runs of the same source can execute different interpreters.
PIN_PARTS = 3


def main() -> int:
    report_text.safe_report_streams()
    path = ROOT.joinpath(VERSION_FILE)
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        print(f"guard-python: cannot read {VERSION_FILE}: {exc}", file=sys.stderr)
        return 1
    parts = raw.split(".")
    if len(parts) != PIN_PARTS or not all(p.isdigit() for p in parts):
        print(f"guard-python: {VERSION_FILE} must look like '3.12.4', got {raw!r}", file=sys.stderr)
        return 1
    want = tuple(int(p) for p in parts)
    have = sys.version_info[:PIN_PARTS]
    if have != want:
        print(
            f"guard-python: need Python {'.'.join(str(x) for x in want)} (per {VERSION_FILE}), "
            f"found {'.'.join(str(x) for x in have)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
