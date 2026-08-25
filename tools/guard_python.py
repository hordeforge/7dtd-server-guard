#!/usr/bin/env python3
"""Exit nonzero unless the running interpreter meets the floor in .python-version.

The pinned minor in .python-version is the single source of truth for the Python
toolchain: CI installs exactly it (actions/setup-python reads the same file), and
local builds enforce it as a floor before any tool runs, so a too-old host fails
here with a clear message instead of inside a tool.
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSION_FILE = ".python-version"


def main() -> int:
    raw = ROOT.joinpath(VERSION_FILE).read_text(encoding="utf-8").strip()
    parts = raw.split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts):
        print(f"guard-python: {VERSION_FILE} must look like '3.12', got {raw!r}", file=sys.stderr)
        return 1
    floor = tuple(int(p) for p in parts[:2])
    have = sys.version_info[:2]
    if have < floor:
        want = ".".join(str(x) for x in floor)
        found = ".".join(str(x) for x in have)
        print(f"guard-python: need Python {want}+ (per {VERSION_FILE}), found {found}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
