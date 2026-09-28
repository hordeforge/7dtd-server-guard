"""Shared machinery for the exit-code contract the tool self-tests in tools/ pin.

Each tool documents three codes: 0 the verdict holds, 1 it does not, and 2 for a
usage error. The usage error writes its help or its message to stderr and leaves
stdout empty, so a redirected run cannot capture a help dump where a verdict
belongs. Every tool's self-test asserts the same three things, and the copies
drifted apart as tools were added, so the assertions live here once.
"""

from __future__ import annotations

import contextlib
import io
import sys
from collections.abc import Callable, Sequence


def main_contract_errors(
    cases: Sequence[tuple[str, list[str], int]],
    *,
    script: str,
    run: Callable[[], int],
    usage_error: int,
) -> list[str]:
    """Run `run` once per (label, argv, expected exit code) case and report the
    mismatches.

    `script` is the name the tool sees in `sys.argv[0]`, which is what its own
    help and error text print. `usage_error` is the tool's own constant for the
    code its `main` returns when it refuses its arguments.
    """
    errs: list[str] = []
    saved = sys.argv
    for label, argv, expected in cases:
        out, err = io.StringIO(), io.StringIO()
        sys.argv = [script, *argv]
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = run()
        except SystemExit as exc:  # argparse rejects a bad argument by exiting
            code = int(exc.code or 0)
        finally:
            sys.argv = saved
        if code != expected:
            errs.append(f"{label}: exit {code}, expected {expected}")
        if expected != usage_error:
            if not out.getvalue():
                errs.append(f"{label}: a verdict run wrote nothing to stdout")
            continue
        if out.getvalue():
            errs.append(f"{label}: usage error wrote to stdout: {out.getvalue()!r}")
        if not err.getvalue():
            errs.append(f"{label}: usage error wrote nothing to stderr")
    return errs
