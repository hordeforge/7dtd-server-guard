"""The exit-code and stream contract every tool in tools/ shares, as one harness.

A tool's `main()` is the only surface a caller sees. A scheduler or a deployment
script branches on its exit code, and a redirected run reads the verdict on
stdout with the detail on stderr, so a usage error that printed its help to
stdout would be captured where a verdict belongs. Every tool documents that
contract and states it in its own self-test cases; the assertion behind those
cases is this one, so the three cannot drift apart.
"""

from __future__ import annotations

import contextlib
import io
import sys
from collections.abc import Callable, Iterable

# One case: what the run is, the argv it is given, and the exit code it must return.
Case = tuple[str, list[str], int]


def main_cases(
    tool: str, main: Callable[[], int], cases: Iterable[Case], usage_error: int
) -> list[str]:
    """Run each case's `main()` and report every way it missed the contract.

    A verdict run (`expected != usage_error`) has to write its verdict to stdout,
    whatever the verdict is: a redirected run records the exit code alone
    otherwise, and "1" says no more than the run did. A usage error has to write
    to stderr and leave stdout empty.
    """
    errs: list[str] = []
    saved = sys.argv
    for label, argv, expected in cases:
        out, err = io.StringIO(), io.StringIO()
        sys.argv = [tool, *argv]
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main()
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
