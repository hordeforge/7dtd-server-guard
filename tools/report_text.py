"""Put the report streams in a state where the text a tool read can be written back.

Every tool in tools/ reports findings that quote the text they read: a chainPrev
from an evidence record, an archive member name, a file name out of a directory
listing. Two legal inputs make that text unwritable on a strict stream. A JSON
string may carry an unpaired UTF-16 half (`"\\udcff"` is well-formed JSON and
Python's parser returns it as a str), and a file name on Linux is arbitrary
bytes that pathlib hands back through surrogateescape. stdout encodes with
errors="strict", so one such character raises UnicodeEncodeError and ends the run
with a traceback where the finding belongs: a restore drill that copied and
verified every record still reports nothing, because the summary line naming the
oldest and newest eventId could not be written.

`backslashreplace` is the policy a report wants. What the stream can encode is
written unchanged; what it cannot becomes the same `\\udcff` spelling the JSON
escape already used, so the finding survives and the exit code still means
something. Naming the encoding as well keeps the output UTF-8 on a host whose
locale would otherwise pick something else, which is the convention every read
and write in this tree already follows.

Usage:
  uv run python tools/report_text.py --self-test

Exit codes: 0 the self-test passed, 1 it did not, 2 usage error.
"""

from __future__ import annotations

import argparse
import io
import sys
from collections.abc import Iterable
from typing import TextIO

# What a report stream is put into: the encoding the rest of the tree reads and
# writes, and the error handler that renders what cannot be encoded instead of
# raising on it.
REPORT_ENCODING = "utf-8"
REPORT_ERRORS = "backslashreplace"

# A JSON string holding an unpaired UTF-16 half, and a file name read through
# surrogateescape, are the two inputs that break a strict stream. Both are legal
# to receive, so both belong in the corpus that proves the policy.
LONE_SURROGATE = "\udcff"
SURROGATEESCAPE_NAME = "evidence-2026-07-21-000000-\udcff.jsonl"


def safe_report_streams(streams: Iterable[TextIO] | None = None) -> None:
    """Reconfigure the report streams to REPORT_ENCODING with REPORT_ERRORS.

    A stream with no `reconfigure` is left alone: an in-memory `io.StringIO` a
    self-test redirected stdout into has no encoder to change, and its text is
    never encoded on the way out.
    """
    for stream in (sys.stdout, sys.stderr) if streams is None else streams:
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        reconfigure(encoding=REPORT_ENCODING, errors=REPORT_ERRORS)


def _self_test() -> list[str]:
    """A strict stream reports an unencodable character instead of raising.

    The case is a real output stream, not a mock: the policy is a property of the
    stream's encoder, and an in-memory buffer that accepts any str would pass
    with no policy at all.
    """
    errs: list[str] = []
    # What the escape spelling is, spelled out from the constant rather than from
    # the encoder under test: the assertion is that both texts arrive in that form.
    escaped = f"\\u{ord(LONE_SURROGATE):04x}"
    escaped_name = SURROGATEESCAPE_NAME.replace(LONE_SURROGATE, escaped)
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding=REPORT_ENCODING, errors="strict")
    try:
        safe_report_streams([stream])
        try:
            print(f"oldest {LONE_SURROGATE}", file=stream)
            print(SURROGATEESCAPE_NAME, file=stream)
        except UnicodeEncodeError as exc:
            errs.append(f"a strict stream raised on unencodable report text: {exc}")
        else:
            stream.flush()
            written = raw.getvalue().decode(REPORT_ENCODING, "replace")
            if written != f"oldest {escaped}\n{escaped_name}\n":
                errs.append(f"report text was not written as expected: {written!r}")
    finally:
        stream.detach()

    # A redirected stream has no encoder to reconfigure and must not raise.
    captured = io.StringIO()
    try:
        safe_report_streams([captured])
    except Exception as exc:
        errs.append(f"an in-memory capture stream was refused: {type(exc).__name__}: {exc}")
    else:
        captured.write("ok")
        if captured.getvalue() != "ok":
            errs.append("an in-memory capture stream did not keep accepting text")

    # The real streams, which is the call every tool makes at the top of main().
    safe_report_streams()
    live: tuple[tuple[str, TextIO], ...] = (("stdout", sys.stdout), ("stderr", sys.stderr))
    for name, report in live:
        if not hasattr(report, "reconfigure"):
            continue
        if report.encoding.lower().replace("-", "") != REPORT_ENCODING.replace("-", ""):
            errs.append(f"{name} is {report.encoding!r} after the report policy was applied")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--self-test", action="store_true", help="run the report stream self-tests and exit"
    )
    args = ap.parse_args()
    if not args.self_test:
        ap.print_help(sys.stderr)
        return 2
    errs = _self_test()
    print(f"report-text self-test: {len(errs)} issue(s)")
    for error in errs:
        print("  " + error, file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
