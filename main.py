"""PQ-Patch command line: detect, plan, patch and verify one Python file, then print a report.

    python main.py samples/sample_input.py
    python main.py app/signer.py --project-root app --ask --out reports

Stdout carries one JSON report row per finding and then, as its LAST line, the run status:
``ok``, ``invalid_output``, ``refused`` or ``error`` (the status of the last model call). Everything
else (progress, counts, reasons) goes to stderr. Exit code: 0 for ``ok``, 1 for any other status,
2 when the input is rejected (empty, over 256 KiB, not .py, or not valid Python) before any model call.

The input file is never modified. Files are written only with ``--out DIR``.

Human gate: by default the plan is approved automatically so the command can run unattended (the
course checker runs it that way), and a failed verification is escalated rather than retried, because
retrying is a person's decision. ``--ask`` puts a person at every checkpoint in the terminal, and the
Streamlit UI (``streamlit run app.py``) always does.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Callable, Optional, Sequence

from pq_patch.autorun import STATUS_OK, run_session
from pq_patch.llm_client import StructuredLLM
from pq_patch.orchestrator import InputRejected, Session, read_input
from pq_patch.report import to_jsonl, write_report


def _err(*parts: object) -> None:
    print(*parts, file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="main.py", description="Find RSA/ECDSA signing in a Python file and propose ML-DSA replacements.")
    ap.add_argument("file", help="a .py file (non-empty, at most 256 KiB, valid Python)")
    ap.add_argument("--project-root", type=Path, help="run the project's own tests against each patch in a temp copy")
    ap.add_argument("--out", type=Path, help="write report.json, report.csv and one .diff per patch into this folder")
    ap.add_argument("--ask", action="store_true", help="ask in the terminal at every checkpoint instead of approving automatically")
    ap.add_argument("--cache", action="store_true", help="reuse stored model replies (sets LLM_CACHE=1); a repeated run then costs no tokens")
    return ap


def main(argv: Optional[Sequence[str]] = None, *, llm: Optional[StructuredLLM] = None, read: Callable[[str], str] = input) -> int:
    for stream in (sys.stdout, sys.stderr):  # model text can hold characters a Windows console cannot show
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    if args.cache:
        os.environ["LLM_CACHE"] = "1"

    try:
        source = read_input(args.file)
    except InputRejected as e:
        _err(f"input rejected: {e}")
        return 2

    model = llm or StructuredLLM()
    session = Session(args.file, source, llm=model, project_root=args.project_root)
    _err(f"{len(session.records)} finding(s) in {args.file}")
    status = run_session(session, ask=args.ask, read=read)

    rows = session.report_rows()
    if args.out:
        for path in write_report(rows, args.out):
            _err(f"wrote {path}")
    print(to_jsonl(rows))
    _err(f"model calls: {session.model_calls}, cached replies: {session.cached_replies}")
    print(status)  # the last line of stdout is always the run status
    return 0 if status == STATUS_OK else 1


if __name__ == "__main__":
    raise SystemExit(main())
