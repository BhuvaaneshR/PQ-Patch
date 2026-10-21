"""Report and export: turn finished findings into JSON, CSV and .diff files (M8).

Pure formatting. Nothing here decides anything; every field comes from a ``ReportRow`` that the schema
already validated. Two things are done on purpose:

* CSV cells that start with ``= + - @`` (or a tab/CR) get a leading apostrophe. Notes and the patch text
  contain model-influenced text, and a spreadsheet would otherwise run it as a formula.
* Files are written only to a folder the caller names, never next to the input file, and file names are
  built from the row (a sanitised base name and line number), never from model text.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional, Sequence, Union

from .orchestrator import Session, State
from .schemas import FindingStatus, ReportRow

COLUMNS = (
    "file",
    "line",
    "original_call",
    "target_algorithm",
    "proposed_patch",
    "verification_result",
    "attempts",
    "status",
    "notes",
)
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def row_dict(row: ReportRow) -> dict:
    """The nine fields as plain JSON-able values, in a fixed order."""
    data = row.model_dump(mode="json")
    return {k: data[k] for k in COLUMNS}


def to_json(rows: Sequence[ReportRow], *, indent: Optional[int] = 2) -> str:
    return json.dumps([row_dict(r) for r in rows], indent=indent, ensure_ascii=False)


def to_jsonl(rows: Sequence[ReportRow]) -> str:
    """One compact JSON object per line (what ``main.py`` prints)."""
    return "\n".join(json.dumps(row_dict(r), ensure_ascii=False) for r in rows)


def _safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def to_csv(rows: Sequence[ReportRow]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(COLUMNS)
    for row in rows:
        data = row_dict(row)
        writer.writerow([_safe_cell(data[c]) for c in COLUMNS])
    return out.getvalue()


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._") or "file"


def diff_name(row: ReportRow) -> str:
    base = _slug(Path(row.file).stem)
    return f"{base}.L{row.line}.diff" if row.line else f"{base}.diff"


def write_report(rows: Sequence[ReportRow], folder: Union[str, Path]) -> list[Path]:
    """Write ``report.json``, ``report.csv`` and one ``.diff`` per row that has a patch.

    Returns the paths written. Existing files of the same name are overwritten; nothing else is touched.
    """
    out = Path(folder)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text in (("report.json", to_json(rows) + "\n"), ("report.csv", to_csv(rows))):
        (out / name).write_text(text, encoding="utf-8", newline="")
        written.append(out / name)
    seen: Counter = Counter()
    for row in rows:
        if not row.proposed_patch:
            continue
        name = diff_name(row)
        seen[name] += 1
        if seen[name] > 1:  # two files with the same base name in one report
            name = name.replace(".diff", f".{seen[name]}.diff")
        # the schema strips trailing whitespace; a patch file must end with a newline
        (out / name).write_text(row.proposed_patch.rstrip("\n") + "\n", encoding="utf-8", newline="")
        written.append(out / name)
    return written


# --------------------------------------------------------------------------
# Numbers for the evaluation (M10) and the UI summary
# --------------------------------------------------------------------------


def summarize(sessions: Iterable[Session]) -> dict:
    """Counts across sessions: statuses, verifier outcomes, attempts, retries and model use.

    ``retry_rate`` is the share of findings that needed more than one patch attempt. A finding still
    waiting for a person is counted under ``unfinished`` and left out of the status counts.
    """
    findings = ready = escalated = unfinished = retried = patched = 0
    attempts = model_calls = cached = 0
    outcomes: Counter = Counter()
    for s in sessions:
        model_calls += s.model_calls
        cached += s.cached_replies
        for rec in s.records:
            findings += 1
            attempts += rec.attempts
            if rec.attempts:
                patched += 1
            if rec.attempts > 1:
                retried += 1
            if rec.verification is not None:
                outcomes[rec.verification.outcome.value] += 1
            if rec.state is State.READY_FOR_REVIEW:
                ready += 1
            elif rec.state is State.ESCALATED:
                escalated += 1
            else:
                unfinished += 1
    return {
        "findings": findings,
        "ready_for_review": ready,
        "escalated": escalated,
        "unfinished": unfinished,
        "patched": patched,
        "patch_pass_rate": round(ready / patched, 3) if patched else None,
        "retry_rate": round(retried / patched, 3) if patched else None,
        "attempts": attempts,
        "verification": dict(outcomes),
        "model_calls": model_calls,
        "cached_replies": cached,
    }


def status_counts(rows: Sequence[ReportRow]) -> dict[str, int]:
    counts = Counter(r.status.value for r in rows)
    return {s.value: counts.get(s.value, 0) for s in FindingStatus}
