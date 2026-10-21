"""Patcher: draft replacement code for one finding, splice it in, and produce a diff (M5).

Two halves with a hard line between them:

* ``patch_finding`` asks the model for a ``Patch`` (replacement source for the enclosing scope,
  plus import statements) following an approved ``Plan``. This is the only part that uses a model,
  and it only drafts: nothing it returns is trusted.
* ``apply_patch`` and ``make_diff`` are deterministic. Given the same finding, source and Patch they
  always produce the same patched file and diff. The caller's file is never written; the verifier
  (M6) decides whether the patched text is acceptable.

Indentation: the scope is shown to the model without its base indentation and the reply is indented
back, so a method inside a class round-trips. Lines that continue a multi-line string are left alone
in both directions, because changing them would change the string.

Known limits:
- A scope longer than ``MAX_SCOPE_CHARS`` is escalated instead of patched: the model must see all of
  the code it replaces.
- Implicitly concatenated string pieces on separate lines are treated like multi-line strings, so
  their continuation lines are not re-indented. This is cosmetic: it is inside parentheses.
- Look-alike punctuation (non-breaking hyphens, curly quotes) is only repaired when the patch does
  not compile as written, so legitimate non-ASCII text in strings is never touched.
"""

from __future__ import annotations

import ast
import difflib
import re
import textwrap
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from .assumptions import Review, review_patch
from .llm_client import STATUS_ERROR, STATUS_INVALID, STATUS_REFUSED, StructuredLLM
from .prompts import build_messages
from .schemas import Finding, Patch, PatchReply, Plan
from .source_text import compile_error, import_lines, split_lines, strip_eol

MAX_FEEDBACK_CHARS = 2000
MAX_SCOPE_CHARS = 12_000
MAX_FAILURE_CHARS = 4000
MAX_IMPORT_CHARS = 3000

# Characters a model writes where it means a plain ASCII one (or nothing): dashes, curly quotes,
# no-break space, zero-width characters.
_LOOKALIKES = {
    **{ord(c): "-" for c in "‐‑‒–—―−"},
    **{ord(c): "'" for c in "‘’‚‛"},
    **{ord(c): '"' for c in "“”„‟"},
    ord(" "): " ",
    **{ord(c): None for c in "​‌‍⁠﻿"},
}


class PatchOutcome(str, Enum):
    PATCHED = "patched"
    ESCALATED = "escalated"
    INVALID_OUTPUT = "invalid_output"
    REFUSED = "refused"
    ERROR = "error"


@dataclass(frozen=True)
class AppliedPatch:
    patched_source: str
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PatchResult:
    outcome: PatchOutcome
    patch: Optional[Patch] = None
    patched_source: Optional[str] = None
    diff: Optional[str] = None
    reason: Optional[str] = None  # why it was escalated or failed
    notes: tuple[str, ...] = ()  # what the deterministic steps changed or flagged (for the reviewer)
    problems: tuple[str, ...] = ()  # guesses the static review found that a person must resolve
    warnings: tuple[str, ...] = ()  # softer findings, shown but not blocking
    calls: int = 0  # model calls made


# --------------------------------------------------------------------------
# Deterministic half: indentation, splice, imports, diff
# --------------------------------------------------------------------------


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip(" \t"))]


def _parses(code: str) -> bool:
    try:
        ast.parse(textwrap.dedent(code))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    return True


def _docstrings(tree: ast.AST) -> list[ast.Constant]:
    """The docstring constants (first statement of a module, class or function) in the tree."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                found.append(first.value)
    return found


def _string_rows(tree: ast.AST, lo: int, hi: int) -> set[int]:
    """Rows (1-based) inside [lo, hi] that continue a multi-line string, not code.

    Docstrings are excluded: their margin is conventionally insignificant (``inspect.cleandoc``
    strips it), so they are re-aligned instead of being left alone. Every other multi-line string
    keeps its text exactly.
    """
    docstrings = {id(n) for n in _docstrings(tree)}
    rows: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and not isinstance(node.value, (str, bytes)):
            continue
        if id(node) in docstrings:
            continue
        if isinstance(node, (ast.Constant, ast.JoinedStr)) and node.end_lineno and node.end_lineno > node.lineno:
            rows.update(range(node.lineno + 1, node.end_lineno + 1))
    return {r for r in rows if lo <= r <= hi}


def _newline_of(source: str) -> str:
    if "\r\n" in source:
        return "\r\n"
    if "\r" in source and "\n" not in source:
        return "\r"
    return "\n"


def _parse_source(source: str) -> ast.Module:
    try:
        return ast.parse(source)
    except SyntaxError as e:
        raise ValueError(f"source does not parse: {e.msg} (line {e.lineno})") from None


_LOOKALIKE_NOTE = "replaced look-alike punctuation (non-breaking hyphens, curly quotes) so the patch parses"
_ESCAPE_NOTE = "undid double-escaped characters in the patch (a literal backslash before n, t or quotes) so it parses"


# Escapes a model writes as a literal backslash pair when it has escaped its JSON twice. Tried mildest
# first: newlines and tabs, then also double quotes, then also single quotes.
_ESCAPES = (("\\n", "\n"), ("\\t", "\t"), ('\\"', '"'), ("\\'", "'"))
_ESCAPE_LEVELS = (2, 3, 4)  # how many of _ESCAPES to undo


def _repair_code(code: str) -> tuple[str, list[str]]:
    """Repair two common model slips, but only in code that does not parse as written.

    Look-alike punctuation and double-escaped characters are tried alone and then together, mildest
    first, and a repair is used only if the result parses. Code that already parses is never touched,
    so legitimate non-ASCII text or backslashes in strings are safe.
    """
    if _parses(code):
        return code, []
    translated = code.translate(_LOOKALIKES)
    attempts = [(translated, 0, True)]
    attempts += [(code, n, False) for n in _ESCAPE_LEVELS]
    attempts += [(translated, n, True) for n in _ESCAPE_LEVELS]
    for base, pairs, used_lookalikes in attempts:
        candidate = base
        for old, new in _ESCAPES[:pairs]:
            candidate = candidate.replace(old, new)
        if candidate != code and _parses(candidate):
            notes = []
            if used_lookalikes and translated != code:
                notes.append(_LOOKALIKE_NOTE)
            if pairs:
                notes.append(_ESCAPE_NOTE)
            return candidate, notes
    return code, []


def _leading(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _closing_quotes_only(line: str) -> bool:
    return line.strip() in ('"""', "'''")


def _reindent(code: str, indent: str) -> list[str]:
    """Lines of ``code`` with ``indent`` added.

    Continuation lines of ordinary multi-line strings are left alone. A multi-line docstring is
    re-aligned instead: its margin is replaced so the body sits under the opening quotes at the new
    indentation, whatever indentation the model happened to write, keeping relative indentation inside.
    """
    text = textwrap.dedent(code.replace("\r\n", "\n").replace("\r", "\n"))
    lines = text.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if not indent:
        return lines
    try:
        tree = ast.parse("\n".join(lines))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return [ln if not ln.strip() else indent + ln for ln in lines]
    skip = _string_rows(tree, 1, len(lines))
    out = [ln if (not ln.strip() or i + 1 in skip) else indent + ln for i, ln in enumerate(lines)]
    for doc in _docstrings(tree):
        if not (doc.end_lineno and doc.end_lineno > doc.lineno):
            continue
        rows = range(doc.lineno + 1, doc.end_lineno + 1)
        counted = [r for r in rows if lines[r - 1].strip() and not (r == doc.end_lineno and _closing_quotes_only(lines[r - 1]))]
        margin = min((_leading(lines[r - 1]) for r in counted), default=0)
        target = indent + " " * doc.col_offset
        for r in rows:
            line = lines[r - 1]
            if not line.strip():
                out[r - 1] = ""
            elif r == doc.end_lineno and _closing_quotes_only(line):
                out[r - 1] = target + line.strip()
            else:
                out[r - 1] = target + line[margin:]
    return out


def scope_for_prompt(finding: Finding, source: str) -> tuple[str, str]:
    """(enclosing scope without its base indentation, that indentation)."""
    lines = [strip_eol(x) for x in split_lines(source)]
    start, end = finding.scope_start_line, finding.scope_end_line
    if end > len(lines):
        raise ValueError("finding does not match the source: its scope extends past the end of the file")
    indent = _indent_of(lines[start - 1])
    skip = _string_rows(_parse_source(source), start, end)
    out = []
    for row in range(start, end + 1):
        line = lines[row - 1]
        if indent and row not in skip and line.startswith(indent):
            line = line[len(indent) :]
        out.append(line)
    return "\n".join(out), indent


def _first_stmt_start(node: ast.stmt) -> int:
    decorators = getattr(node, "decorator_list", [])
    return min([node.lineno, *(d.lineno for d in decorators)])


def apply_patch(finding: Finding, source: str, patch: Patch) -> AppliedPatch:
    """Splice ``patch`` into ``source``: pure, deterministic, never touches the file system.

    Replaces exactly the finding's enclosing scope and adds any new import statements after the
    last existing top-level import (or after the module docstring). Raises ValueError if the
    finding does not belong to this source or an import statement is malformed.
    """
    lines = split_lines(source)
    start, end = finding.scope_start_line, finding.scope_end_line
    if end > len(lines):
        raise ValueError("finding does not match the source: its scope extends past the end of the file")
    tree = _parse_source(source)
    notes: list[str] = []

    indent = _indent_of(lines[start - 1])
    code, repairs = _repair_code(patch.new_source)
    notes.extend(repairs)
    newline = _newline_of(source)
    new_lines = _reindent(code, indent)
    last = lines[end - 1]
    last_eol = last[len(strip_eol(last)) :]
    chunk = [ln + newline for ln in new_lines[:-1]] + [new_lines[-1] + last_eol]
    out = lines[: start - 1] + chunk + lines[end:]

    fresh: list[str] = []
    existing = {ast.dump(n) for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))}
    for stmt in (s.strip() for s in patch.imports):
        try:
            body = ast.parse(stmt).body
        except SyntaxError:
            raise ValueError(f"import statement is not valid Python: {stmt!r}") from None
        if len(body) != 1 or not isinstance(body[0], (ast.Import, ast.ImportFrom)):
            raise ValueError(f"not a single import statement: {stmt!r}")
        key = ast.dump(body[0])
        if key in existing:
            notes.append(f"import already present, not added: {stmt}")
        else:
            existing.add(key)
            fresh.append(stmt)

    if fresh:
        before = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)) and (n.end_lineno or 0) < start]
        first = tree.body[0]
        is_docstring = isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant) and isinstance(first.value.value, str)
        pad = False
        if before:
            at = before[-1].end_lineno or 0
        elif is_docstring and (first.end_lineno or 0) < start:
            at, pad = first.end_lineno or 0, True
        else:
            at, pad = _first_stmt_start(first) - 1, True
        block = [s + newline for s in fresh]
        if pad:
            block = ([newline] if at > 0 and is_docstring else []) + block + [newline]
        out[at:at] = block
        notes.append("added imports: " + "; ".join(fresh))

    return AppliedPatch("".join(out), tuple(notes))


def make_diff(display_name: str, original: str, patched: str) -> str:
    """Unified diff of the whole file, with ``a/`` and ``b/`` headers."""
    name = re.sub(r"^[A-Za-z]:", "", Path(display_name).as_posix()).lstrip("/")

    def prepared(text: str) -> list[str]:
        lines = split_lines(text)
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += "\n"
        return lines

    return "".join(difflib.unified_diff(prepared(original), prepared(patched), fromfile=f"a/{name}", tofile=f"b/{name}"))


# --------------------------------------------------------------------------
# Model half
# --------------------------------------------------------------------------


def _task(finding: Finding, plan: Plan, indent: str, feedback: Optional[str], retry: bool) -> str:
    scope = finding.enclosing_scope or "module level code"
    task = (
        "Draft the replacement code for one flagged cryptographic call, following the approved plan.\n\n"
        f"Flagged call: `{finding.original_call}` ({finding.algorithm.value} family) at line {finding.line} "
        f"of the file, inside {scope}. The scope_code block is the COMPLETE enclosing code, lines "
        f"{finding.scope_start_line} to {finding.scope_end_line}"
        + (f", shown without its base indentation of {len(indent)} character(s)" if indent else "")
        + ".\n\n"
        "Rules:\n"
        "- Return the full replacement for exactly that code: same name, parameters, return annotation, "
        "decorators and docstring unless the plan says otherwise, but update any wording in the docstring "
        "or comments that names the old algorithm so it does not become wrong. Keep unrelated lines as they are.\n"
        "- Use only the liboqs Python API: `oqs.Signature(alg, secret_key=None)`, with generate_keypair() "
        "(returns the public key), export_secret_key(), sign(message), and verify(message, signature, "
        "public_key) (returns a bool). Use it as a context manager (`with oqs.Signature(...) as s:`) so "
        f"native memory is freed. The algorithm name is {plan.target_algorithm}. If you are unsure an API "
        "exists, say so in the explanation instead of inventing it.\n"
        "- Keys: a key held in a parameter or variable becomes raw `bytes` (the ML-DSA secret or public key), "
        "so use it directly, for example `oqs.Signature(alg, secret_key=<parameter>)`. Do not call methods or "
        "read attributes on a parameter unless the original code already did. Do not write comments saying you "
        "are assuming something: if the change depends on a guess about what callers pass, escalate instead.\n"
        "- Put new import statements in `imports`, one statement per entry. Do not repeat them in new_source.\n"
        "- Use plain ASCII punctuation in code: hyphen-minus and straight quotes.\n"
        "- Return code only in new_source: no markdown fences, no line numbers.\n\n"
        'Reply as {"patch": {"new_source": "...", "imports": ["..."], "explanation": "..."}}, or '
        '{"escalate": {"reason": "..."}} if the change cannot be made by rewriting this code alone.\n\n'
        f"Approved plan:\n{plan.model_dump_json(indent=2)}"
    )
    if retry:
        task += (
            "\n\nThe previous attempt was applied and checked, and it failed. The previous_patch block holds "
            "the code you returned and the verifier_output block holds what the checks reported. Fix the problem."
        )
    if feedback:
        task += f"\n\nReviewer guidance: {feedback.strip()}"
    return task


def _draft(
    finding: Finding,
    source: str,
    plan: Plan,
    *,
    llm: StructuredLLM,
    feedback: Optional[str],
    previous_patch: Optional[Patch],
    failure_output: Optional[str],
    display_name: Optional[str],
) -> PatchResult:
    """One model call (plus the client's own re-ask) and the splice. No static review here."""
    if feedback is not None and len(feedback) > MAX_FEEDBACK_CHARS:
        raise ValueError(f"feedback is {len(feedback)} characters; the limit is {MAX_FEEDBACK_CHARS}")
    scope, indent = scope_for_prompt(finding, source)
    if len(scope) > MAX_SCOPE_CHARS:
        return PatchResult(
            PatchOutcome.ESCALATED,
            reason=f"the enclosing scope is {len(scope)} characters (limit {MAX_SCOPE_CHARS}); too large to rewrite safely",
        )

    untrusted = {"imports": import_lines(source, MAX_IMPORT_CHARS), "scope_code": scope}
    retry = previous_patch is not None or bool(failure_output)
    if previous_patch is not None:
        untrusted["previous_patch"] = previous_patch.new_source
    if failure_output:
        untrusted["verifier_output"] = failure_output[-MAX_FAILURE_CHARS:]

    messages = build_messages(_task(finding, plan, indent, feedback, retry), untrusted, PatchReply, "patcher.py:patch_finding")
    result = llm.call(messages, PatchReply, purpose="patcher")

    if result.status == STATUS_REFUSED:
        return PatchResult(PatchOutcome.REFUSED, reason=result.error, calls=result.calls)
    if result.status == STATUS_INVALID:
        return PatchResult(PatchOutcome.INVALID_OUTPUT, reason=result.error, calls=result.calls)
    if result.status == STATUS_ERROR:
        return PatchResult(PatchOutcome.ERROR, reason=result.error, calls=result.calls)

    reply = result.value
    assert reply is not None
    if reply.escalate is not None:
        return PatchResult(PatchOutcome.ESCALATED, reason=reply.escalate.reason, calls=result.calls)
    assert reply.patch is not None
    try:
        applied = apply_patch(finding, source, reply.patch)
    except ValueError as e:
        return PatchResult(PatchOutcome.INVALID_OUTPUT, patch=reply.patch, reason=f"patch could not be applied: {e}", calls=result.calls)
    diff = make_diff(display_name or finding.file, source, applied.patched_source)
    return PatchResult(
        PatchOutcome.PATCHED,
        patch=reply.patch,
        patched_source=applied.patched_source,
        diff=diff,
        notes=applied.notes,
        calls=result.calls,
    )


def _score(review: Review) -> tuple[int, int]:
    return (len(review.problems), len(review.warnings))


def _full_review(original: str, patched: str, filename: str) -> Review:
    """The assumption review plus a compile check, so a syntax error is sent back like any other finding."""
    review = review_patch(original, patched)
    error = compile_error(patched, filename)
    if error is None:
        return review
    return Review((f"the patched file does not compile: {error}", *review.problems), review.warnings)


def patch_finding(
    finding: Finding,
    source: str,
    plan: Plan,
    *,
    llm: Optional[StructuredLLM] = None,
    feedback: Optional[str] = None,
    previous_patch: Optional[Patch] = None,
    failure_output: Optional[str] = None,
    display_name: Optional[str] = None,
) -> PatchResult:
    """Ask the model for a patch for ``finding`` following ``plan``, splice it in, and review it.

    ``source`` is the whole file. To retry after a failed verification pass ``previous_patch`` and the
    verifier's ``failure_output`` (and optionally the reviewer's ``feedback``). Provider or reply
    problems come back as a non-patched outcome; ValueError means the inputs cannot be patched
    (source does not match the finding, feedback too long).

    After splicing, the patch gets the same static review the verifier applies (``assumptions.py``).
    If it finds a guess (a method assumed on a parameter, an "assume" comment, an old algorithm name
    left in a docstring) the model is asked ONCE to fix it, with the findings passed back like a failed
    check. Whichever attempt reviews better is returned; what is still wrong is in ``problems`` and
    ``warnings``, so nothing is hidden from the reviewer.
    """
    model = llm or StructuredLLM()
    first = _draft(
        finding, source, plan, llm=model, feedback=feedback,
        previous_patch=previous_patch, failure_output=failure_output, display_name=display_name,
    )
    if first.outcome is not PatchOutcome.PATCHED:
        return first
    filename = display_name or finding.file
    review = _full_review(source, first.patched_source or "", filename)
    if review.clean:
        return first

    issues = "\n".join(f"- {x}" for x in [*review.problems, *review.warnings])
    second = _draft(
        finding, source, plan, llm=model, feedback=feedback, previous_patch=first.patch,
        failure_output=f"A static review of your patch found:\n{issues}", display_name=display_name,
    )
    chosen, chosen_review, note = first, review, ()
    if second.outcome is PatchOutcome.PATCHED:
        second_review = _full_review(source, second.patched_source or "", filename)
        if _score(second_review) < _score(review):
            chosen, chosen_review = second, second_review
            note = ("the first draft was revised once after a static review found guesses in it",)
    calls = first.calls + second.calls
    attention = tuple(f"needs attention: {p}" for p in chosen_review.problems) + tuple(
        f"note: {w}" for w in chosen_review.warnings
    )
    return PatchResult(
        PatchOutcome.PATCHED,
        patch=chosen.patch,
        patched_source=chosen.patched_source,
        diff=chosen.diff,
        notes=(*chosen.notes, *note, *attention),
        problems=chosen_review.problems,
        warnings=chosen_review.warnings,
        calls=calls,
    )
