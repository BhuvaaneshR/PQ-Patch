"""Reading source text the way Python's parser does.

``str.splitlines()`` also breaks at form feeds, vertical tabs and a few Unicode separators that
Python treats as ordinary whitespace, so its line numbers drift from the ``ast`` line numbers the
detector records. Anything that maps a finding back to text uses these helpers instead.
"""

from __future__ import annotations

import ast
import re

_LINE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+")


def split_lines(source: str) -> list[str]:
    """Lines with their endings kept, split only at \\n, \\r\\n and \\r."""
    return _LINE.findall(source)


def strip_eol(line: str) -> str:
    return line.rstrip("\r\n")


def compile_error(source: str, filename: str) -> str | None:
    """Why ``source`` does not compile, or None if it does. Compiles only; never executes it.

    A syntax error names the offending line, so it can be sent back to a model as is.
    """
    try:
        compile(source, filename, "exec", dont_inherit=True)
    except SyntaxError as e:
        text = (e.text or "").strip()
        where = f" (line {e.lineno}" + (f": {text[:120]!r})" if text else ")") if e.lineno else ""
        return f"{type(e).__name__}: {e.msg}{where}"
    except (ValueError, RecursionError, MemoryError) as e:
        return f"{type(e).__name__}: {e}"
    return None


def import_lines(source: str, max_chars: int = 3_000) -> str:
    """Every import statement in the file (all scopes), one statement per entry, as text."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        raise ValueError(f"source does not parse: {e.msg} (line {e.lineno})") from None
    lines = [strip_eol(x) for x in split_lines(source)]
    spans = sorted(
        {(n.lineno, n.end_lineno or n.lineno) for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))}
    )
    text = "\n".join("\n".join(lines[a - 1 : b]) for a, b in spans)
    return text if len(text) <= max_chars else text[:max_chars] + "\n# [imports truncated]"
