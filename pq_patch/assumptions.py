"""Deterministic review of a patched file for guesses the model made (M5/M6).

A patch can compile, clear the detector and pass the project's tests and still be wrong because the
model *assumed* something about code it cannot see. The first real-model run did exactly this: it
rewrote ``private_key.sign(...)`` as ``private_key.export_secret_key()`` and said so in a comment.
Nothing in compile / detector / tests can catch that, so this module looks for the footprints:

Problems (a person must look; the verifier will not return ``pass``):
- A function that existed before is gone (renamed or removed), or its parameters (names, order, kinds)
  changed. Callers would break. Annotations and defaults may change: a key becoming ``bytes`` is expected.
- A function now reads or calls ``param.attr`` where the original never used that attribute of that
  parameter. The caller's object may not have it.
- A new comment says the model is assuming something, or leaves a TODO / FIXME / placeholder.

Warnings (shown to the reviewer, do not change the outcome):
- A docstring or comment inside a changed function still names the old algorithm (RSA, ECDSA, PSS,
  PKCS#1) unchanged, so it is probably wrong now.

Everything is plain ``ast`` and ``tokenize``; no model is involved. It is a heuristic: it finds common
footprints, not every assumption. ``self`` and ``cls`` are ignored, and functions that did not exist
before the patch are not compared.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass

_ASSUMPTION = re.compile(r"\b(assum(e|es|ed|ing|ption|ptions)|todo|fixme|placeholder)\b", re.IGNORECASE)
_OLD_ALGORITHM = re.compile(r"\b(RSA|ECDSA|PSS|PKCS\s?#?1(v1\.?5)?|PKCS1v15)\b", re.IGNORECASE)
_IGNORED_PARAMS = frozenset({"self", "cls"})


@dataclass(frozen=True)
class Review:
    problems: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        return not self.problems and not self.warnings


def _functions(tree: ast.AST) -> dict[str, ast.AST]:
    """Qualified name -> function node, for every function and method in the module."""
    found: dict[str, ast.AST] = {}

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}{child.name}"
                found.setdefault(name, child)
                walk(child, name + ".")
            elif isinstance(child, ast.ClassDef):
                walk(child, f"{prefix}{child.name}.")
            else:
                walk(child, prefix)

    walk(tree, "")
    return found


def _params(func: ast.AST) -> set[str]:
    a = func.args  # type: ignore[attr-defined]
    names = [x.arg for x in [*a.posonlyargs, *a.args, *a.kwonlyargs]]
    names += [x.arg for x in (a.vararg, a.kwarg) if x is not None]
    return {n for n in names if n not in _IGNORED_PARAMS}


def _signature(func: ast.AST) -> tuple[tuple[str, str], ...]:
    """Parameter kinds and names in order. Annotations and defaults are deliberately not compared."""
    a = func.args  # type: ignore[attr-defined]
    parts = [("pos-only", x.arg) for x in a.posonlyargs] + [("pos", x.arg) for x in a.args]
    if a.vararg is not None:
        parts.append(("*", a.vararg.arg))
    parts += [("kw", x.arg) for x in a.kwonlyargs]
    if a.kwarg is not None:
        parts.append(("**", a.kwarg.arg))
    return tuple(parts)


def _show_signature(sig: tuple[tuple[str, str], ...]) -> str:
    prefix = {"*": "*", "**": "**"}
    return ", ".join(prefix.get(kind, "") + name for kind, name in sig)


def _param_attributes(func: ast.AST) -> set[tuple[str, str]]:
    params = _params(func)
    return {
        (n.value.id, n.attr)
        for n in ast.walk(func)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in params
    }


def _comments(source: str) -> list[tuple[int, str]]:
    """(line, text) of every comment, or [] if the source cannot be tokenized."""
    out = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                out.append((tok.start[0], tok.string.lstrip("#").strip()))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []
    return out


def _old_wording(text: str | None) -> bool:
    return bool(text and _OLD_ALGORITHM.search(text))


def review_patch(original_source: str, patched_source: str) -> Review:
    """Compare the two whole files and report guesses. Unparseable input gives an empty review."""
    try:
        old_tree, new_tree = ast.parse(original_source), ast.parse(patched_source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return Review()
    try:
        return _review_trees(original_source, patched_source, old_tree, new_tree)
    except RecursionError:  # parses, but is nested too deeply for the recursive walks below
        return Review(problems=("the static review could not analyse this file: it is nested too deeply",))


def _review_trees(original_source: str, patched_source: str, old_tree: ast.AST, new_tree: ast.AST) -> Review:
    problems: list[str] = []
    warnings: list[str] = []
    old_funcs, new_funcs = _functions(old_tree), _functions(new_tree)

    for name in old_funcs:
        if name not in new_funcs:
            problems.append(f"`{name}` no longer exists: it was removed or renamed, so anything that calls it will break")

    for name, new_fn in new_funcs.items():
        old_fn = old_funcs.get(name)
        if old_fn is None or ast.dump(old_fn) == ast.dump(new_fn):
            continue
        if _signature(old_fn) != _signature(new_fn):
            problems.append(
                f"`{name}` changed its parameters from ({_show_signature(_signature(old_fn))}) to "
                f"({_show_signature(_signature(new_fn))}): callers may break"
            )
        for param, attr in sorted(_param_attributes(new_fn) - _param_attributes(old_fn)):
            problems.append(
                f"`{name}` now uses `{param}.{attr}`, which the original never did: this assumes the "
                f"object passed as `{param}` has `{attr}`"
            )
        new_doc, old_doc = ast.get_docstring(new_fn, clean=False), ast.get_docstring(old_fn, clean=False)
        if new_doc is not None and new_doc == old_doc and _old_wording(new_doc):
            warnings.append(f"the docstring of `{name}` still names the old algorithm and was not updated")

    old_comments = {text for _, text in _comments(original_source)}
    changed_ranges = [
        (fn.lineno, fn.end_lineno or fn.lineno)
        for name, fn in new_funcs.items()
        if name in old_funcs and ast.dump(old_funcs[name]) != ast.dump(fn)
    ]
    for line, text in _comments(patched_source):
        if text in old_comments:
            if _old_wording(text) and any(a <= line <= b for a, b in changed_ranges):
                warnings.append(f"a comment on line {line} still names the old algorithm: {text[:80]!r}")
        elif _ASSUMPTION.search(text):
            problems.append(f"a new comment on line {line} states an assumption or leaves work undone: {text[:100]!r}")

    return Review(tuple(problems), tuple(warnings))
