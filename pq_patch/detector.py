"""Deterministic detector for quantum-vulnerable crypto calls (M1).

No LLM is involved: calls are resolved through the file's imports and matched
against fixed lookup tables, so classification is exact and reproducible.
Unparseable files are reported, never skipped.

Known limits (by design, for a bounded scope):
- Only call sites are detected. Methods on already-constructed keys
  (``key.sign(...)``) need type inference and are not resolved.
- Imports are collected file-wide; local shadowing of an imported name is ignored.
- Relative imports and ``from x import *`` are not resolved.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Iterator, Optional, Union

from .schemas import Algorithm, FileScanResult, Finding

_PYCA = "cryptography.hazmat.primitives.asymmetric"

# Fully-qualified call -> algorithm family.
CALL_TABLE: dict[str, Algorithm] = {
    # pyca/cryptography
    f"{_PYCA}.rsa.generate_private_key": Algorithm.RSA,
    f"{_PYCA}.ec.generate_private_key": Algorithm.EC,
    f"{_PYCA}.ec.ECDSA": Algorithm.ECDSA,
    f"{_PYCA}.ec.ECDH": Algorithm.ECDH,
    f"{_PYCA}.dsa.generate_private_key": Algorithm.DSA,
    f"{_PYCA}.dh.generate_parameters": Algorithm.DH,
    # python-rsa
    "rsa.newkeys": Algorithm.RSA,
    "rsa.sign": Algorithm.RSA,
    "rsa.verify": Algorithm.RSA,
    "rsa.encrypt": Algorithm.RSA,
    "rsa.decrypt": Algorithm.RSA,
}
# PyCryptodome (and its Cryptodome fork)
for _pkg in ("Crypto", "Cryptodome"):
    CALL_TABLE[f"{_pkg}.PublicKey.RSA.generate"] = Algorithm.RSA
    CALL_TABLE[f"{_pkg}.PublicKey.ECC.generate"] = Algorithm.EC
    CALL_TABLE[f"{_pkg}.PublicKey.DSA.generate"] = Algorithm.DSA

# JWT libraries: function -> (keyword name carrying the algorithm(s), positional index).
JWT_CALLS: dict[str, tuple[str, int]] = {
    "jose.jwt.encode": ("algorithm", 2),
    "jose.jwt.decode": ("algorithms", 2),
    "jose.jws.sign": ("algorithm", 3),
    "jose.jws.verify": ("algorithms", 2),
    "jwt.encode": ("algorithm", 2),  # PyJWT
    "jwt.decode": ("algorithms", 2),
}
JWT_ALGORITHMS: dict[str, Algorithm] = {
    **{f"RS{n}": Algorithm.RSA for n in (256, 384, 512)},
    **{f"PS{n}": Algorithm.RSA for n in (256, 384, 512)},
    **{f"ES{n}": Algorithm.ECDSA for n in (256, 384, 512)},
    "ES256K": Algorithm.ECDSA,
}

SKIP_DIRS = frozenset({".git", "__pycache__", ".venv", "venv", "env", "node_modules", ".tox", "site-packages"})


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _dotted(node: ast.AST) -> Optional[str]:
    """'a.b.c' for a Name/Attribute chain rooted at a Name, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _collect_imports(tree: ast.AST) -> dict[str, str]:
    """Map each locally bound name to the dotted path it refers to."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
                else:
                    root = a.name.split(".")[0]
                    aliases[root] = root
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue
            for a in node.names:
                if a.name != "*":
                    aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def _string_values(node: Optional[ast.AST]) -> list[str]:
    """String constants from a literal str or a list/tuple/set of them."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    return []


def _jwt_algorithm(call: ast.Call, kw_name: str, pos: int) -> Optional[tuple[str, Algorithm]]:
    arg: Optional[ast.AST] = None
    for kw in call.keywords:
        if kw.arg == kw_name:
            arg = kw.value
    if arg is None and len(call.args) > pos and not isinstance(call.args[pos], ast.Starred):
        arg = call.args[pos]
    for name in _string_values(arg):
        if name in JWT_ALGORITHMS:
            return name, JWT_ALGORITHMS[name]
    return None


# --------------------------------------------------------------------------
# Visitor
# --------------------------------------------------------------------------


class _Collector(ast.NodeVisitor):
    def __init__(self, filename: str, aliases: dict[str, str]) -> None:
        self.filename = filename
        self.aliases = aliases
        self.findings: list[Finding] = []
        self._top: Optional[ast.stmt] = None
        self._names: list[str] = []  # enclosing class/function names
        self._funcs: list[ast.AST] = []  # enclosing function nodes

    # --- scope tracking ---------------------------------------------------

    def visit_stmt_top(self, stmt: ast.stmt) -> None:
        self._top = stmt
        self.visit(stmt)

    def _visit_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        # Decorators and defaults are evaluated in the enclosing scope.
        for expr in node.decorator_list:
            self.visit(expr)
        for expr in [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]:
            self.visit(expr)
        self._names.append(node.name)
        self._funcs.append(node)
        for stmt in node.body:
            self.visit(stmt)
        self._funcs.pop()
        self._names.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expr in [*node.decorator_list, *node.bases, *(k.value for k in node.keywords)]:
            self.visit(expr)
        self._names.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self._names.pop()

    # --- detection --------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        written = _dotted(node.func)
        if written is not None:
            head, _, rest = written.partition(".")
            if head in self.aliases:
                qualified = self.aliases[head] + (f".{rest}" if rest else "")
                algorithm = CALL_TABLE.get(qualified)
                if algorithm is not None:
                    self._record(node, written, qualified, algorithm)
                elif qualified in JWT_CALLS:
                    hit = _jwt_algorithm(node, *JWT_CALLS[qualified])
                    if hit is not None:
                        self._record(node, written, f"{qualified}[{hit[0]}]", hit[1])
        self.generic_visit(node)

    def _record(self, node: ast.Call, written: str, qualified: str, algorithm: Algorithm) -> None:
        scope = self._funcs[-1] if self._funcs else self._top
        assert scope is not None and node.end_lineno is not None and scope.end_lineno is not None
        decorators = getattr(scope, "decorator_list", [])
        start = min([scope.lineno, *(d.lineno for d in decorators)])
        self.findings.append(
            Finding(
                file=self.filename,
                line=node.lineno,
                end_line=node.end_lineno,
                column=node.col_offset,
                original_call=written,
                qualified_name=qualified,
                algorithm=algorithm,
                enclosing_scope=".".join(self._names) or None,
                scope_start_line=start,
                scope_end_line=scope.end_lineno,
            )
        )


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def scan_source(source: Union[str, bytes], filename: str = "<string>") -> FileScanResult:
    """Scan Python source. Syntax/encoding problems yield ``parse_ok=False``."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as e:
        where = f" (line {e.lineno})" if e.lineno else ""
        return FileScanResult(file=filename, parse_ok=False, parse_error=f"{type(e).__name__}: {e.msg}{where}")
    except (ValueError, RecursionError, MemoryError) as e:
        return FileScanResult(file=filename, parse_ok=False, parse_error=f"{type(e).__name__}: {e}")

    collector = _Collector(filename, _collect_imports(tree))
    for stmt in tree.body:
        collector.visit_stmt_top(stmt)
    findings = sorted(collector.findings, key=lambda f: (f.line, f.column))
    return FileScanResult(file=filename, parse_ok=True, findings=findings)


def scan_file(path: Union[str, Path]) -> FileScanResult:
    """Scan one file. Raises OSError if it cannot be read at all."""
    path = Path(path)
    return scan_source(path.read_bytes(), str(path))


def iter_python_files(root: Union[str, Path]) -> Iterator[Path]:
    """Yield ``.py`` files under ``root`` in deterministic order, skipping vendor/VCS dirs."""
    root = Path(root)
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield Path(dirpath) / name


def scan_path(path: Union[str, Path]) -> list[FileScanResult]:
    """Scan a file or every Python file under a directory."""
    return [scan_file(p) for p in iter_python_files(path)]
