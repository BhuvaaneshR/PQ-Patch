"""Deterministic verifier for a drafted patch (M6).

No LLM is involved, and nothing the model wrote is trusted: the patched file is
checked by code that only looks at the patched source itself.

Four checks, in order:

1. Compile: the patched source must compile (``compile()``, which never runs it).
2. Detector: the original finding must be gone, and no finding may have appeared
   that was not already in the original file. Findings are compared by
   (qualified name, enclosing scope), so moving code up or down does not matter.
3. Review: look for guesses the model made about code it cannot see (see
   ``assumptions.py``), such as a new method call on a parameter the original never used.
4. Tests: if a project root is given, the project is copied to a temp directory,
   the patched file is written into the copy, and the existing pytest tests that
   mention the module are run there under a timeout.

The caller's files are never modified. Outcome mapping (see ``VerificationResult``):
failed_compile, else failed_test(timeout) if the tests did not finish in time, else
failed_test if the tests ran and failed, else pass if the detector is clear and the
review found no assumption, else needs_review.

Known limits:
- Running the tests executes project code (and the patch) in a subprocess. The temp
  copy keeps file writes away from the original and secrets are kept out of the copy
  and the environment, but this is not an OS-level sandbox.
- Tests are chosen by a text match on the module name, not by import analysis.
- A patch that imports a package that is not installed (for example ``oqs``) will make
  those tests fail with ModuleNotFoundError; the output says so.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional, Sequence, Union

from .assumptions import review_patch
from .detector import SKIP_DIRS, scan_source
from .source_text import compile_error
from .schemas import Finding, VerificationOutcome, VerificationResult

DEFAULT_TEST_TIMEOUT = 30.0
MAX_OUTPUT_CHARS = 6000
MAX_COPY_FILES = 5000
MAX_COPY_BYTES = 100 * 1024 * 1024

_COPY_SKIP_DIRS = SKIP_DIRS | {".pytest_cache", ".mypy_cache", ".ruff_cache", ".idea", ".vscode"}
_SECRET_ENV_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
_PYTEST_EXIT_NO_TESTS = 5


# --------------------------------------------------------------------------
# 1. Compile
# --------------------------------------------------------------------------


_compile_error = compile_error  # shared with the patcher; compiles only, never executes


# --------------------------------------------------------------------------
# 2. Detector
# --------------------------------------------------------------------------


def _key(f: Finding) -> tuple[str, Optional[str]]:
    return (f.qualified_name, f.enclosing_scope)


def _label(key: tuple[str, Optional[str]]) -> str:
    return f"{key[0]} in {key[1] or '<module>'}"


def _check_detector(
    finding: Finding, original_source: str, patched_source: str, filename: str
) -> tuple[Optional[bool], str]:
    """(detector_clear, explanation). None means the check could not be evaluated."""
    before = scan_source(original_source, filename)
    after = scan_source(patched_source, filename)
    if not after.parse_ok:
        return None, f"detector could not analyse the patched file: {after.parse_error}"
    if not before.parse_ok:
        return None, f"detector could not analyse the original file: {before.parse_error}"

    n_before = Counter(_key(f) for f in before.findings)
    n_after = Counter(_key(f) for f in after.findings)
    target = _key(finding)
    lines = []

    if n_before[target] == 0:
        return False, f"the finding ({_label(target)}) is not present in the original source"

    gone = n_after[target] < n_before[target]
    lines.append(
        f"{_label(target)}: {n_before[target]} before, {n_after[target]} after"
        + (" (removed)" if gone else " (still present)")
    )
    new = sorted((k for k in n_after if n_after[k] > n_before[k] and k != target), key=lambda k: (k[0], k[1] or ""))
    new_for_target = n_after[target] > n_before[target]
    for k in new:
        lines.append(f"new finding: {_label(k)} ({n_after[k]} after, {n_before[k]} before)")
    if new_for_target:
        lines.append(f"new finding: more {_label(target)} calls than before")
    return gone and not new and not new_for_target, "; ".join(lines)


# --------------------------------------------------------------------------
# 3. Tests in a temp copy
# --------------------------------------------------------------------------


def _is_secret_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.")


def _copy_project(src: Path, dst: Path) -> None:
    """Copy regular files only: no symlinks, no VCS/vendor dirs, no .env files."""
    files = total = 0
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _COPY_SKIP_DIRS and not (Path(dirpath) / d).is_symlink())
        rel = Path(dirpath).relative_to(src)
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or _is_secret_file(name) or name.endswith(".pyc"):
                continue
            files += 1
            total += path.stat().st_size
            if files > MAX_COPY_FILES or total > MAX_COPY_BYTES:
                raise ValueError(f"project is too large to verify in a temp copy (limit {MAX_COPY_FILES} files / {MAX_COPY_BYTES // 2**20} MB)")
            (dst / rel / name).write_bytes(path.read_bytes())


def _is_test_file(name: str) -> bool:
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _select_tests(root: Path, rel_file: Path) -> list[str]:
    """Test files (relative, posix) that are the file itself or mention its module name."""
    stem = rel_file.stem
    mentions = re.compile(rf"\b{re.escape(stem)}\b")
    selected = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(dirnames)
        for name in sorted(filenames):
            if not _is_test_file(name):
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(root)
            if rel == rel_file or mentions.search(path.read_text(encoding="utf-8", errors="replace")):
                selected.append(rel.as_posix())
    return selected


def _clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not any(m in k.upper() for m in _SECRET_ENV_MARKERS)}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _tail(text: str) -> str:
    return text if len(text) <= MAX_OUTPUT_CHARS else "...[truncated]...\n" + text[-MAX_OUTPUT_CHARS:]


def _run_tests(
    project_root: Path,
    rel_file: Path,
    patched_source: str,
    test_paths: Optional[Sequence[str]],
    timeout: float,
) -> tuple[bool, Optional[bool], bool, str]:
    """(tests_ran, tests_passed, timed_out, output). Runs pytest on a temp copy with the patch applied."""
    with tempfile.TemporaryDirectory(prefix="pq_patch_verify_") as tmp:
        sandbox = Path(tmp)
        _copy_project(project_root, sandbox)
        target = sandbox / rel_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(patched_source.encode("utf-8"))

        selected = list(test_paths) if test_paths else _select_tests(sandbox, rel_file)
        if not selected:
            return False, None, False, "no existing tests mention this module; tests not run"

        cmd = [sys.executable, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider", "--color=no", *selected]
        try:
            proc = subprocess.run(
                cmd, cwd=sandbox, env=_clean_env(), capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return True, False, True, f"tests timed out after {timeout:g}s: {' '.join(selected)}"

        out = _tail((proc.stdout or "") + (proc.stderr or "")).strip()
        if "No module named pytest" in out:
            return False, None, False, "pytest is not installed in this environment; tests not run"
        if proc.returncode == _PYTEST_EXIT_NO_TESTS:
            return False, None, False, "pytest collected no tests; tests not run"
        return True, proc.returncode == 0, False, out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def verify(
    finding: Finding,
    original_source: str,
    patched_source: str,
    *,
    project_root: Union[str, Path, None] = None,
    test_paths: Optional[Iterable[str]] = None,
    test_timeout: float = DEFAULT_TEST_TIMEOUT,
) -> VerificationResult:
    """Verify ``patched_source`` (the whole patched file) against ``finding``.

    ``project_root`` is the directory the file lives in; without it only the compile and
    detector checks run. ``test_paths`` (relative to the project root) overrides the
    automatic choice of tests. Raises ValueError if the file is outside ``project_root``
    or the project is too large to copy; those are caller errors, not verification results.
    """
    filename = finding.file
    sections: list[str] = []

    err = _compile_error(patched_source, filename)
    if err is not None:
        return VerificationResult(
            outcome=VerificationOutcome.FAILED_COMPILE, compile_ok=False, output=f"[compile] {err}"
        )
    sections.append("[compile] ok")

    detector_clear, detector_msg = _check_detector(finding, original_source, patched_source, filename)
    sections.append(f"[detector] {'clear' if detector_clear else 'not clear' if detector_clear is False else 'not evaluated'}: {detector_msg}")

    review = review_patch(original_source, patched_source)
    if review.problems or review.warnings:
        sections.append(
            "[review] "
            + "; ".join([f"needs a person: {p}" for p in review.problems] + [f"note: {w}" for w in review.warnings])
        )
    else:
        sections.append("[review] no assumptions found")

    tests_ran, tests_passed, timed_out = False, None, False
    if project_root is None:
        sections.append("[tests] no project root given; tests not run")
    else:
        root = Path(project_root).resolve()
        try:
            rel_file = Path(filename).resolve().relative_to(root)
        except ValueError:
            raise ValueError(f"{filename} is not inside the project root {root}") from None
        tests_ran, tests_passed, timed_out, tests_msg = _run_tests(
            root, rel_file, patched_source, list(test_paths) if test_paths else None, test_timeout
        )
        status = "timed out" if timed_out else "passed" if tests_passed else "failed" if tests_ran else "not run"
        sections.append(f"[tests] {status}\n{tests_msg}")

    if timed_out:
        outcome = VerificationOutcome.FAILED_TEST_TIMEOUT
    elif tests_ran and tests_passed is False:
        outcome = VerificationOutcome.FAILED_TEST
    elif detector_clear is True and not review.problems:
        outcome = VerificationOutcome.PASS
    else:
        outcome = VerificationOutcome.NEEDS_REVIEW

    return VerificationResult(
        outcome=outcome,
        compile_ok=True,
        detector_clear=detector_clear,
        tests_ran=tests_ran,
        tests_passed=tests_passed,
        output="\n".join(sections),
    )
