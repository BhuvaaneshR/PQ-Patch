"""Run detect -> plan -> patch -> verify on one file and print every stage. Never edits the file.

    python scripts/demo_pipeline.py samples/sample_input.py
    python scripts/demo_pipeline.py samples/sample_input.py --project-root .
    python scripts/demo_pipeline.py ../targets/pyjwt/jwt/algorithms.py --line 683 --pause 8
    python scripts/demo_pipeline.py --review-demo

The model comes from .env (or from LLM_BASE_URL / LLM_MODEL set in the shell: use local://stub and
stub:ok to run offline). Findings are handled in order and the run stops at the first one that does not
finish cleanly. Exit code: 0 all patched and verified `pass`, 1 something needs a person or failed,
2 the input cannot be used. This is a manual-checking aid, not the product's entry point (that is main.py).
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):  # model text can contain characters the Windows console cannot show
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import client  # noqa: E402
from pq_patch.assumptions import review_patch  # noqa: E402
from pq_patch.detector import scan_file  # noqa: E402
from pq_patch.patcher import PatchOutcome, patch_finding  # noqa: E402
from pq_patch.planner import PlanOutcome, plan_finding  # noqa: E402
from pq_patch.verifier import verify  # noqa: E402

# What the real model returned on the first live run (a guessed API plus an "Assume" comment).
FIRST_REAL_RUN_PATCH = '''"""Signs release manifests with a long-lived RSA key."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import oqs


def sign_manifest(private_key, manifest: bytes) -> bytes:
    """Return an ML-DSA-65 signature over the manifest."""
    # Assume private_key provides export_secret_key()
    with oqs.Signature('ML-DSA-65', secret_key=private_key.export_secret_key()) as signer:
        return signer.sign(manifest)
'''


def heading(text: str) -> None:
    print(f"\n=== {text}")


def review_demo() -> int:
    original = (ROOT / "samples" / "sample_input.py").read_text(encoding="utf-8")
    heading("static review of the patch the real model wrote on its first run")
    review = review_patch(original, FIRST_REAL_RUN_PATCH)
    for p in review.problems:
        print("PROBLEM:", p)
    for w in review.warnings:
        print("WARNING:", w)
    print("result:", "needs a person" if review.problems else "clean")
    return 0


def check_environment(stub: bool) -> None:
    """client.py silently ignores .env when python-dotenv is missing: say so instead of failing oddly."""
    have = lambda name: importlib.util.find_spec(name) is not None  # noqa: E731
    if (ROOT / ".env").exists() and not have("dotenv"):
        print("WARNING: python-dotenv is not installed, so .env is being IGNORED (model and URL will look empty). "
              "Run: pip install python-dotenv openai", file=sys.stderr)
    if not stub and not have("openai"):
        print("WARNING: the openai package is not installed, so no real model can be called. "
              "Run: pip install python-dotenv openai", file=sys.stderr)


def run(path: Path, project_root: Path | None, only_line: int | None = None, pause: float = 0.0, limit: int | None = None) -> int:
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2
    source = path.read_text(encoding="utf-8")
    model = client.get_model()
    stub = client.os.getenv("LLM_BASE_URL", "").startswith("local://stub")
    check_environment(stub)
    heading(f"provider: {'course stub (offline)' if stub else 'real model'} | model: {model}")

    heading(f"detect: {path}")
    scan = scan_file(path)
    if not scan.parse_ok:
        print("unparseable:", scan.parse_error)
        return 2
    if not scan.findings:
        print("no findings: nothing to do")
        return 0
    for f in scan.findings:
        print(f"line {f.line}: {f.original_call} [{f.algorithm.value}] in {f.enclosing_scope or '<module>'}")

    chosen = [f for f in scan.findings if only_line is None or f.line == only_line]
    if limit is not None:
        chosen = chosen[:limit]
    if len(chosen) != len(scan.findings):
        print(f"\nprocessing {len(chosen)} of {len(scan.findings)} findings" + (f" (line {only_line})" if only_line else ""))
    if not chosen:
        print("no finding matches that selection")
        return 2

    worst = 0
    for f in chosen:
        heading(f"plan: {f.original_call} (line {f.line})")
        planned = plan_finding(f, source)
        print("outcome:", planned.outcome.value, "| model calls:", planned.calls)
        if planned.outcome is PlanOutcome.ESCALATED:
            print("escalated:", planned.reason)
            return 1
        if planned.outcome is not PlanOutcome.PLANNED:
            print("stopped:", planned.reason)
            return 1
        p = planned.plan
        print(f"target: {p.target_algorithm} | usage: {p.usage_context.value}")
        print("approach:", p.approach[:300])
        print("risks:", len(p.risks))

        time.sleep(pause)  # a free tier limits tokens per minute; this spaces the calls out
        heading("patch")
        patched = patch_finding(f, source, p, display_name=str(path).replace("\\", "/"))
        print("outcome:", patched.outcome.value, "| model calls:", patched.calls)
        if patched.outcome is not PatchOutcome.PATCHED:
            print("stopped:", patched.reason)
            return 1
        print("problems:", list(patched.problems) or "none", "| warnings:", list(patched.warnings) or "none")
        for n in patched.notes:
            print("note:", n)
        print("explanation:", patched.patch.explanation[:300] or "(none)")
        print("\n" + patched.diff)

        heading("verify")
        v = verify(f, source, patched.patched_source, project_root=project_root)
        print("outcome:", v.outcome.value, "| compile:", v.compile_ok, "| detector clear:", v.detector_clear,
              "| tests ran:", v.tests_ran)
        for line in v.output.splitlines():
            print("  ", line)
        worst = max(worst, 0 if v.outcome.value == "pass" else 1)
        time.sleep(pause)
    heading("summary")
    print("every finding patched and verified `pass`" if worst == 0 else "at least one finding needs a person")
    return worst


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="a .py file to analyse")
    ap.add_argument("--project-root", type=Path, help="run the project's own tests against the patch in a temp copy")
    ap.add_argument("--review-demo", action="store_true", help="show the static review on a known-bad patch (no model)")
    ap.add_argument("--line", type=int, help="only process the finding on this line")
    ap.add_argument("--limit", type=int, help="only process the first N findings")
    ap.add_argument("--pause", type=float, default=0.0, help="seconds to wait between model calls (use ~8 on a free tier)")
    args = ap.parse_args()
    if args.review_demo:
        return review_demo()
    if not args.file:
        ap.print_usage(sys.stderr)
        return 2
    return run(Path(args.file), args.project_root, args.line, args.pause, args.limit)


if __name__ == "__main__":
    raise SystemExit(main())
