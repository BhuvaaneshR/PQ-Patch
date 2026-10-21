"""Summarise the records the live tests leave in eval_results/: pass rate per test across runs, tokens, speed, cost.

    python scripts/summarize_live.py                    # every live_*.jsonl in eval_results/
    python scripts/summarize_live.py --dir some/folder
    python scripts/summarize_live.py --failures         # also show how each failing run failed

Each live run (python -m pytest -m live) appends one JSON line per test. Running it several times and
summarising shows how often a real model gets it right, which a single pass or fail cannot. The cost column
is the provider's list price from observability.py, not what a free tier charges ($0).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(folder: Path) -> list[dict]:
    records = []
    for path in sorted(folder.glob("live_*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                records.append({**json.loads(line), "_file": path.name})
            except json.JSONDecodeError:
                continue
    return records


def _mean(values: list[float]) -> float | None:
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def summarize(records: list[dict]) -> list[dict]:
    """One row per (test, model): runs, passes, mean tokens and latency, total list-price cost."""
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in records:
        groups[(r.get("test", "?"), r.get("model", "?"))].append(r)
    rows = []
    for (test, model), runs in sorted(groups.items()):
        passed = sum(1 for r in runs if r.get("passed") is True)
        usage = [r.get("usage") or {} for r in runs]
        tokens = [(u.get("prompt_tokens") or 0) + (u.get("completion_tokens") or 0) for u in usage if u.get("calls")]
        rows.append(
            {
                "test": test,
                "model": model,
                "runs": len(runs),
                "passed": passed,
                "mean_tokens": _mean(tokens),
                "mean_latency_s": (lambda m: None if m is None else m / 1000)(_mean([u.get("latency_ms") for u in usage])),
                "cost_usd": sum(u.get("cost_usd") or 0 for u in usage),
                "failures": [r.get("failure") for r in runs if r.get("passed") is False],
            }
        )
    return rows


def render(rows: list[dict], failures: bool = False) -> str:
    if not rows:
        return "no live results found. Run: python -m pytest -m live"
    width = max(len(r["test"]) for r in rows)
    out = [f"{'test':<{width}}  {'model':<22} runs  passed  rate   tokens/run  latency  list-price"]
    for r in rows:
        rate = f"{100 * r['passed'] / r['runs']:.0f}%"
        tokens = "-" if r["mean_tokens"] is None else f"{r['mean_tokens']:.0f}"
        latency = "-" if r["mean_latency_s"] is None else f"{r['mean_latency_s']:.1f}s"
        out.append(
            f"{r['test']:<{width}}  {r['model']:<22} {r['runs']:>4}  {r['passed']:>6}  {rate:>4}   {tokens:>10}  {latency:>7}  ${r['cost_usd']:.4f}"
        )
    total_runs = sum(r["runs"] for r in rows)
    total_pass = sum(r["passed"] for r in rows)
    out.append(f"\nall tests: {total_pass} of {total_runs} runs passed ({100 * total_pass / total_runs:.0f}%)")
    if failures:
        for r in rows:
            for text in r["failures"]:
                lines = (text or "").strip().splitlines()
                errors = [ln.strip() for ln in lines if ln.lstrip().startswith("E ")]  # pytest marks the real message with "E"
                shown = errors[0] if errors else (lines[-1].strip() if lines else "(no message)")
                out.append(f"FAILED {r['test']}: {shown[:200]}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", type=Path, default=ROOT / "eval_results", help="folder holding live_*.jsonl")
    ap.add_argument("--failures", action="store_true", help="show the last line of each failure")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(render(summarize(load(args.dir)), args.failures))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
