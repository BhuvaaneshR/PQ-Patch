"""Run the hand-labelled fixtures and write the numbers EVAL.md needs.

    python scripts/run_eval.py --detector-only            # free: no model, deterministic
    python scripts/run_eval.py                            # the whole set through the model in .env
    python scripts/run_eval.py --kinds out_of_scope safe --pause 8
    python scripts/run_eval.py --only v01_rsa_pss_sign.py --cache

The detector layer always runs. The pipeline layer calls the model configured in .env, one fixture at a
time, approving every plan automatically (this is a measurement, not a review), and records whether each
fixture reached the outcome the manifest expects. Results go to ``eval_results/eval_<UTC time>.json``
(git-ignored): provider, model, per-fixture outcome, attempts, verifier verdicts, model calls and the
detector metrics. A run against the course stub is stamped ``"measurement": false``: it proves the harness
works, nothing about the model.

The reply cache is OFF here unless you pass --cache, because a cached reply hides run-to-run variance.
If every configured model runs out of quota the run stops and lists what was not run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

from pq_patch.evaluation import (  # noqa: E402
    detector_metrics,
    evaluate_detector,
    load_manifest,
    pipeline_metrics,
    run_fixture,
)
from pq_patch.llm_client import StructuredLLM  # noqa: E402
from pq_patch.rate_limit import ReplyCache, describe_wait  # noqa: E402


def say(text: str = "") -> None:
    print(text)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--detector-only", action="store_true", help="skip the model entirely")
    ap.add_argument("--kinds", nargs="+", help="only these kinds: vulnerable safe broken injection with_tests out_of_scope")
    ap.add_argument("--only", nargs="+", help="only fixtures with these file names")
    ap.add_argument("--pause", type=float, default=0.0, help="seconds between fixtures (use ~8 on a free tier)")
    ap.add_argument("--cache", action="store_true", help="reuse stored replies (hides run-to-run variance)")
    ap.add_argument("--out", type=Path, default=ROOT / "eval_results", help="folder for the result file")
    args = ap.parse_args()

    fixtures = load_manifest()
    if args.kinds:
        fixtures = [f for f in fixtures if f.kind in args.kinds]
    if args.only:
        fixtures = [f for f in fixtures if Path(f.file).name in args.only or f.name in args.only]
    if not fixtures:
        print("no fixture matches that selection", file=sys.stderr)
        return 2

    say(f"== detector layer: {len(fixtures)} fixture(s), no model")
    detector = evaluate_detector(fixtures)
    for r in detector:
        say(f"  {'ok  ' if r.ok else 'DIFF'} {r.fixture.name:42} matched {len(r.matched)}"
            + (f", missing {r.missing}" if r.missing else "") + (f", unexpected {r.unexpected}" if r.unexpected else ""))
    dm = detector_metrics(detector)
    say(f"  precision {dm['precision']}, recall {dm['recall']}, false positives {dm['false_positives']}, "
        f"false negatives {dm['false_negatives']}, clean files with a false positive {dm['clean_files_with_false_positives']}/{dm['clean_files']}")

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "detector": dm,
        "detector_files": [{"file": r.fixture.name, "ok": r.ok, "missing": r.missing, "unexpected": r.unexpected} for r in detector],
    }

    if not args.detector_only:
        offline = os.getenv("LLM_BASE_URL", "").startswith("local://")
        if args.cache:
            os.environ["LLM_CACHE"] = "1"
        llm = StructuredLLM(cache=ReplyCache(os.getenv("LLM_CACHE_DIR") or ".llm_cache") if args.cache and not offline else None)
        model = ", ".join(llm.models()) or "(none configured)"
        say(f"\n== pipeline layer: {'COURSE STUB (harness check, not a measurement)' if offline else 'real model'} | {model}")
        results, skipped = [], []
        for i, fx in enumerate(fixtures):
            if fx.outcome != "rejected" and not llm.has_quota():
                skipped = [f.name for f in fixtures[i:]]
                break
            started = time.perf_counter()
            res = run_fixture(fx, llm)
            results.append(res)
            say(f"  {'met ' if res.met else 'MISS'} {fx.name:42} {res.observed[:70]}  "
                f"[calls {res.model_calls}, attempts {res.attempts}, {time.perf_counter() - started:.0f}s]")
            if args.pause and fx.outcome != "rejected":
                time.sleep(args.pause)
        if skipped:
            wait = max((s for _, s, _ in llm.unavailable_models()), default=0)
            say(f"\n  STOPPED: every configured model is out of quota (back in about {describe_wait(wait)}). Not run: {', '.join(skipped)}")
        pm = pipeline_metrics(results)
        say(f"\n  outcome met {pm['outcome_met']}/{pm['fixtures']}  by kind {pm['outcome_met_by_kind']}")
        say(f"  patched {pm['patched']}, pass rate {pm['patch_pass_rate']}, retry rate {pm['retry_rate']}, "
            f"model calls {pm['model_calls']}, cached replies {pm['cached_replies']}")
        record.update(
            {
                "provider": "stub" if offline else "real",
                "measurement": not offline,
                "models": llm.models(),
                "cache": bool(args.cache),
                "pipeline": pm,
                "not_run_quota": skipped,
                "fixtures": [
                    {
                        "file": r.fixture.name, "kind": r.fixture.kind, "expected": r.fixture.outcome, "met": r.met,
                        "observed": r.observed, "run_status": r.run_status, "model_calls": r.model_calls,
                        "cached_replies": r.cached_replies, "attempts": r.attempts, "statuses": r.statuses,
                        "verification": r.verification, "notes": r.notes,
                    }
                    for r in results
                ],
            }
        )

    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / f"eval_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    say(f"\nresults written to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
