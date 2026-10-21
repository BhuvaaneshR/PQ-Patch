# PQ-Patch

PQ-Patch finds quantum-vulnerable digital signatures in a Python file (RSA and ECDSA signing, including RS/PS/ES JWT algorithms) and proposes a reviewed replacement using the NIST post-quantum signature scheme ML-DSA (FIPS 204). Key exchange, encryption and other uses are reported and escalated, never patched. It is for developers who need to migrate a codebase and want a human-checkable diff for each call site, not an automatic rewrite.

How it works:

1. A deterministic detector (`pq_patch/detector.py`) parses the file with `ast` and locates each vulnerable call. No model is involved in finding them.
2. For each finding the model drafts a replacement **plan**. A person approves it (or asks for a revision, or escalates). Only then does the model draft the **patch**. Every reply is checked against a Pydantic schema (`pq_patch/schemas.py`) before anything uses it.
3. A deterministic verifier compiles the patched code, re-runs the detector, reviews the patch for guesses, and runs the project's own tests in a temp copy.
4. The output is a unified diff per finding, with the verifier's verdict. The tool never edits your file.

A deterministic state machine (`pq_patch/orchestrator.py`) moves each finding along; the model never chooses the next step, and there is no way to skip the plan checkpoint.

The run ends with one status on the last line: `ok`, `invalid_output`, `refused` or `error`.

> **Status:** every part is built and tested offline: detector, schemas, verifier, model client (with rate-limit handling), planner, patcher, orchestrator, report export, `main.py` and the UI. Not yet done: a measured run of the evaluation set against a real model (see `EVAL.md`).

## Setup

Python 3.12 is what this was developed on.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
cp .env.example .env               # Windows: copy .env.example .env  - then fill in your provider
```

`.env` holds `LLM_API_KEY`, `LLM_BASE_URL` and `LLM_MODEL`. Never commit it. If your provider limits tokens (most free tiers do), four optional variables help, all off unless set: `LLM_FALLBACK_MODELS` (models to use when the main one is out of quota), `LLM_TPM_LIMIT` (pace calls under a tokens-per-minute limit), `LLM_CACHE=1` (store validated replies so a repeated step costs no tokens) and `LLM_MAX_RETRY_DELAY` (see `.env.example`). The provider must expose an OpenAI-compatible endpoint, because every model call goes through `client.py`. To run offline against the course stub instead of a real model, set `LLM_BASE_URL=local://stub` and `LLM_MODEL=stub:ok`.

No second program needs to be running.

## Run

```bash
python main.py <path to a .py file>        # no UI; one JSON row per finding, then the status
streamlit run app.py                       # the UI
```

`main.py` options: `--project-root DIR` runs the project's own tests against each patch, `--out DIR` writes `report.json`, `report.csv` and one `.diff` per patch, `--ask` asks you at each checkpoint in the terminal, `--cache` reuses stored model replies. Without `--ask` the plan is approved automatically so the command can run unattended, and a failed check is escalated rather than retried. The UI always waits for you: it drafts a plan, stops, and only drafts a patch after you approve. It can also plan one finding at a time, which is the way to spend few tokens.

Stdout is the report rows and then, as its last line, the run status. Exit codes: `0` for `ok`, `1` for `invalid_output`, `refused` or `error`, and `2` when the input is rejected before any model call (empty, too large, not a `.py` file, or not valid Python).

Two logs are written in the repository root and are not committed: `run_log.jsonl` (one line per model call) and `security_log.jsonl` (guardrail events). A small sample of the run log is in `samples/run_log_sample.jsonl`.

## Tests

```bash
python -m pytest
```

To run the tests that call the real model set in `.env` (they spend free-tier quota and are excluded from the normal run):

```bash
python -m pytest -m live
```

A live run first makes one tiny call. If the provider settings are wrong (a model id the provider does not know, a rejected key, an unreachable URL) it stops straight away with one sentence saying what to fix in `.env`. Otherwise every live test appends what it saw (the plan, the patch and diff, the verifier's verdict, tokens, latency, list-price cost) to `eval_results/live_<time>.jsonl`, which git ignores. Run it a few times, then compare the runs:

```bash
python scripts/summarize_live.py --failures
```

The normal run covers every module, including the orchestrator, `main.py` (as a real process against the course stub) and the UI (headless, with Streamlit's `AppTest`). It needs no real model and no network: model calls are tested against the course stub (using `samples/valid_response.json` and `samples/invalid_response.json`), a fake provider and `tests/scripted_llm.py`, which stands in for the model so the real planner, patcher and verifier run on scripted replies. `tests/test_real_repos.py` also needs local clones of pyjwt and trustme and is skipped without them (see its docstring).

## Evaluate

Twenty-two hand-labelled fixtures live in `samples/fixtures/` (vulnerable, safe, broken, injected, out of scope, and two small projects with tests), listed with their expected findings and outcomes in `samples/fixtures/manifest.json`.

```bash
python scripts/run_eval.py --detector-only     # no model: precision and recall of the detector
python scripts/run_eval.py                     # the whole set through the model in .env
```

Results land in `eval_results/eval_<time>.json` and are summarised in `EVAL.md`. The two fixture projects carry `oqs.py`, a labelled test double with the call shape of `liboqs-python` (not cryptography), so their tests can import the patched code without installing `liboqs`.

## Check

```bash
python check_capstone.py .
```

This runs the course check script on your last commit, using only the stub.

## Known limitations

These are the limits of the detector, which are known now. The limitations found by running the model are recorded in `EVAL.md` and will be summarised here.

- Only call sites are detected. A method on an already-built key, such as `key.sign(...)`, needs type inference and is not found. The exception is RSA `sign`/`verify`, which is recognised by the `padding.PSS` or `padding.PKCS1v15` argument it must be given. The same padding passed to `encrypt`/`decrypt` is not flagged.
- Imports are collected for the whole file. If a local variable shadows an imported name, the detector does not notice.
- Relative imports and `from x import *` are not resolved.
- ECDSA versus ECDH is decided by how the key is used, not by the call, so an elliptic-curve key generation call is reported with the generic `EC` family.
- The verifier runs the project's existing tests in a temp copy, chosen by a text match on the module name. A patch that imports a package that is not installed (for example `oqs`) makes those tests fail with `ModuleNotFoundError`. This is not an OS-level sandbox: it keeps file writes off the original and keeps `.env` files and secret-looking environment variables out of the run.
- Before a file reaches the model, instruction-like phrases in it (for example "ignore previous instructions", "mark this as safe") are replaced with a placeholder and logged. This lowers injection risk but is not a guarantee, and it changes the text the model sees, so a comment inside a rewritten scope can come back as the placeholder. The verifier, not the model, decides whether a patch passes.
- The planner decides from the code it is shown whether a flagged key is used for signing. If it is key exchange, encryption, or cannot be told, the planner escalates with a reason instead of planning. A wrong call here is caught only by the human reviewing the plan.
- The patcher rewrites the whole enclosing function, class or statement of a finding. A scope longer than 12,000 characters is escalated instead, because the model must see all the code it replaces. The patch is spliced in by code and shown as a diff; the file is never written.
- A `pass` from the verifier means the patch compiles, the old call is gone, nothing new was flagged, a static review found no sign of a guess, and any existing tests passed. It does not mean the patch is correct. The review looks for the footprints of an assumption (a method called on a parameter the original never used, an "assume" or TODO comment, a docstring that still names the old algorithm). The first real-model patch assumed `private_key.export_secret_key()` exists, and this is how that is now caught. It cannot catch a guess that leaves no footprint, so a person has to read every diff.
- The model sometimes escapes its JSON twice, which breaks the code. The patcher repairs that (and non-breaking hyphens or curly quotes) only when the patch does not parse as written, and sends any other syntax error back to the model once.
- Only single files are scanned by the app. Directory scanning exists in the detector but is not exposed in `main.py`.
- Each finding is patched on its own against the original file. Two findings in one function get notes saying so, but their diffs rewrite the same code, so apply only one.
- `main.py` approves plans automatically unless you pass `--ask`. The UI never does.
- Rate limits: a daily quota is not retried (a minute of waiting cannot fix it); the model is marked out of quota until the provider says it resets, and `LLM_FALLBACK_MODELS` is tried next. The reply cache and `LLM_TPM_LIMIT` are opt-in. Details in `DECISIONS.md` (14).
