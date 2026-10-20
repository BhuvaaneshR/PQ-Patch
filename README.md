# PQ-Patch

PQ-Patch finds quantum-vulnerable cryptography in a Python file (RSA, elliptic-curve, DSA and DH key generation, and RS/PS/ES JWT algorithms) and proposes a reviewed replacement using a NIST post-quantum algorithm: ML-DSA for signing, ML-KEM for key exchange. It is for developers who need to migrate a codebase and want a human-checkable diff for each call site, not an automatic rewrite.

How it works:

1. A deterministic detector (`pq_patch/detector.py`) parses the file with `ast` and locates each vulnerable call. No model is involved in finding them.
2. For each finding, the model drafts a replacement plan and patch. The reply is checked against a Pydantic schema (`pq_patch/schemas.py`) before anything uses it.
3. A deterministic verifier compiles the patched code and re-runs the detector on it.
4. The output is a unified diff per finding. The tool never edits your file.

The run ends with one status on the last line: `ok`, `invalid_output`, `refused` or `error`.

> **Status:** the detector, schemas and verifier are done and tested. `main.py`, the model pipeline, the guards and the UI are being built, so the Run section below describes the intended interface. Update this section before tagging.

## Setup

Python 3.12 is what this was developed on.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
cp .env.example .env               # Windows: copy .env.example .env  - then fill in your provider
```

`.env` holds `LLM_API_KEY`, `LLM_BASE_URL` and `LLM_MODEL`. Never commit it. The provider must expose an OpenAI-compatible endpoint, because every model call goes through `client.py`. To run offline against the course stub instead of a real model, set `LLM_BASE_URL=local://stub` and `LLM_MODEL=stub:ok`.

No second program needs to be running.

## Run

```bash
python main.py <path to a .py file>        # no UI; the last line is the status
streamlit run app.py                       # the UI
```

Exit codes: `0` for `ok`, `1` for `invalid_output`, `refused` or `error`, and `2` when the input is rejected before any model call (empty, too large, not a `.py` file, or not valid Python).

Two logs are written in the repository root and are not committed: `run_log.jsonl` (one line per model call) and `security_log.jsonl` (guardrail events). A small sample of the run log is in `samples/run_log_sample.jsonl`.

## Tests

```bash
python -m pytest
```

These cover the schemas, the detector and the verifier. They need no model and no network. `tests/test_real_repos.py` also needs local clones of pyjwt and trustme and is skipped without them (see its docstring).

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
- Only single files are scanned by the app. Directory scanning exists in the detector but is not exposed in `main.py`.
