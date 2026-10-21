# What it does

PQ-Patch takes one Python file and finds the places where it uses RSA or ECDSA digital signatures, which a quantum computer could break. For each place it proposes a replacement that uses the NIST post-quantum signature scheme ML-DSA (FIPS 204), checks the proposal with code rather than trusting the model, and prints a unified diff for a person to review. It never edits the file.

It is an agent in the sense that matters here: a model drafts a plan and then a patch, deterministic code decides whether each draft is acceptable, and a human approves the plan before a patch is drafted. Only the two drafting steps use a model. Finding the calls and verifying the result do not.

Only signing is in scope. Key exchange, encryption and other uses are reported and escalated to a person, never patched.

> **Status.** Built and tested: the detector, schemas, verifier, model client and planner. Not built yet: the patcher, the orchestrator, the report/export, `main.py` and the UI. Checks marked † below need `main.py`.

# Inputs

- **A single `.py` file**, given as `python main.py <path>` or uploaded in the UI.
- **The input is untrusted.** Its code, comments, strings and file name may contain text written to manipulate the model (see `SECURITY.md`).
- **Limits, enforced before any model call.** The file must be non-empty, at most 262,144 bytes (256 KiB), have a `.py` extension, and parse as Python. Otherwise the run ends with exit code 2, makes no model call and writes no `run_log.jsonl` line. A file that does not parse is reported with the reason, never silently skipped.
- **Optional project folder** (UI and library): used by the verifier to run the project's existing tests against the patch in a temp copy.
- **Reviewer feedback** (UI): free text, at most 2,000 characters, sent to the model when a plan is revised or a patch is retried.
- **Configuration** is three variables in `.env`: `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL`. Any OpenAI-compatible provider works. `LLM_BASE_URL=local://stub` selects the course's offline stub, which exists to trigger failures on purpose and is not how the product is used.

# Outputs

`main.py` prints, for each finding, one report row, then a **status line as the last line of stdout**. Diagnostics go to stderr. Two logs are written in the repository root and never committed: `run_log.jsonl` (one line per model call) and `security_log.jsonl` (guardrail events).

**Report row** (the nine fields; `proposed_patch` is a unified diff):

```json
{
  "file": "samples/sample_input.py",
  "line": 9,
  "original_call": "private_key.sign",
  "target_algorithm": "ML-DSA-65",
  "proposed_patch": "--- a/samples/sample_input.py\n+++ b/samples/sample_input.py\n@@ ... @@",
  "verification_result": "pass",
  "attempts": 1,
  "status": "ready_for_review",
  "notes": ""
}
```

- `status` is one of `ready_for_review` (patch verified `pass`; a person still has to review it), `escalated` (out of scope, or retries ran out; `notes` says why) or `no_action_needed` (nothing to patch; no patch is fabricated).
- `verification_result` is one of `pass`, `failed_compile`, `failed_test`, `failed_test(timeout)`, `needs_review`. `pass` means the patch compiles, the original call is gone, nothing new was introduced and any existing tests passed. It does not mean the patch is correct.

**Run status** (last line of stdout, and the `status` of the last `run_log.jsonl` line): `ok`, `invalid_output`, `refused` or `error`. If a model call ends in anything but `ok`, the run stops there with that status and any later findings are listed as not attempted.

**Exit codes:** `0` for `ok`; `1` for `invalid_output`, `refused` or `error`; `2` when the input is rejected before any model call.

**Model reply shape.** Each model step returns one JSON envelope and reads only its own key: the planner reads `{"plan": {...}}` or `{"escalate": {"reason": "..."}}`; the patcher will read `{"patch": {...}}`. Unknown top-level keys are ignored; the inner objects are strict. `samples/valid_response.json` and `samples/invalid_response.json` are the accepted and rejected examples used with the stub.

# Failure cases

| Situation | What the app does | Run status / exit |
|---|---|---|
| Empty file, over 256 KiB, not `.py`, or does not parse | Rejects before any model call, says why on stderr | exit 2, no log line |
| Reply is empty, not JSON, or fails the schema (`stub:empty`, `stub:malformed`, `stub:badshape`) | One re-ask quoting the validation error; if still bad, nothing is kept | `invalid_output`, exit 1 |
| Model refuses (`stub:refused`) | Not retried, no plan | `refused`, exit 1 |
| Call raises or the provider is down (`stub:error`) | Up to 3 calls with capped backoff, then gives up | `error`, exit 1 |
| Rate limited (`stub:ratelimit`) | Waits as the provider asks (capped), gives up after 3 calls | `error`, exit 1 |
| One transient failure (`stub:flaky`) | Retries and continues | `ok`, exit 0 |
| Injected instructions in the file (`stub:obedient`) | Phrases are replaced before the call and logged; the model never sees them; the result is validated and verified as normal | `ok`, exit 0, guard event logged |
| Model says the call is not signing, or cannot tell | Escalated with its reason; no patch is drafted | row `escalated` |
| Patch does not parse as the model wrote it (for example JSON escaped twice, or non-breaking hyphens) | Repaired by code only if the repaired text parses; otherwise sent back to the model once with the compiler message and the offending line | repaired or revised patch is shown; if still broken, `failed_compile` |
| Patch does not compile | Reported as `failed_compile` with the compiler message; a person may retry with guidance | row not `ready_for_review` |
| Patch assumes something about the caller's code (a method the original never used on a parameter, an "assume" or TODO comment) | Sent back to the model once; the better draft is kept and what remains is listed | `needs_review`, never `pass` |
| Original call still present, or a new one introduced | `needs_review` | row not `ready_for_review` |
| Existing tests fail / do not finish in 30 s | `failed_test` / `failed_test(timeout)` with the output | row not `ready_for_review` |
| Retry limit reached (3 attempts per finding) | Escalated with the last failure output | row `escalated` |
| Nothing flagged | No model call, no patch | row `no_action_needed` |

# Acceptance checks

Each check is a command. † means it needs `main.py`.

1. Unit tests, no model or network needed: `python -m pytest` (all pass).
2. The detector on a real project: with pyjwt cloned to `../targets/pyjwt`, `python -m pytest tests/test_real_repos.py` expects 6 findings in `jwt/algorithms.py`.
3. † Happy path against the stub: `python main.py samples/sample_input.py`, with `.env` set to `LLM_BASE_URL=local://stub` and `LLM_MODEL=stub:ok`. Last line `ok`, exit 0, `run_log.jsonl` has one line per model call with nine keys and one `run_id`.
4. † Bad replies: with `stub:malformed`, `stub:badshape` and `stub:empty` the last line is `invalid_output`, exit 1, no file written other than the two logs. With `stub:refused` it is `refused`; with `stub:error` it is `error`.
5. † Bad input: an empty file and a file over 256 KiB each exit 2, make no model call and add no log line.
6. † Injection: `python main.py samples/injected_input.py` with `stub:obedient` ends `ok`; the marker `PWNED-7F3A` appears in neither stdout nor any stored file; `security_log.jsonl` contains `instruction_ignored` and `guardrail_input`.
7. † The course check: `python check_capstone.py .` (needs the `capstone-submission` tag when marking).
8. † Human gate: with no approval given, the UI stays at "awaiting plan approval" and drafts no patch.
9. Every status in `samples/run_log_sample.jsonl` is one of the four, and every line has the nine keys.

# Out of scope

- Key exchange and KEM (ECDH, DH), DSA, and RSA encryption/decryption. They are detected only as far as the planner can tell, and are escalated, never patched.
- Replacing anything with a scheme other than ML-DSA (no ML-KEM, no hybrid or composite signatures).
- Applying patches or editing files, opening pull requests, or any autonomous change to a codebase.
- Whole-repository scanning in the app (the detector can scan a folder; `main.py` takes one file).
- Languages other than Python, and calls that need type inference, such as `key.sign(...)` without a padding argument.
- Making `liboqs` installable or proving a patch correct at runtime. Verification is compile, detector and the project's own tests, not a cryptographic proof.
- Certificate (X.509) signing, which `pyca/cryptography` cannot do with ML-DSA.
