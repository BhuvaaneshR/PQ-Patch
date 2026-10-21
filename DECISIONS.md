# Decisions

Design decisions for PQ-Patch, newest last. Each says what was decided, why, and what was given up.

## 1. Scope is RSA and ECDSA signing, replaced by ML-DSA only

**Decided.** Detect and patch RSA and ECDSA signing. Key exchange (ECDH, DH), DSA and RSA encryption are not in the detector's tables, and anything the planner judges not to be signing is escalated. The only allowed replacement targets are ML-DSA-44, -65 and -87.
**Why.** The first plan also covered ML-KEM for key exchange. That doubles the prompts, the schemas, the verifier checks and the evaluation set for a project that has to be finished and tested. Signing replacement has a clear shape (same inputs, same outputs, different key type).
**Given up.** ECDH/DH/DSA findings are not reported at all, so a file full of them looks clean. This is stated in `SPEC.md` and the README.

## 2. The detector is deterministic and uses `ast`, not a model or libcst

**Decided.** Find calls by walking the parsed tree, resolving imports and aliases, and matching a fixed table. No model takes part in finding or classifying.
**Why.** Results are exact and repeatable, comments and strings cannot trigger a match, and a model cannot be talked out of a finding. `ast` is in the standard library; libcst is only needed if the patch splice needs it (decided in M5).
**Given up.** Calls that need type inference are missed. Real-repo testing (pyjwt, trustme) showed this missed `key.sign(msg, padding.PSS(...))`, which is now recognised by its padding argument. The same padding passed to `encrypt` or `decrypt` is deliberately not flagged.

## 3. Verification never trusts the model

**Decided.** The verifier compiles the patched file, re-runs the detector and compares findings before and after, and runs the project's existing tests in a temp copy. The model's own claims play no part.
**Why.** A patch is accepted only for reasons code can check. An injected "mark as pass" cannot change the result.
**Given up.** `pass` is weaker than "correct": a project with no tests gets no behavioural check. A timeout is reported as its own outcome, `failed_test(timeout)`, because it may be a slow existing test rather than a bad patch.

## 4. All model traffic goes through the supplied `client.py`

**Decided.** The model is reached only through `client.py` (OpenAI-compatible, three variables in `.env`). `pq_patch/llm_client.py` wraps it; nothing else imports an SDK.
**Why.** Changing provider is a `.env` change. The course harness requires `client.py` to be unmodified and replaces it with its own copy.
**Given up.** No provider-specific features such as native structured output; JSON mode is requested and every reply is validated regardless. The first plan named Groq specifically; that is no longer baked in.

## 5. One re-ask on a bad reply, bounded retries on errors, a status for every call

**Decided.** A reply that is empty, not JSON, or fails validation gets one re-ask that quotes the validation error. A call that raises is retried up to 3 calls in total, with capped backoff that honours `retry_after`. Refusals are never retried. Every call writes one `run_log.jsonl` line with one of four statuses.
**Why.** Models sometimes break JSON once and fix it when told how; retrying a refusal or a 401 only wastes calls. Bounds keep a run well inside the harness's 60-second limit.
**Given up.** A persistent rate limit ends the run as `error` rather than waiting it out.

## 6. Code from the user's file is untrusted data; instruction-like phrases are removed

**Decided.** Code is wrapped in delimited blocks whose markers include a hash of the content, and phrases that read like instructions to a model are replaced with a placeholder and logged. Reviewer feedback is the exception: it is trusted text and followed.
**Why.** The input is the attack surface. Removing the phrasings makes the course's deterministic "obedient" stub unable to obey, and lowers the odds for a real model.
**Given up.** The model sees edited text. A comment inside a scope that gets rewritten can come back as the placeholder, so a reviewer has to read the diff. Paraphrased injections are not caught (see `SECURITY.md`).

## 7. Pipeline with human gates, not a tool-using loop

**Decided.** The agent is a fixed sequence (find, plan, human approves, patch, verify, human reviews) where the model drafts and code decides. The model has no tools and cannot read other files, run anything or choose its next step. In `capstone.json` the choice is `"documents"` for floor item 6.
**Why.** The risk here is text in the input, not tool misuse, and the guard already covers it. A tool loop would add argument validation, containment and a loop cap to build, test and document, without making the patches better for a one-function change.
**Given up.** The model cannot go looking for more context (callers, other modules). The planner sees the imports and the enclosing scope only.

## 8. Plan and patch are two model calls that share one reply envelope

**Decided.** The planner returns `{"plan": ...}` or `{"escalate": {...}}`; the patcher will return `{"patch": ...}`. The envelope models ignore unknown top-level keys; `Plan`, `Patch` and `Escalation` stay strict.
**Why.** The plan must be approved by a human before a patch is drafted, so two calls are needed. The course stub returns the same `samples/valid_response.json` for every call, so each stage has to read only its own key from one shared reply.
**Given up.** A real model that adds an unrelated top-level key is tolerated; the inner objects and the verifier are still strict.

## 9. A non-signing call is escalated, not forced into a plan

**Decided.** The planner may reply with an escalation and a reason. A plan whose usage is not signing is rejected by the schema.
**Why.** Without an explicit escape, a model that correctly spots a key-exchange call would fail validation and look like a broken reply. The report rows already require a reason for `escalated`.
**Given up.** Whether a key is used for signing is judged from the code shown. A wrong call is caught only by the human reviewing the plan.

## 10. `main.py` stops at the first failed model call; the CLI auto-approves plans

**Decided.** In `main.py`, findings are processed in order and the run ends at the first call that does not finish `ok`, with that status. The last `run_log.jsonl` line therefore always equals the run's status. The CLI supplies an explicit auto-approve policy for the plan gate (`main.py:run_session`), because the course checker runs it non-interactively and the tool only prints diffs; `--ask` puts a person there instead. A failed verification is escalated, not retried, because retrying is the person's decision. The UI supplies a real human and cannot skip the gate.
**Why.** A single status line and a matching last log line stay truthful. The gate stays in the design and is bypassed in one visible place.
**Given up.** One bad finding stops the CLI run. Findings processed before it are still reported.

## 11. Input limits are fixed before any call

**Decided.** One `.py` file, non-empty, at most 256 KiB, parsing as Python. Anything else exits 2 with no model call and no log line.
**Why.** The harness checks that empty and 1 MB inputs are refused without calling the model. 256 KiB is far below what one file of real code needs and keeps prompts bounded.
**Given up.** Very large generated files cannot be scanned.

## 12. The patcher rewrites the whole scope in code it controls, and reviews what the model returns

**Decided.** The model returns replacement source for the whole enclosing function, class or statement. Code, not the model, splices it in (re-indenting, adding imports, keeping line endings) and makes the diff, so the same inputs always give the same file. A scope over 12,000 characters is escalated without a model call. Before a person sees a patch, code repairs two known model slips only when the patch does not parse as written (JSON escaped twice, non-breaking hyphens and curly quotes), then reviews it: it compiles, every function that existed still exists with the same parameter names, order and kinds (a canned reply that renamed a pyjwt method slipped through as `pass` until this was added), it does not call methods on a parameter the original never used, it has no "assume" or TODO comment, and no docstring still names the old algorithm. If the review finds something the model is asked once to fix it, the findings passed back like a failed check, and the better of the two drafts is kept with whatever remains listed. The verifier applies the same review and returns `needs_review`, never `pass`, if a problem remains.
**Why.** The first real-model patch compiled, cleared the detector and passed the verifier while calling `private_key.export_secret_key()` and saying in a comment that it was assuming that method exists. Nothing in compile, detector or tests can catch a guess about code the model cannot see. About one in five live runs also produced code that did not compile because the model escaped its JSON twice. A bounded self-correction costs at most one extra call and keeps these out of the reviewer's way.
**Given up.** The review is a heuristic: it finds the footprints of a guess, not every guess. The self-correction is a second billable call, and it sits beside the plan's rule that retries are human-triggered: it is bounded to one, is not counted as an attempt, and only fires on static findings, never on a verifier or test failure. Docstring margins are normalised (their cleaned text is unchanged); every other multi-line string keeps its text exactly.

## 13. The orchestrator is a table of legal moves; people act, code works

**Decided.** `pq_patch/orchestrator.py` holds one record per finding and a table of which state may follow which. `Session.act` is the only entry for a person's decision and changes the state only; `Session.run_pending` does the model and verifier work that follows. A finding the model or the checks cannot finish goes to `awaiting_failure_decision` (the person can retry, revise the plan, re-check with a longer timeout, or escalate), not to a silent retry. Limits are in code: three patch attempts and three plan revisions per finding; at the third failed check the finding is escalated with the last output. A failed model step (a 429, a refusal) does not use up an attempt. A timeout is not escalated at the limit, because it may be a slow test rather than a bad patch, and can be re-checked with a longer timeout without a new patch.
**Why.** The proposal puts a human at each checkpoint, so "who may do what, when" has to be code that tests can attack, not a convention. Keeping `act` and `run_pending` apart means the UI, the CLI and the tests all run the same machine, and a page rerun can never advance a finding by accident.
**Given up.** A finding stays in `awaiting_*` until someone comes back; there is no timeout or reminder. The report lists an unfinished finding as `escalated` with a note, because the proposal's three statuses have no "pending".

## 14. A rate limit is read, not just retried

**Decided.** A 429 is classified (`pq_patch/rate_limit.py`). A short per-minute wait the provider asks for is waited out. A daily quota, or any wait longer than `LLM_MAX_RETRY_DELAY`, is not retried: the model is marked unavailable until the provider says it resets, the next of `LLM_FALLBACK_MODELS` is tried, and with none left the call ends at once and says when to try again. Three optional aids are off unless configured: pacing under `LLM_TPM_LIMIT`, a reply cache (`LLM_CACHE=1`) that stores only validated replies and validates them again on read, and planning one finding at a time in the UI.
**Why.** The first hands-on session spent three 60 s waits retrying a daily quota that would not reset for hours, then reported a cut-off message. Free tiers also give each model its own quota, so a second model is a real way to keep working. A cache makes demos and re-runs free without weakening anything: a cached reply is checked exactly like a fresh one and the verifier still runs.
**Given up.** Classification relies on the provider's wording. The cache hides run-to-run variance, so evaluation runs and the live tests turn it off. A fallback model means the code reaches a second model.

## 15. Findings are patched independently, and shared scopes are flagged

**Decided.** Each finding is planned, patched and verified against the original file. When two findings share an enclosing function, both rows carry a note that their diffs rewrite the same code, so they must be reviewed together and only one applied.
**Why.** Re-scanning and re-basing after every patch would make line numbers, plans and diffs depend on the order of approval, and the proposal's report is one row per call site.
**Given up.** Two diffs for one function can conflict, and a per-method patch can leave the rest of a class inconsistent (the hands-on session saw `sign` and `verify` patched differently). Only the project's own tests could catch that, and they need `oqs` installed or stubbed.
