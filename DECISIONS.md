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

## 10. `main.py` stops at the first failed model call; the CLI auto-approves plans (planned)

**Decided.** In `main.py`, findings are processed in order and the run ends at the first call that does not finish `ok`, with that status. The last `run_log.jsonl` line therefore always equals the run's status. The CLI supplies an explicit auto-approve policy for the plan gate, because the course checker runs it non-interactively and the tool only prints diffs. The UI supplies a real human and cannot skip the gate.
**Why.** A single status line and a matching last log line stay truthful. The gate stays in the design and is bypassed in one visible place.
**Given up.** One bad finding stops the CLI run. Findings processed before it are still reported.

## 11. Input limits are fixed before any call

**Decided.** One `.py` file, non-empty, at most 256 KiB, parsing as Python. Anything else exits 2 with no model call and no log line.
**Why.** The harness checks that empty and 1 MB inputs are refused without calling the model. 256 KiB is far below what one file of real code needs and keeps prompts bounded.
**Given up.** Very large generated files cannot be scanned.
