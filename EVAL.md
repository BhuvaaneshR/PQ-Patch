<!--
  EVAL.md - does your app actually work?

  It shows two things:
    1. You can say what "correct" means for your app. Each row is an input and
       WHAT MUST BE TRUE about the answer: the facts that matter, never the
       exact words. If you could write the exact output in advance, you would
       not need a model.
    2. You are honest about where it fails: at least three known failures,
       each explained.

  There is no fixed number of rows. Cover each of the five kinds below at
  least once (start from the three examples in section 9 of your brief), then
  keep adding rows until three of them fail. Most people end up with around
  eight.

  Run your rows against your REAL model, not the stub. The stub tells you that
  you survive; a real model tells you whether you are right.

  Delete these comments before you tag.
-->

# What this set covers

<!-- One short paragraph: which inputs, which model and provider, which date. -->

# The rows

| # | Kind | Input | What must be true | Result |
|---|---|---|---|---|
| 1 | Ordinary |  |  |  |
| 2 | Unusual but legitimate |  |  |  |
| 3 | Nothing wrong |  |  |  |
| 4 | Malformed or empty |  |  |  |
| 5 | Injected (your `injected_input`) |  |  |  |

# Metrics

<!-- One small table. Numbers from your run_log.jsonl. On a free tier, say $0 and
     give the list-price figure too, and say where the prices came from. -->

| Metric | Value | Where it comes from |
|---|---|---|
| Accuracy | __ of __ rows pass (model and date) | Your rows |
| Speed |  | `latency_ms` in `run_log.jsonl` |
| Cost |  | Token counts in `run_log.jsonl`, times your provider's prices |

# Known failures

<!-- At least three. For each, four short parts:
     what happened (with the row number), why, the fix, and why you did not do it. -->

# What this set does not cover

<!-- A few honest lines on what your rows cannot tell anyone. -->
