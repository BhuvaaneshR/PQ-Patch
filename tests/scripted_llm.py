"""A model that returns scripted replies, for tests of the orchestrator and everything above it.

It stands in for ``StructuredLLM`` (same ``call`` signature) so the REAL planner and patcher run, with
their prompts, schema validation, splice and static review; only the model's words are scripted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from pq_patch.llm_client import LLMResult

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
VALID = json.loads((SAMPLES / "valid_response.json").read_text(encoding="utf-8"))

GOOD_PLAN = VALID["plan"]
GOOD_PATCH = VALID["patch"]  # rewrites samples/sample_input.py's sign_manifest
BAD_PATCH = {"new_source": "def sign_manifest(private_key, manifest: bytes) -> bytes:\n    return (\n", "imports": []}
ESCALATE = {"escalate": {"reason": "this key is used for key exchange, not signing"}}


class ScriptedLLM:
    """``plans`` and ``patches`` are queues. An item is a reply dict, or a status string
    ("error", "refused", "invalid_output") for a model step that fails."""

    def __init__(self, plans: Any = (), patches: Any = ()) -> None:
        self.queues = {"planner": list(plans), "patcher": list(patches)}
        self.calls: list[str] = []
        self.messages: list[list[dict]] = []

    def call(self, messages: Any, response_model: Any, purpose: str = "") -> LLMResult:
        self.calls.append(purpose)
        self.messages.append(list(messages))
        queue = self.queues[purpose]
        if not queue:
            raise AssertionError(f"the script has no more {purpose} replies")
        item = queue.pop(0)
        if isinstance(item, str):
            return LLMResult(item, None, f"scripted {item}", 1)
        key = "plan" if purpose == "planner" else "patch"
        body = item if "escalate" in item else {key: item}
        return LLMResult("ok", response_model.model_validate(body), None, 1)

    def count(self, purpose: Optional[str] = None) -> int:
        return len(self.calls) if purpose is None else self.calls.count(purpose)
