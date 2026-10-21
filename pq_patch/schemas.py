"""Pydantic data contracts shared by every PQ-Patch module (M2).

LLM-produced objects (Plan, Patch) are validated here so that anything outside
the allowed shape is rejected before a human ever sees it. Verification and
report objects are produced by deterministic code, and carry consistency
checks so an inconsistent result (e.g. "pass" with a failed compile) cannot be
constructed.

Scope: RSA and ECDSA *signing* only, replaced by ML-DSA. Key exchange / KEM,
DSA, DH and encryption are out of scope and are escalated, never patched.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _Model(BaseModel):
    """Base: reject unknown fields so malformed LLM output fails loudly."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------


class Algorithm(str, Enum):
    """Classical algorithm family, assigned by the deterministic detector."""

    RSA = "RSA"
    EC = "EC"  # generic elliptic-curve key; whether it signs is decided by usage, not by the call
    ECDSA = "ECDSA"


class UsageContext(str, Enum):
    """How the key is used at a call site (decided by the planner)."""

    SIGNING = "signing"
    OTHER = "other"  # not signing (e.g. key exchange, encryption): out of scope


class VerificationOutcome(str, Enum):
    PASS = "pass"
    FAILED_COMPILE = "failed_compile"
    FAILED_TEST = "failed_test"
    FAILED_TEST_TIMEOUT = "failed_test(timeout)"  # tests started but did not finish in time
    NEEDS_REVIEW = "needs_review"


class FindingStatus(str, Enum):
    READY_FOR_REVIEW = "ready_for_review"
    ESCALATED = "escalated"
    NO_ACTION_NEEDED = "no_action_needed"


# Replacement algorithms the agent is allowed to propose.
ML_DSA_ALGORITHMS = frozenset({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
ALLOWED_TARGETS = ML_DSA_ALGORITHMS


# --------------------------------------------------------------------------
# Detector output (M1)
# --------------------------------------------------------------------------


class Finding(_Model):
    """One quantum-vulnerable call site located by the detector."""

    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    column: int = Field(ge=0)
    original_call: str = Field(min_length=1, description="Call as written in source, e.g. 'rsa.generate_private_key'")
    qualified_name: str = Field(
        min_length=1, description="Import-resolved name, stable across line shifts and aliases"
    )
    algorithm: Algorithm
    enclosing_scope: Optional[str] = Field(
        default=None, description="Name of the enclosing function/class, or None at module level"
    )
    scope_start_line: int = Field(ge=1)
    scope_end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def _check_ranges(self) -> "Finding":
        if self.end_line < self.line:
            raise ValueError("end_line must be >= line")
        if not (self.scope_start_line <= self.line and self.end_line <= self.scope_end_line):
            raise ValueError("call site must lie within its enclosing scope range")
        return self


class FileScanResult(_Model):
    """Per-file detector result. Unparseable files are reported, never skipped."""

    file: str = Field(min_length=1)
    parse_ok: bool
    parse_error: Optional[str] = None
    findings: list[Finding] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_consistency(self) -> "FileScanResult":
        if not self.parse_ok:
            if not self.parse_error:
                raise ValueError("unparseable file must carry a parse_error")
            if self.findings:
                raise ValueError("unparseable file cannot have findings")
        elif self.parse_error:
            raise ValueError("parse_error set on a file that parsed")
        return self


# --------------------------------------------------------------------------
# LLM output (M4, M5) - strictly validated
# --------------------------------------------------------------------------


class Plan(_Model):
    """Replacement plan for one call site, drafted by the planner."""

    usage_context: UsageContext
    target_algorithm: str

    @field_validator("target_algorithm", mode="before")
    @classmethod
    def _ascii_hyphens(cls, value: object) -> object:
        # Real models often emit non-breaking hyphens (U+2011) and other dashes in names such as
        # "ML-DSA-65". They mean the same thing, so normalise them before the allow-list check.
        if isinstance(value, str):
            return re.sub("[‐‑‒–—−]", "-", value).strip()
        return value
    approach: str = Field(min_length=10, max_length=2000)
    interface_notes: str = Field(
        default="", max_length=1000, description="How the surrounding signature/interface is preserved"
    )
    risks: list[str] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def _check_target(self) -> "Plan":
        if self.target_algorithm not in ALLOWED_TARGETS:
            raise ValueError(f"target_algorithm must be one of {sorted(ALLOWED_TARGETS)}")
        if self.usage_context is not UsageContext.SIGNING:
            raise ValueError("only signing is in scope; a non-signing call site must be escalated, not planned")
        return self


class Escalation(_Model):
    """The planner's way of saying a call site is out of scope or unclear (not signing)."""

    reason: str = Field(min_length=5, max_length=1000)


class PlanReply(BaseModel):
    """What the planner call returns: exactly one of ``plan`` or ``escalate``.

    This is an envelope. It ignores unknown top-level keys, because the course stub
    returns one shared reply (``{"plan": ..., "patch": ...}``) for every call and each
    stage reads only its own key. ``Plan`` and ``Escalation`` stay strict.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    plan: Optional[Plan] = None
    escalate: Optional[Escalation] = None

    @model_validator(mode="after")
    def _exactly_one(self) -> "PlanReply":
        if (self.plan is None) == (self.escalate is None):
            raise ValueError("reply must contain exactly one of 'plan' or 'escalate'")
        return self


_IMPORT_RE = re.compile(r"^(import\s+[\w.]+(\s+as\s+\w+)?|from\s+[\w.]+\s+import\s+[\w*,\s()]+)$")


class Patch(_Model):
    """Replacement source for the enclosing scope of a finding, drafted by the patcher.

    Syntax is deliberately NOT checked here: a syntactically broken patch must
    reach the deterministic verifier and surface as ``failed_compile``.
    """

    new_source: str = Field(min_length=1, max_length=20000)
    imports: list[str] = Field(default_factory=list, max_length=10)
    explanation: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def _check_imports(self) -> "Patch":
        for stmt in self.imports:
            if "\n" in stmt or not _IMPORT_RE.match(stmt.strip()):
                raise ValueError(f"not a single import statement: {stmt!r}")
        return self


# --------------------------------------------------------------------------
# Verifier output (M6) - produced by deterministic code only
# --------------------------------------------------------------------------


class VerificationResult(_Model):
    outcome: VerificationOutcome
    compile_ok: bool
    detector_clear: Optional[bool] = Field(
        default=None, description="Original pattern gone and no new findings; None if not evaluated"
    )
    tests_ran: bool = False
    tests_passed: Optional[bool] = None
    output: str = Field(default="", description="Compiler/detector/test output for the human reviewer")

    @model_validator(mode="after")
    def _check_consistency(self) -> "VerificationResult":
        if self.tests_ran and self.tests_passed is None:
            raise ValueError("tests_passed must be set when tests_ran is True")
        if not self.tests_ran and self.tests_passed is not None:
            raise ValueError("tests_passed set although tests did not run")
        if self.outcome is VerificationOutcome.PASS:
            if not (self.compile_ok and self.detector_clear is True and self.tests_passed is not False):
                raise ValueError("'pass' requires compile ok, detector clear and no failing tests")
        if self.outcome is VerificationOutcome.FAILED_COMPILE and self.compile_ok:
            raise ValueError("'failed_compile' requires compile_ok=False")
        if self.outcome is VerificationOutcome.FAILED_TEST and self.tests_passed is not False:
            raise ValueError("'failed_test' requires tests_passed=False")
        if self.outcome is VerificationOutcome.FAILED_TEST_TIMEOUT and not (self.tests_ran and self.tests_passed is False):
            raise ValueError("'failed_test(timeout)' requires tests_ran=True and tests_passed=False")
        return self


# --------------------------------------------------------------------------
# Final output (M8)
# --------------------------------------------------------------------------


class ReportRow(_Model):
    """One row of the final report: the nine output fields from the proposal."""

    file: str = Field(min_length=1)
    line: Optional[int] = Field(default=None, ge=1)
    original_call: Optional[str] = None
    target_algorithm: Optional[str] = None
    proposed_patch: Optional[str] = Field(default=None, description="Unified diff")
    verification_result: Optional[VerificationOutcome] = None
    attempts: int = Field(default=0, ge=0)
    status: FindingStatus
    notes: str = ""

    @model_validator(mode="after")
    def _check_status(self) -> "ReportRow":
        if self.target_algorithm is not None and self.target_algorithm not in ALLOWED_TARGETS:
            raise ValueError(f"target_algorithm must be one of {sorted(ALLOWED_TARGETS)}")
        if self.status is FindingStatus.NO_ACTION_NEEDED:
            if self.proposed_patch or self.attempts or self.verification_result is not None:
                raise ValueError("no_action_needed must not carry a patch, attempts or verification result")
        elif self.status is FindingStatus.READY_FOR_REVIEW:
            if not self.proposed_patch:
                raise ValueError("ready_for_review requires a proposed_patch")
            if self.verification_result is not VerificationOutcome.PASS:
                raise ValueError("ready_for_review requires verification_result == pass")
            if self.attempts < 1:
                raise ValueError("ready_for_review requires attempts >= 1")
        elif self.status is FindingStatus.ESCALATED:
            if self.verification_result is VerificationOutcome.PASS:
                raise ValueError("escalated cannot carry a passing verification_result")
            if not self.notes:
                raise ValueError("escalated requires a note stating the reason")
        return self
