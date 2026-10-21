"""PQ-Patch UI:  streamlit run app.py

A person sits at every checkpoint. The page drafts a plan for a finding, then STOPS until the person
approves it (or asks for a revision, or escalates). Only after approval is a patch drafted, and the
verifier's verdict is shown next to the diff. Nothing is written to the analysed file.

This file never talks to a model. It drives ``pq_patch.orchestrator.Session``, the same pipeline
``main.py`` runs; every model-written string is shown as plain text, never as markdown or HTML.
"""

from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

from pq_patch.llm_client import StructuredLLM
from pq_patch.orchestrator import (
    Action,
    ActionNotAllowed,
    FindingRecord,
    InputRejected,
    Session,
    State,
    check_source,
    read_input,
)
from pq_patch.rate_limit import ReplyCache, describe_wait
from pq_patch.report import row_dict, to_csv, to_json
from pq_patch.schemas import VerificationOutcome

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "samples" / "sample_input.py"

STATE_LABEL = {
    State.DETECTED: ("found, no plan yet", "gray"),
    State.PLANNING: ("planning", "blue"),
    State.AWAITING_PLAN_APPROVAL: ("awaiting plan approval", "orange"),
    State.PATCHING: ("patching", "blue"),
    State.VERIFYING: ("verifying", "blue"),
    State.READY_FOR_REVIEW: ("ready for review", "green"),
    State.AWAITING_FAILURE_DECISION: ("needs your decision", "red"),
    State.ESCALATED: ("escalated", "violet"),
}


# --------------------------------------------------------------------------
# State kept between reruns
# --------------------------------------------------------------------------


def llm() -> StructuredLLM:
    """One client for the whole browser session, so it remembers which models are out of quota."""
    if "llm" not in st.session_state:
        st.session_state.llm = StructuredLLM(cache=None)
    return st.session_state.llm


def start(name: str, source: str, root: Path | None) -> None:
    st.session_state.session = Session(name, source, llm=llm(), project_root=root, display_name=name)
    st.session_state.generation = st.session_state.get("generation", 0) + 1


def show_error(e: Exception) -> None:
    st.error(str(e))


def run(session: Session, ids: list[int], label: str) -> None:
    with st.spinner(label):
        session.run_pending(only=ids)


def key(rec: FindingRecord, name: str) -> str:
    return f"{st.session_state.get('generation', 0)}-{rec.id}-{name}"


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------


def sidebar() -> None:
    with st.sidebar:
        st.header("PQ-Patch")
        model = os.getenv("LLM_MODEL", "") or "(not set)"
        offline = os.getenv("LLM_BASE_URL", "").startswith("local://")
        st.caption(("Offline course stub: " if offline else "Model: ") + model)

        client = llm()
        use_cache = st.toggle(
            "Reuse stored replies",
            value=client.cache is not None or os.getenv("LLM_CACHE", "").lower() in {"1", "true", "on", "yes"},
            disabled=offline,
            help="A repeated step costs no model call and no tokens. Stored replies are re-checked before use.",
        )
        client.cache = ReplyCache(os.getenv("LLM_CACHE_DIR") or ".llm_cache") if use_cache and not offline else None
        if client.cache is not None:
            st.caption(f"{client.cache.hits} reply(ies) reused this session")

        for name, seconds, daily in client.unavailable_models():
            kind = "daily quota used up" if daily else "rate limited"
            st.warning(f"{name}: {kind}. Usable again in about {describe_wait(seconds)}.")
        fallbacks = client.models()[1:]
        if fallbacks:
            st.caption("Fallback models: " + ", ".join(fallbacks))

        session = st.session_state.get("session")
        if session is not None:
            st.metric("Model calls", session.model_calls)
            if st.button("Start over", use_container_width=True):
                st.session_state.pop("session", None)
                st.rerun()


# --------------------------------------------------------------------------
# Choosing a file
# --------------------------------------------------------------------------


def choose_file() -> None:
    st.title("Post-quantum patching, with you in the loop")
    st.write(
        "Finds RSA and ECDSA signing in one Python file, drafts an ML-DSA replacement, checks it with code, "
        "and shows you a diff. Nothing is changed in your file, and no patch is drafted until you approve a plan."
    )
    upload, paste, disk, sample = st.tabs(["Upload", "Paste code", "File on disk", "Sample"])
    with upload:
        data = st.file_uploader("A .py file (at most 256 KiB)", type=["py"])
        if st.button("Analyse upload", disabled=data is None):
            try:
                start(data.name, check_source(data.getvalue(), data.name), None)
                st.rerun()
            except InputRejected as e:
                show_error(e)
    with paste:
        code = st.text_area("Python source", height=240, placeholder="paste a file here")
        if st.button("Analyse pasted code"):
            try:
                start("pasted.py", check_source(code, "pasted code"), None)
                st.rerun()
            except InputRejected as e:
                show_error(e)
    with disk:
        st.caption("Needed to run your project's own tests against each patch (in a temporary copy).")
        path = st.text_input("Path to the .py file")
        root = st.text_input("Project folder (optional; must contain the file)")
        if st.button("Analyse file on disk"):
            try:
                source = read_input(path)
                project = Path(root) if root.strip() else None
                if project is not None:
                    if not project.is_dir():
                        raise InputRejected(f"{root}: not a folder")
                    try:
                        Path(path).resolve().relative_to(project.resolve())
                    except ValueError:
                        raise InputRejected("the file is not inside the project folder") from None
                start(path, source, project)
                st.rerun()
            except InputRejected as e:
                show_error(e)
    with sample:
        st.caption("A 14-line file that signs with RSA-PSS.")
        if st.button("Use the sample"):
            start("samples/sample_input.py", SAMPLE.read_text(encoding="utf-8"), None)
            st.rerun()


# --------------------------------------------------------------------------
# One finding
# --------------------------------------------------------------------------


def verification_box(rec: FindingRecord) -> None:
    v = rec.verification
    if v is None:
        return
    ok = v.outcome is VerificationOutcome.PASS
    (st.success if ok else st.warning)(f"Verifier: {v.outcome.value}")
    st.caption(
        "compile ok" if v.compile_ok else "does not compile",
        help="Checks run by code, not by the model. A pass does not mean the patch is correct: read the diff.",
    )
    with st.expander("Verifier output"):
        st.text(v.output or "(none)")


def patch_view(rec: FindingRecord) -> None:
    pr = rec.patch_result
    if pr is None or not pr.diff:
        return
    st.code(pr.diff, language="diff")
    for n in pr.notes:
        st.caption(n)
    st.download_button("Download diff", pr.diff, file_name=diff_name_for(rec), key=key(rec, "dl"))


def diff_name_for(rec: FindingRecord) -> str:
    return f"{Path(rec.finding.file).stem}.L{rec.finding.line}.diff"


def feedback_box(rec: FindingRecord, name: str, label: str) -> str | None:
    text = st.text_area(label, key=key(rec, name), max_chars=2000, height=90)
    return text.strip() or None


def act(session: Session, rec: FindingRecord, action: Action, work: str | None = None, **kw) -> None:
    try:
        session.act(rec.id, action, **kw)
    except (ActionNotAllowed, ValueError) as e:
        show_error(e)
        return
    if work:
        run(session, [rec.id], work)
    st.rerun()


def finding_panel(session: Session, rec: FindingRecord) -> None:
    f = rec.finding
    allowed = session.allowed_actions(rec.id)
    st.caption(f"{f.algorithm.value} · `{f.qualified_name}` · in {f.enclosing_scope or 'module level'} (lines {f.scope_start_line}-{f.scope_end_line})")
    for note in rec.notes:
        st.info(note)

    if rec.state is State.DETECTED:
        st.write("No model call has been made for this finding yet.")
        if st.button("Draft a plan", key=key(rec, "plan")):
            run(session, [rec.id], "Asking the model for a plan...")
            st.rerun()

    if rec.plan is not None and rec.state is not State.ESCALATED:
        st.subheader("Plan")
        st.text(f"Target: {rec.plan.target_algorithm}\n\n{rec.plan.approach}")
        if rec.plan.interface_notes:
            st.text("Interface: " + rec.plan.interface_notes)
        for risk in rec.plan.risks:
            st.text("Risk: " + risk)

    if rec.state is State.AWAITING_PLAN_APPROVAL:
        st.warning("Waiting for you. No patch is drafted until you approve this plan.")
        if st.button("Approve plan and draft the patch", type="primary", key=key(rec, "approve")):
            act(session, rec, Action.APPROVE_PLAN, "Drafting and checking the patch...")
        if Action.REVISE_PLAN in allowed:
            text = feedback_box(rec, "rev", "Ask for a different plan (what should change?)")
            if st.button("Revise plan", key=key(rec, "revise"), disabled=not text):
                act(session, rec, Action.REVISE_PLAN, "Asking the model for a revised plan...", feedback=text)

    if rec.state in (State.READY_FOR_REVIEW, State.AWAITING_FAILURE_DECISION) or (rec.state is State.ESCALATED and rec.patch_result):
        st.subheader("Patch")
        patch_view(rec)
        verification_box(rec)

    if rec.state is State.READY_FOR_REVIEW:
        st.success("All automated checks passed. A person still has to read the diff.")
        if Action.RETRY in allowed:
            text = feedback_box(rec, "chg", "Ask for changes (what should be different?)")
            if st.button("Request changes", key=key(rec, "chg-go"), disabled=not text):
                act(session, rec, Action.RETRY, "Drafting a new patch...", feedback=text)

    if rec.state is State.AWAITING_FAILURE_DECISION and rec.failure is not None:
        st.error(f"The {rec.failure.stage} step ended: {rec.failure.kind}")
        st.text(rec.failure.detail[:1500])
        if Action.REVERIFY in allowed:
            seconds = st.number_input("Test timeout (seconds)", 5, 300, int(rec.test_timeout), key=key(rec, "to"))
            if st.button("Run the checks again on this patch", key=key(rec, "reverify")):
                act(session, rec, Action.REVERIFY, "Re-running the checks...", test_timeout=float(seconds))
        if Action.RETRY in allowed:
            text = feedback_box(rec, "guide", "Guidance for the next attempt (optional)")
            label = "Retry the " + ("plan" if rec.failure.stage == "plan" else "patch")
            if st.button(label, key=key(rec, "retry")):
                act(session, rec, Action.RETRY, "Asking the model again...", feedback=text)
        if Action.REVISE_PLAN in allowed:
            text = feedback_box(rec, "rev2", "Or ask for a different plan (what should change?)")
            if st.button("Revise plan", key=key(rec, "revise2"), disabled=not text):
                act(session, rec, Action.REVISE_PLAN, "Asking the model for a revised plan...", feedback=text)

    if rec.state is State.ESCALATED:
        st.info("Escalated to a person: " + (rec.escalation_reason or ""))

    if rec.attempt_log:
        with st.expander(f"Attempts ({rec.attempts}/{session.max_attempts})"):
            for a in rec.attempt_log:
                st.text(f"Attempt {a.number}: {a.verification.value if a.verification else 'not verified'}")
    with st.expander("History"):
        for e in rec.history:
            st.text(f"{e.time[11:19]}  {e.to_state.value}: {e.why}")

    if Action.ESCALATE in allowed:
        reason = st.text_input("Reason for escalating (optional)", key=key(rec, "why"), max_chars=300)
        if st.button("Escalate to a person", key=key(rec, "esc")):
            act(session, rec, Action.ESCALATE, feedback=reason or None)


# --------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------


def results(session: Session) -> None:
    rows = session.report_rows()
    st.dataframe(
        [{k: v for k, v in row_dict(r).items() if k != "proposed_patch"} for r in rows],
        use_container_width=True,
        hide_index=True,
    )
    left, right = st.columns(2)
    left.download_button("Download report.json", to_json(rows), file_name="report.json", mime="application/json")
    right.download_button("Download report.csv", to_csv(rows), file_name="report.csv", mime="text/csv")
    unfinished = [r.id for r in session.records if r.state not in (State.READY_FOR_REVIEW, State.ESCALATED)]
    if unfinished:
        st.caption("Findings still waiting for you are listed as escalated with a note until you decide: " + ", ".join(f"#{i}" for i in unfinished))


def show_session(session: Session) -> None:
    st.title(session.display_name)
    if session.scan_error:
        st.error("This file does not parse: " + session.scan_error)
        return
    if not session.records:
        st.success("No RSA or ECDSA signing calls were found. Nothing to do, and no model call was made.")
        results(session)
        return

    ready = sum(r.state is State.READY_FOR_REVIEW for r in session.records)
    escalated = sum(r.state is State.ESCALATED for r in session.records)
    a, b, c, d = st.columns(4)
    a.metric("Findings", len(session.records))
    b.metric("Waiting for you", len(session.waiting))
    c.metric("Ready for review", ready)
    d.metric("Escalated", escalated)
    if session.run_status not in (None, "ok"):
        st.error(f"The last model step ended: {session.run_status}")

    undrafted = [r.id for r in session.records if r.state is State.DETECTED]
    if undrafted and st.button(f"Draft plans for all {len(undrafted)} undrafted finding(s)"):
        run(session, undrafted, "Asking the model for plans...")
        st.rerun()

    findings_tab, report_tab = st.tabs(["Findings", "Report"])
    with findings_tab:
        for rec in session.records:
            label, colour = STATE_LABEL[rec.state]
            with st.expander(f"#{rec.id}  line {rec.finding.line}  {rec.finding.original_call}  :{colour}[{label}]", expanded=len(session.records) == 1 or rec.state in (State.AWAITING_PLAN_APPROVAL, State.AWAITING_FAILURE_DECISION)):
                finding_panel(session, rec)
    with report_tab:
        results(session)


def main() -> None:
    st.set_page_config(page_title="PQ-Patch", layout="wide")
    sidebar()
    session = st.session_state.get("session")
    if session is None:
        choose_file()
    else:
        show_session(session)


main()
