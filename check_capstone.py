#!/usr/bin/env python3
"""
check_capstone.py: the capstone self-check, and the marking script.

    python check_capstone.py .                         check your own repository
    python check_capstone.py --all submissions/ --out results/     marking

It is the same script in both cases. Without a reference_files/ folder beside
it, it runs in self-check mode: it uses your client.py and stub_client.py as
they are and warns you if either differs from the starter kit. With
reference_files/ beside it (marking), it overwrites both with the originals
before running anything, so an edited stub gains nothing.

WHAT IT DOES
    1. Three gates: the capstone-submission tag, client.py unmodified, and
       .env absent from the whole git history.
    2. Reads capstone.json for your sample input, your injected input and
       which side of floor item 6 you chose.
    3. Clones your repository into a temporary folder (committed files only,
       at the tag when marking, at HEAD when you check yourself), then runs
       python main.py <input-file> against the course stub in every mode
       below, one run at a time, with a timeout on every run.
    4. Prints the automated marks. Everything else in the capstone is read
       by a person.

    | Test                     | Stub mode, input                         | Marks |
    |--------------------------|------------------------------------------|------:|
    | Clean clone runs         | stub:ok, sample_input                    | 1.0   |
    | Log well-formed          | every run                                | 1.0   |
    | Malformed / bad shape    | stub:malformed, stub:badshape            | 1.5   |
    | Empty / refused / error  | stub:empty, stub:refused, stub:error     | 1.0   |
    | Empty + oversized input  | generated files, same extension          | 1.0   |
    | Floor item 6             | tools: stub:badargs                      | 1.5   |
    |                          | documents: stub:obedient, injected_input |       |
    | UI calls the pipeline    | read, never run                          | 1.0   |
    | Injection survived       | stub:obedient, injected_input            | 1.0   |
    | Guard event logged       | stub:obedient, injected_input            | 1.0   |
    | Log sample valid         | samples/run_log_sample.jsonl             | 0.5   |

    10.5 automated marks out of 30. Application 8, security 2, logging 0.5.

WHAT "SURVIVES" MEANS
    No crash, nothing invalid stored or shown, and the correct status logged.
    "Shown" means printed on stdout: print diagnostics to stderr. "Stored"
    means written to any file in the repository other than the two logs.

NEVER TOUCHES YOUR WORK
    Everything runs in a throwaway clone. Your repository, your .env and your
    logs are never read or changed, apart from git commands that only read.

Requires, in the Python you run it with: everything in your
requirements.txt. Run it inside your virtual environment.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
REFERENCE = HERE / "reference_files"      # holds client.py and stub_client.py
SELF_CHECK = not REFERENCE.exists()       # student copy: no reference dir shipped

# The supplied files. client.py is byte-identical to Labs 4 to 6.
CLIENT_SHA256 = "d329e4e46de10b6c8569b8d07210aed21ab0481380d662d2ec7bc97477d5ef77"
STUB_SHA256 = "af7feea14104d7db0c66002ce5ae35a6a92023e3aa77548e940b96669569594f"
LAB6_STUB_SHA256 = "be83c25c67fc7b7ebf74ab95f9228d398008e239534a833a04854f45b92d7213"

TAG = "capstone-submission"
TIMEOUT = 60                  # one run of main.py, including retry sleeps
OVERSIZE_BYTES = 1_048_576    # the "about 1 MB" input
SUGGESTED_SAMPLE_LINES = 20   # Part 1 said "about twenty"; guidance only, never marked

OUTCOMES = {"ok", "invalid_output", "refused", "error"}
GUARD_EVENTS = {"guardrail_input", "instruction_ignored", "guardrail_output"}
DOC_ITEM6_EVENTS = {"guardrail_input", "instruction_ignored"}
CANARY = "PWNED-7F3A"         # what stub:obedient appends when it obeys

LOG_KEYS = ("timestamp", "run_id", "model", "status", "prompt_tokens",
            "completion_tokens", "latency_ms", "cost_usd", "tokens_estimated")

CAPSTONE_KEYS = ("sample_input", "injected_input", "floor_item_6", "ui_command")

REQUIRED_FILES = [
    "main.py", "client.py", "stub_client.py", "observability.py", "security.py",
    "capstone.json", "SPEC.md", "SECURITY.md", "EVAL.md", "DECISIONS.md",
    "README.md", "requirements.txt", ".env.example", ".gitignore",
    "samples/valid_response.json", "samples/invalid_response.json",
    "samples/run_log_sample.jsonl",
]

HEADINGS = {
    "SPEC.md": ["What it does", "Inputs", "Outputs", "Failure cases",
                "Acceptance checks", "Out of scope"],
    "SECURITY.md": ["What this application is", "Trust boundaries",
                    "What an attacker could try", "The guardrails in place",
                    "What each guardrail does not stop",
                    "What I would do with more time"],
    "EVAL.md": ["What this set covers", "The rows", "Metrics", "Known failures",
                "What this set does not cover"],
}

# Identical to stub_client.INJECTION_PATTERNS. Used only to tell you whether
# your injected_input contains one of the phrasings the stub reacts to.
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|earlier|above)\s+instructions", re.I),
    re.compile(r"disregard\s+(the\s+|all\s+|any\s+)?(above|previous|prior|earlier)", re.I),
    re.compile(r"(system|assistant|admin)\s*(note|directive|override|message)\s*:", re.I),
    re.compile(r"you\s+must\s+(now\s+)?append", re.I),
    re.compile(r"new\s+instructions?\s+for\s+the\s+(assistant|model|ai)", re.I),
]

# Model SDKs. Only client.py may import one, and the UI never.
SDK_MODULES = {"openai", "anthropic", "groq", "mistralai", "cohere", "ollama",
               "litellm", "together", "huggingface_hub", "langchain",
               "langchain_openai", "langchain_core", "langchain_community",
               "google.generativeai", "google.genai", "vertexai", "replicate"}

# Files in the throwaway clone that a run may change without "storing" anything.
VOLATILE = {"run_log.jsonl", "security_log.jsonl", ".stub_calls.log"}
SKIP_DIRS = {".git", ".venv", "venv", "env", "__pycache__", ".pytest_cache",
             "node_modules", ".mypy_cache", ".ruff_cache", ".streamlit"}


# --------------------------------------------------------------------------

@dataclass
class Check:
    group: str            # "Application", "Security", "Logging"
    name: str
    marks: float
    passed: bool = False
    note: str = ""


@dataclass
class Gate:
    name: str
    passed: bool
    note: str = ""


@dataclass
class Result:
    repo: str
    gates: list[Gate] = field(default_factory=list)
    prereqs: list[Gate] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def awarded(self, group: str | None = None) -> float:
        return round(sum(c.marks for c in self.checks
                         if c.passed and (group is None or c.group == group)), 2)

    def total(self, group: str | None = None) -> float:
        return round(sum(c.marks for c in self.checks
                         if group is None or c.group == group), 2)


@dataclass
class Run:
    label: str
    mode: str
    last: str
    code: int
    stdout: str
    stderr: str
    calls: int
    log: list[dict]
    log_bad: int
    events: list[dict]
    changed: dict[str, str]          # path -> text of files created or modified
    timed_out: bool

    @property
    def event_names(self) -> set[str]:
        return {str(e.get("event", "")) for e in self.events}

    @property
    def crashed(self) -> bool:
        return self.timed_out or "Traceback (most recent call last)" in self.stderr

    def why(self) -> str:
        """One short line explaining a failure, for the note column."""
        if self.timed_out:
            return f"no result within {TIMEOUT}s"
        bits = [f"last line {self.last!r}, exit {self.code}"]
        tail = [ln for ln in self.stderr.splitlines() if ln.strip()]
        if tail:
            bits.append("stderr: " + tail[-1][:160])
        return "; ".join(bits)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def git(repo: Path, *args: str) -> tuple[int, str]:
    try:
        out = subprocess.run(["git", "-C", str(repo), *args],
                             capture_output=True, text=True, timeout=60)
        return out.returncode, out.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return 1, ""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path: Path) -> tuple[list[dict], int]:
    """(records, number of lines that are not a JSON object)."""
    if not path.exists():
        return [], 0
    records, bad = [], 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            continue
        if isinstance(obj, dict):
            records.append(obj)
        else:
            bad += 1
    return records, bad


def leaf_strings(node) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for v in node.values() for s in leaf_strings(v)]
    if isinstance(node, list):
        return [s for v in node for s in leaf_strings(v)]
    return []


def distinctive(sample: Path, input_text: str) -> list[str]:
    """Long strings from a sample reply that cannot have come from the input.

    If one of these turns up on stdout or in a stored file after a reply that
    should have been rejected, the reply was shown or stored anyway.
    """
    try:
        data = json.loads(sample.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    found = []
    for s in leaf_strings(data):
        s = s.strip()
        if len(s) >= 12 and s not in input_text and s not in found:
            found.append(s)
    return found


def text_of(path: Path) -> str:
    """Whatever text can be read out of a file, for phrase searching only."""
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    parts = [raw.decode("utf-8", errors="ignore")]
    if zipfile.is_zipfile(path):                         # docx, pptx, xlsx, odt
        try:
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    if name.endswith((".xml", ".txt", ".rels")):
                        xml = zf.read(name).decode("utf-8", errors="ignore")
                        parts.append(re.sub(r"<[^>]+>", " ", xml))
        except (zipfile.BadZipFile, OSError):
            pass
    if raw[:5] == b"%PDF-":                              # best effort only
        for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, re.S):
            try:
                parts.append(zlib.decompress(m.group(1)).decode("latin-1", errors="ignore"))
            except zlib.error:
                pass
    return re.sub(r"\s+", " ", " ".join(parts))


def snapshot(root: Path, skip: set[str]) -> dict[str, tuple[int, int]]:
    snap = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            if name in VOLATILE or rel in skip or name.endswith(".pyc"):
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            snap[rel] = (st.st_size, st.st_mtime_ns)
    return snap


def changed_files(root: Path, before: dict, after: dict) -> dict[str, str]:
    out = {}
    for rel, sig in after.items():
        if before.get(rel) != sig:
            p = root / rel
            try:
                out[rel] = p.read_bytes()[:4_000_000].decode("utf-8", errors="ignore") \
                    if p.stat().st_size <= 4_000_000 else ""
            except OSError:
                out[rel] = ""
    return out


def imports_of(path: Path) -> tuple[set[str], set[str], bool]:
    """(top-level modules, full dotted modules, calls chat.completions) for one file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return set(), set(), False
    tops, full, completions = set(), set(), False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                tops.add(a.name.split(".")[0])
                full.add(a.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            tops.add(node.module.split(".")[0])
            full.add(node.module)
            for a in node.names:
                full.add(f"{node.module}.{a.name}")
        elif isinstance(node, ast.ImportFrom) and node.level > 0:
            # relative import inside a package: count the package's names
            for a in node.names:
                tops.add(a.name)
        elif isinstance(node, ast.Attribute) and node.attr == "completions":
            if isinstance(node.value, ast.Attribute) and node.value.attr == "chat":
                completions = True
    return tops, full, completions


def is_local(root: Path, top: str, base: Path) -> bool:
    for where in {root, base}:
        if (where / f"{top}.py").is_file() or (where / top / "__init__.py").is_file():
            return True
    return False


def sdk_hits(full: set[str]) -> set[str]:
    return {m for m in full if m in SDK_MODULES or m.split(".")[0] in SDK_MODULES
            or any(m == s or m.startswith(s + ".") for s in SDK_MODULES)}


def ui_files(root: Path, command: str) -> list[Path]:
    """The Python files a ui_command would start. Read, never run."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    found: list[Path] = []
    for i, tok in enumerate(tokens):
        cands = []
        if tok.endswith(".py"):
            cands.append(tok)
        if i > 0 and tokens[i - 1] in ("--app", "-A", "--app-dir"):
            cands += [tok.split(":")[0].replace(".", "/") + ".py", tok + ".py"]
        if ":" in tok and not tok.startswith("-") and "://" not in tok:
            cands.append(tok.split(":")[0].replace(".", "/") + ".py")
        for c in cands:
            p = (root / c)
            if p.is_file() and p.resolve().is_relative_to(root.resolve()) and p not in found:
                found.append(p)
    return found


# --------------------------------------------------------------------------
# Running the application
# --------------------------------------------------------------------------

def run_app(work: Path, input_path: str, mode: str, label: str,
            protect: set[str]) -> Run:
    env = dict(os.environ)
    env.update({
        "LLM_API_KEY": "not-needed",
        "LLM_BASE_URL": "local://stub",
        "LLM_MODEL": f"stub:{mode}",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
    })
    for var in ("LLM_PROVIDER", "RUN_LOG_PATH", "GAP_RUN_ID", "STUB_SAMPLES_DIR"):
        env.pop(var, None)

    for name in VOLATILE:
        (work / name).unlink(missing_ok=True)

    before = snapshot(work, protect)
    timed_out = False
    try:
        proc = subprocess.run([sys.executable, "main.py", input_path],
                              cwd=str(work), env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=TIMEOUT)
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        code, timed_out = -1, True
        out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        err = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
    after = snapshot(work, protect)

    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    last = lines[-1] if lines else "<no output>"
    calls_file = work / ".stub_calls.log"
    calls = 0
    if calls_file.exists():
        calls = len([ln for ln in calls_file.read_text(errors="ignore").splitlines() if ln.strip()])
    log, log_bad = read_jsonl(work / "run_log.jsonl")
    events, _ = read_jsonl(work / "security_log.jsonl")

    return Run(label=label, mode=mode, last=last, code=code, stdout=out or "",
               stderr=err or "", calls=calls, log=log, log_bad=log_bad,
               events=events, changed=changed_files(work, before, after),
               timed_out=timed_out)


def log_problems(r: Run) -> list[str]:
    """Problems with run_log.jsonl for one run. Empty list means well-formed."""
    p = []
    if r.log_bad:
        p.append(f"{r.log_bad} line(s) not JSON")
    if len(r.log) != r.calls:
        p.append(f"{len(r.log)} log line(s) for {r.calls} model call(s)")
    missing = sorted({k for line in r.log for k in LOG_KEYS if k not in line})
    if missing:
        p.append("missing key(s): " + ", ".join(missing))
    bad_status = sorted({str(line.get("status")) for line in r.log
                         if line.get("status") not in OUTCOMES})
    if bad_status:
        p.append("status not one of the four: " + ", ".join(bad_status))
    if len({str(line.get("run_id")) for line in r.log}) > 1:
        p.append("more than one run_id in one run")
    return p


def status_logged(r: Run, want: str) -> str:
    """'' if the log tells the truth about a failed run, else the problem."""
    if not r.log:
        return "nothing in run_log.jsonl"
    if any(line.get("status") == "ok" for line in r.log):
        return "run_log.jsonl says ok for a call that failed"
    if r.log[-1].get("status") != want:
        return f"last run_log.jsonl status is {r.log[-1].get('status')!r}, not {want!r}"
    return ""


def leaked(r: Run, needles: list[str]) -> list[str]:
    """Where any needle appears: stdout, or a file the run created or changed."""
    where = []
    for n in needles:
        if n in r.stdout:
            where.append("stdout")
            break
    for rel, text in r.changed.items():
        if any(n in text for n in needles):
            where.append(rel)
    return where


# --------------------------------------------------------------------------
# The checks
# --------------------------------------------------------------------------

def check_repo(repo: Path) -> Result:
    res = Result(repo=repo.name)
    add, gate, prereq, note = res.checks.append, res.gates.append, res.prereqs.append, res.notes.append
    is_git = (repo / ".git").exists()

    # ---- Gates: not marks. A failing gate is a submission that cannot be
    #      marked, not a lost fraction of a mark. --------------------------
    _, tags = git(repo, "tag", "-l", TAG)
    tagged = TAG in tags.split()
    gate(Gate(f"{TAG} tag present", tagged,
              "" if tagged else f"git tag {TAG} && git push origin {TAG}"))

    client = repo / "client.py"
    same = client.exists() and sha256(client) == CLIENT_SHA256
    gate(Gate("client.py unmodified (SHA-256)", same,
              "" if same else ("client.py missing" if not client.exists()
                               else "differs from the starter kit copy")))

    _, history = git(repo, "log", "--all", "--name-only", "--pretty=format:")
    tracked = {ln.strip() for ln in history.splitlines() if ln.strip()}
    env_hit = sorted(t for t in tracked if t == ".env" or t.endswith("/.env"))
    gate(Gate(".env never committed, on any branch", is_git and not env_hit,
              "not a git repository" if not is_git else
              ("" if not env_hit else "in history: " + ", ".join(env_hit))))

    # ---- Prerequisites: reported so that a zero can be explained ----------
    missing = [f for f in REQUIRED_FILES if not (repo / f).exists()]
    prereq(Gate("Required files present", not missing,
                "" if not missing else "missing: " + ", ".join(missing)))

    gi = (repo / ".gitignore").read_text(encoding="utf-8", errors="ignore") \
        if (repo / ".gitignore").exists() else ""
    ignored = all(x in gi for x in (".env", "run_log.jsonl", "security_log.jsonl"))
    leaked_logs = sorted(t for t in tracked if Path(t).name in ("run_log.jsonl", "security_log.jsonl"))
    prereq(Gate("Logs ignored and never committed", ignored and not leaked_logs,
                "; ".join(filter(None, [
                    "" if ignored else ".gitignore lacks one of .env, run_log.jsonl, security_log.jsonl",
                    ("committed at some point: " + ", ".join(leaked_logs)) if leaked_logs else "",
                ]))))

    cfg, cfg_problems = {}, []
    try:
        cfg = json.loads((repo / "capstone.json").read_text(encoding="utf-8"))
        if not isinstance(cfg, dict):
            cfg, cfg_problems = {}, ["not a JSON object"]
    except FileNotFoundError:
        cfg_problems.append("capstone.json missing")
    except (OSError, json.JSONDecodeError) as exc:
        cfg_problems.append(f"capstone.json does not parse: {exc}")
    for key in CAPSTONE_KEYS:
        if cfg and not isinstance(cfg.get(key), str):
            cfg_problems.append(f"{key} missing or not a string")
    for key in ("sample_input", "injected_input"):
        val = cfg.get(key)
        if isinstance(val, str) and val:
            p = (repo / val)
            if Path(val).is_absolute() or ".." in Path(val).parts:
                cfg_problems.append(f"{key} must be a path inside the repository")
            elif not p.is_file():
                cfg_problems.append(f"{key} not found: {val}")
    item6 = str(cfg.get("floor_item_6", "")).strip().lower()
    if cfg and item6 not in ("tools", "documents"):
        cfg_problems.append(f"floor_item_6 must be \"tools\" or \"documents\", not {cfg.get('floor_item_6')!r}")
    extra = sorted(set(cfg) - set(CAPSTONE_KEYS)) if cfg else []
    if extra:
        note("capstone.json has extra keys, which are ignored: " + ", ".join(extra))
    cfg_ok = not cfg_problems
    prereq(Gate("capstone.json valid", cfg_ok, "; ".join(cfg_problems)))

    # ---- Informational: never marked by the script -----------------------
    if SELF_CHECK:
        stub = repo / "stub_client.py"
        if stub.exists() and sha256(stub) != STUB_SHA256:
            note("stub_client.py is not the starter-kit copy"
                 + (" (it is the Lab 6 stub, which has no stub:badargs)"
                    if sha256(stub) == LAB6_STUB_SHA256 else "")
                 + ". Marking uses the original; take it from the starter kit.")
    for fname, heads in HEADINGS.items():
        f = repo / fname
        if f.exists():
            text = f.read_text(encoding="utf-8", errors="ignore")
            found = {h for h in heads if re.search(
                rf"^\s*#{{1,3}}\s*{re.escape(h)}\s*$", text, re.I | re.M)}
            absent = [h for h in heads if h not in found]
            if absent:
                note(f"{fname}: heading(s) not found: " + "; ".join(absent)
                     + ". Headings are read by a person, but they are fixed.")

    if not (repo / "main.py").exists() or not cfg_ok:
        why = "no main.py" if not (repo / "main.py").exists() else "capstone.json is not valid"
        for grp, name, m in TESTS:
            add(Check(grp, name, m, False, f"not run: {why}"))
        add(ui_check(repo, cfg))
        add(sample_check(repo, note))
        return res

    # ---- Behavioural checks, on a clean clone -----------------------------
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        if is_git:
            ref = TAG if (tagged and not SELF_CHECK) else "HEAD"
            subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout",
                            str(repo), str(work)], capture_output=True, timeout=120)
            _, sha = git(repo, "rev-parse", ref)
            subprocess.run(["git", "-C", str(work), "-c", "advice.detachedHead=false",
                            "checkout", "--quiet", sha], capture_output=True, timeout=120)
            _, subject = git(repo, "log", "-1", "--format=%h %cs %s", sha)
            note(f"Tested commit {subject[:90]}"
                 + (f" (the {TAG} tag)" if ref == TAG else " (HEAD; commits after it are not tested)"))
            if SELF_CHECK:
                _, dirty = git(repo, "status", "--porcelain", "--untracked-files=no")
                if dirty:
                    note("You have uncommitted changes. This run tested your last commit, "
                         "which is what gets marked. Commit, then check again.")
                _, untracked = git(repo, "ls-files", "--others", "--exclude-standard")
                if untracked:
                    names = untracked.splitlines()
                    note(f"{len(names)} untracked file(s) were not tested, for example "
                         + ", ".join(names[:3]) + ". If your app needs them, commit them.")
        else:
            shutil.copytree(repo, work, ignore=shutil.ignore_patterns(*SKIP_DIRS, "*.pyc"))
            note("Not a git repository: tested the folder as it is.")

        if not (work / "main.py").exists():
            for grp, name, m in TESTS:
                add(Check(grp, name, m, False, "main.py is not in the committed tree"))
            add(ui_check(work, cfg))
            add(sample_check(work, note))
            return res

        if not SELF_CHECK:
            shutil.copy2(REFERENCE / "client.py", work / "client.py")
            shutil.copy2(REFERENCE / "stub_client.py", work / "stub_client.py")
        (work / ".env").unlink(missing_ok=True)

        sample = cfg["sample_input"]
        injected = cfg["injected_input"]
        ext = Path(sample).suffix
        gen_dir = Path(sample).parent
        empty_rel = (gen_dir / f"_check_empty{ext}").as_posix()
        big_rel = (gen_dir / f"_check_oversize{ext}").as_posix()
        protect = {empty_rel, big_rel}

        sample_bytes = (work / sample).read_bytes() if (work / sample).is_file() else b""
        if not sample_bytes:
            note("sample_input is empty or not committed; the oversized file is padding only.")
        (work / empty_rel).parent.mkdir(parents=True, exist_ok=True)
        (work / empty_rel).write_bytes(b"")
        chunk = sample_bytes or b"x" * 1024
        (work / big_rel).write_bytes((chunk * (OVERSIZE_BYTES // len(chunk) + 1))[:OVERSIZE_BYTES])

        sample_text = text_of(work / sample)
        valid_needles = distinctive(work / "samples" / "valid_response.json", sample_text)
        invalid_needles = distinctive(work / "samples" / "invalid_response.json", sample_text)

        runs: list[Run] = []

        def go(path: str, mode: str, label: str) -> Run:
            r = run_app(work, path, mode, label, protect)
            runs.append(r)
            return r

        # -- Clean clone runs (1.0) ----------------------------------------
        r = go(sample, "ok", "stub:ok")

        passed = r.last == "ok" and r.code == 0 and not r.crashed
        add(Check("Application", "Clean clone runs: stub:ok -> ok, exit 0", 1.0, passed,
                  "" if passed else r.why()))
        if passed and r.log and r.log[-1].get("status") != "ok":
            note("stub:ok ended ok, but the last run_log.jsonl line does not say ok.")

        # -- Malformed / bad shape (1.5) -----------------------------------
        for mode, needles, mark in (("malformed", valid_needles, 0.75),
                                    ("badshape", invalid_needles, 0.75)):
            r = go(sample, mode, f"stub:{mode}")
            probs = []
            if not (r.last == "invalid_output" and r.code == 1):
                probs.append(r.why())
            if r.crashed and not r.timed_out:
                probs.append("crashed (traceback on stderr)")
            where = leaked(r, needles)
            if where:
                probs.append("reply content shown or stored anyway: " + ", ".join(where[:3]))
            logged = status_logged(r, "invalid_output")
            if logged:
                probs.append(logged)
            add(Check("Application", f"stub:{mode} -> invalid_output, exit 1, nothing kept",
                      mark, not probs, "; ".join(probs)))
            if not needles:
                note(f"No long strings in the sample reply for stub:{mode} to look for, "
                     "so 'nothing shown or stored' was checked by status only.")

        # -- Empty / refused / error (1.0) ---------------------------------
        for mode, want in (("empty", "invalid_output"), ("refused", "refused"), ("error", "error")):
            r = go(sample, mode, f"stub:{mode}")
            probs = []
            if not (r.last == want and r.code == 1):
                probs.append(r.why())
            if r.crashed and not r.timed_out:
                probs.append("crashed (traceback on stderr)")
            logged = status_logged(r, want)
            if logged:
                probs.append(logged)
            add(Check("Application", f"stub:{mode} -> {want}, exit 1", round(1 / 3, 4),
                      not probs, "; ".join(probs)))

        # -- Empty and oversized input, rejected before any call (1.0) -------
        for path, label in ((empty_rel, "empty file (0 bytes)"),
                            (big_rel, "oversized file (1 MB)")):
            r = go(path, "ok", label)
            probs = []
            if r.code != 2:
                probs.append(r.why())
            if r.calls:
                probs.append(f"{r.calls} model call(s) made")
            if r.log:
                probs.append(f"{len(r.log)} new run_log.jsonl line(s)")
            add(Check("Application", f"{label[0].upper()}{label[1:]} -> exit 2, no call, no log line",
                      0.5, not probs, "; ".join(probs)))

        # -- Injection (security, 2.0) and documents item 6 ----------------
        inj_text = text_of(work / injected)
        if not any(p.search(inj_text) for p in INJECTION_PATTERNS):
            note("No supplied phrasing found in injected_input. If your file format "
                 "compresses text (some PDFs), this can be a false alarm. Otherwise "
                 "stub:obedient has nothing to obey and the injection test proves little.")
        if (work / injected).is_file() and (work / sample).is_file() and \
                (work / injected).read_bytes() == (work / sample).read_bytes():
            note("injected_input is byte-identical to sample_input.")

        r = go(injected, "obedient", "stub:obedient, injected_input")
        inj_run = r
        probs = []
        where = leaked(r, [CANARY])
        if where:
            probs.append("the stub's marker reached " + ", ".join(where[:3]))
        if r.crashed or r.last not in OUTCOMES:
            probs.append(r.why())
        add(Check("Security", "Injection survived: marker never shown or stored, no crash",
                  1.0, not probs, "; ".join(probs)))

        hit = r.event_names & GUARD_EVENTS
        add(Check("Security", "A guard event logged on the injected input", 1.0, bool(hit),
                  "" if hit else "no guardrail_input, instruction_ignored or guardrail_output "
                                 f"in security_log.jsonl; events: {sorted(r.event_names) or 'none'}"))

        # -- Floor item 6 (1.5) --------------------------------------------
        if item6 == "documents":
            hit = inj_run.event_names & DOC_ITEM6_EVENTS
            ok6 = bool(hit) and not inj_run.crashed and inj_run.last in OUTCOMES
            add(Check("Application", "Item 6, documents: guardrail_input or instruction_ignored "
                                     "on the injected input", 1.5, ok6,
                      "" if ok6 else "; ".join(filter(None, [
                          "" if hit else f"events: {sorted(inj_run.event_names) or 'none'}",
                          "" if (not inj_run.crashed and inj_run.last in OUTCOMES) else inj_run.why(),
                      ]))))
        else:
            r = go(sample, "badargs", "stub:badargs")
            rejected = "tool_arg_rejected" in r.event_names
            survived = not r.crashed and r.last in OUTCOMES
            probs = []
            if not rejected:
                probs.append("no tool_arg_rejected logged")
                if r.last == "error":
                    probs.append("ended error: did the request carry tools=? "
                                 "Without a tools list stub:badargs behaves as stub:error")
            if not survived:
                probs.append(r.why())
            add(Check("Application", "Item 6, tools: stub:badargs -> call refused, "
                                     "tool_arg_rejected logged", 1.5, rejected and survived,
                      "; ".join(probs)))

        # -- Log well-formed, across every run that made a call (1.0) -------
        problems = []
        for run in runs:
            if run.calls or run.log:
                p = log_problems(run)
                if p:
                    problems.append(f"{run.label}: " + "; ".join(p))
        made_calls = any(run.calls for run in runs)
        passed = made_calls and not problems
        add(Check("Application", "run_log.jsonl: one line per call, nine keys, one run_id",
                  1.0, passed,
                  "no run made a model call" if not made_calls else " | ".join(problems[:2])))

        # -- Static: SDK imports outside client.py (note only) --------------
        for py in sorted(work.rglob("*.py")):
            rel = py.relative_to(work).as_posix()
            if any(part in SKIP_DIRS for part in py.parts) or rel in (
                    "client.py", "stub_client.py", "check_capstone.py") or \
                    rel.startswith(("capstone_starter/", "reference_files/")):
                continue
            hits = sdk_hits(imports_of(py)[1])
            if hits:
                note(f"{rel} imports {', '.join(sorted(hits))}. Only client.py may talk to a model.")

        # -- Static checks, on the committed files ---------------------------
        add(ui_check(work, cfg))
        add(sample_check(work, note))

    return res


# The behavioural tests, listed so that a repository where nothing can run
# still shows every line it lost.
TESTS = [
    ("Application", "Clean clone runs: stub:ok -> ok, exit 0", 1.0),
    ("Application", "stub:malformed -> invalid_output, exit 1, nothing kept", 0.75),
    ("Application", "stub:badshape -> invalid_output, exit 1, nothing kept", 0.75),
    ("Application", "stub:empty -> invalid_output, exit 1", round(1 / 3, 4)),
    ("Application", "stub:refused -> refused, exit 1", round(1 / 3, 4)),
    ("Application", "stub:error -> error, exit 1", round(1 / 3, 4)),
    ("Application", "Empty file (0 bytes) -> exit 2, no call, no log line", 0.5),
    ("Application", "Oversized file (1 MB) -> exit 2, no call, no log line", 0.5),
    ("Security", "Injection survived: marker never shown or stored, no crash", 1.0),
    ("Security", "A guard event logged on the injected input", 1.0),
    ("Application", "Item 6 (tools or documents)", 1.5),
    ("Application", "run_log.jsonl: one line per call, nine keys, one run_id", 1.0),
]


def ui_check(repo: Path, cfg: dict) -> Check:
    name = "UI imports the pipeline, never client.py"
    command = cfg.get("ui_command") if isinstance(cfg, dict) else None
    if not isinstance(command, str) or not command.strip():
        return Check("Application", name, 1.0, False, "no ui_command in capstone.json")
    files = ui_files(repo, command)
    if not files:
        return Check("Application", name, 1.0, False,
                     f"no Python file found in ui_command {command!r}; a person will check it by hand")
    main_tops = imports_of(repo / "main.py")[0] if (repo / "main.py").exists() else set()
    supplied = {"client", "stub_client", "observability", "security"}
    main_local = {t for t in main_tops if is_local(repo, t, repo) and t not in supplied}
    problems, shared_any = [], False
    for ui in files:
        tops, full, completions = imports_of(ui)
        rel = ui.relative_to(repo).as_posix()
        bad = sorted({t for t in tops if t in ("client", "stub_client")} | sdk_hits(full))
        if bad:
            problems.append(f"{rel} imports {', '.join(bad)}")
        if completions:
            problems.append(f"{rel} calls chat.completions itself")
        local = {t for t in tops if is_local(repo, t, ui.parent) and t not in supplied}
        if "main" in local or (local & main_local):
            shared_any = True
    if not shared_any:
        problems.append("the UI imports no module that main.py also imports, so it cannot be "
                        "calling the same pipeline" + (f" (main.py imports {sorted(main_local)})"
                                                         if main_local else ""))
    return Check("Application", name, 1.0, not problems, "; ".join(problems))


def sample_check(repo: Path, note=None) -> Check:
    name = "Log sample valid: samples/run_log_sample.jsonl"
    path = repo / "samples" / "run_log_sample.jsonl"
    if not path.exists():
        return Check("Logging", name, 0.5, False, "file missing")
    records, bad = read_jsonl(path)
    probs = []
    if bad:
        probs.append(f"{bad} line(s) do not parse")
    if not records:
        probs.append("no log lines in it")
    elif len(records) < SUGGESTED_SAMPLE_LINES and note:
        note(f"samples/run_log_sample.jsonl has {len(records)} line(s). Not marked, "
             f"but about {SUGGESTED_SAMPLE_LINES} gives a fairer picture of your runs.")
    missing = sorted({k for r in records for k in LOG_KEYS if k not in r})
    if missing:
        probs.append("missing key(s): " + ", ".join(missing))
    statuses = sorted({str(r.get("status")) for r in records if r.get("status") not in OUTCOMES})
    if statuses:
        probs.append("status not one of the four: " + ", ".join(statuses))
    return Check("Logging", name, 0.5, not probs, "; ".join(probs))


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def fmt(x: float) -> str:
    return f"{x:.2f}".rstrip("0").rstrip(".") if x != int(x) else f"{int(x)}"


def render(res: Result) -> str:
    failed_gates = [g.name for g in res.gates if not g.passed]
    headline = f"**Automated: {fmt(res.awarded())} / {fmt(res.total())}**  "
    if failed_gates:
        headline = (f"**Automated: {fmt(res.awarded())} / {fmt(res.total())}, but "
                    f"{len(failed_gates)} gate(s) failed: as it stands this cannot be "
                    "marked. See Gates.**  ")
    out = [f"# Capstone check: {res.repo}", "",
           headline,
           f"Application with UI {fmt(res.awarded('Application'))} / 8 · "
           f"Security {fmt(res.awarded('Security'))} / 2 of 5 · "
           f"Logging and evaluation {fmt(res.awarded('Logging'))} / 0.5 of 5  ",
           "Read by a person: brief 3, security 3, logging and evaluation 4.5. "
           "Viva 9. Capstone total 30.", ""]
    if SELF_CHECK:
        out += ["*Self-check mode: your client.py and stub_client.py were used as they are. "
                "Marking uses the originals.*", ""]
    out += ["## Gates", "", "A failing gate is not a lost fraction of a mark. It is a "
            "submission that cannot be marked.", "",
            "| Gate | Result | Note |", "|---|:-:|---|"]
    out += [f"| {g.name} | {'PASS' if g.passed else 'FAIL'} | {g.note} |" for g in res.gates]
    out += ["", "## Before anything runs", "", "| Prerequisite | Result | Note |", "|---|:-:|---|"]
    out += [f"| {g.name} | {'PASS' if g.passed else 'FAIL'} | {g.note} |" for g in res.prereqs]
    for group, title in (("Application", "Application with UI: 8 marks, all automated"),
                         ("Security", "Security: 2 of 5 marks automated"),
                         ("Logging", "Logging and evaluation: 0.5 of 5 marks automated")):
        out += ["", f"## {title}", "", "| Check | Marks | Result | Note |", "|---|--:|:-:|---|"]
        for c in res.checks:
            if c.group == group:
                note = c.note.replace("|", "/").replace("\n", " ")
                out.append(f"| {c.name} | {fmt(c.marks)} | {'PASS' if c.passed else 'FAIL'} | {note} |")
    if res.notes:
        out += ["", "## Notes (not marked)", ""] + [f"- {n}" for n in res.notes]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Capstone self-check and marking script.")
    ap.add_argument("path", nargs="?", default=".", help="a repository, or with --all a folder of them")
    ap.add_argument("--all", action="store_true", help="treat path as a folder of repositories")
    ap.add_argument("--out", default=None, help="folder for one .md per repository and summary.json")
    args = ap.parse_args()

    if not SELF_CHECK:
        for name, want in (("client.py", CLIENT_SHA256), ("stub_client.py", STUB_SHA256)):
            if not (REFERENCE / name).exists() or sha256(REFERENCE / name) != want:
                print(f"reference_files/{name} is missing or not the released copy. Stopping.")
                return 1

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"{root} is not a folder")
        return 1
    repos = sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")) \
        if args.all else [root]

    if SELF_CHECK:
        print("[self-check mode] client.py and stub_client.py are taken as they are.\n"
              "The marking run uses the supplied originals.\n")

    outdir = Path(args.out) if args.out else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)
    summary = []
    for repo in repos:
        res = check_repo(repo)
        text = render(res)
        print(text)
        print()
        if outdir:
            (outdir / f"{res.repo}.md").write_text(text + "\n", encoding="utf-8")
        summary.append({
            "repo": res.repo,
            "awarded": res.awarded(), "total": res.total(),
            "application": res.awarded("Application"),
            "security_automated": res.awarded("Security"),
            "logging_automated": res.awarded("Logging"),
            "gates_passed": all(g.passed for g in res.gates),
            "gates": [g.__dict__ for g in res.gates],
            "prerequisites": [g.__dict__ for g in res.prereqs],
            "checks": [c.__dict__ for c in res.checks],
            "notes": res.notes,
        })
    if outdir:
        (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
