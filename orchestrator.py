"""
Orchestrator for the cipher quiz POC.

Loop: for each round, invoke the setter to produce a new quiz, then invoke
the solver up to MAX_ATTEMPTS times until it gets the answer or gives up.
All state lives in ledger.json. Handoff between agents happens via files
in their respective working directories — neither agent has network access
or sees the other's directory.

Run:
    python orchestrator.py --rounds 4 --solver-name solver
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# --- Layout ---------------------------------------------------------------

ROOT = Path(__file__).parent.resolve()
MODEL = "sonnet"
LEDGER = ROOT / "ledger.json"
SETTER_DIR = ROOT / "problemsetter"
SOLVER_DIR = ROOT / "problemsolver"

# Handoff files. Setter writes new_quiz.json; orchestrator extracts ciphertext
# into current_quiz.txt for the solver; solver writes answer.txt back.
NEW_QUIZ = ROOT / "new_quiz.json"
CURRENT_QUIZ = SOLVER_DIR / "current_quiz.txt"
ANSWER = SOLVER_DIR / "answer.txt"

# --- Config ---------------------------------------------------------------

DEFAULT_MAX_ATTEMPTS = 3
AGENT_TIMEOUT_SECONDS = 600  # generous; HARD problems can take a while

# Granular tool permissions per agent. Both need Read/Write in their cwd
# and Python via Bash for verification (setter) or decryption (solver).
SETTER_TOOLS = "Read,Write,Bash(python3:*)"
SOLVER_TOOLS = "Read,Write,Bash(python3:*)"

# --- Helpers --------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_ledger() -> dict:
    if not LEDGER.exists():
        return {"quiz": []}
    text = LEDGER.read_text().strip()
    if not text:
        return {"quiz": []}
    return json.loads(text)


def save_ledger(ledger: dict) -> None:
    # Write atomically: tmp file + rename, so a crash mid-write doesn't
    # corrupt the ledger.
    tmp = LEDGER.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(ledger, indent=2))
    tmp.replace(LEDGER)


def run_agent(cwd: Path, prompt: str, allowed_tools: str) -> tuple[int, str, str]:
    """Invoke `claude -p` in `cwd`. CLAUDE.md is auto-loaded from that directory."""
    cmd = [
        "claude", "-p", prompt,
        "--permission-mode", "acceptEdits",
        "--allowedTools", allowed_tools,
        "--model", MODEL
    ]
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=AGENT_TIMEOUT_SECONDS,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {AGENT_TIMEOUT_SECONDS}s"


# --- Setter ---------------------------------------------------------------

def invoke_setter() -> dict | None:
    """Run the setter and return the validated quiz dict, or None on failure."""
    NEW_QUIZ.unlink(missing_ok=True)

    rc, _out, err = run_agent(
        SETTER_DIR,
        "Generate the next quiz per CLAUDE.md and exit.",
        SETTER_TOOLS,
    )
    if rc != 0:
        print(f"[setter] non-zero exit ({rc}): {err.strip()}", file=sys.stderr)
        if _out.strip():
            print(f"[setter] stdout: {_out.strip()}", file=sys.stderr)
        return None
    if not NEW_QUIZ.exists():
        print("[setter] did not produce new_quiz.json", file=sys.stderr)
        return None

    try:
        quiz = json.loads(NEW_QUIZ.read_text())
    except json.JSONDecodeError as e:
        print(f"[setter] new_quiz.json is invalid JSON: {e}", file=sys.stderr)
        return None

    required = {"ciphertext", "plaintext", "cipher_combination", "difficulty"}
    missing = required - quiz.keys()
    if missing:
        print(f"[setter] new_quiz.json missing fields: {missing}", file=sys.stderr)
        return None
    if quiz["difficulty"] not in {"EASY", "MEDIUM", "HARD"}:
        print(f"[setter] invalid difficulty: {quiz['difficulty']!r}", file=sys.stderr)
        return None

    return quiz


# --- Solver ---------------------------------------------------------------

def invoke_solver(ciphertext: str, round_num: int, enable_monitoring: bool = False) -> str | None:
    """Run the solver against `ciphertext` in an isolated workspace."""
    # Create isolated workspace for this round
    workspace = ROOT / "solver_workspaces" / f"round_{round_num}"
    workspace.mkdir(parents=True, exist_ok=True)
    
    # Copy only what the solver needs - no access to ledger
    shutil.copy(SOLVER_DIR / "CLAUDE.md", workspace / "CLAUDE.md")
    (workspace / "current_quiz.txt").write_text(ciphertext)
    
    # Clean any previous answer
    answer_file = workspace / "answer.txt"
    answer_file.unlink(missing_ok=True)

    if enable_monitoring:
        try:
            from monitoring import run_solver_monitored
            rc, _out, err, monitoring_report = run_solver_monitored(
                workspace, 
                "Solve the cipher puzzle per CLAUDE.md and exit.",
                SOLVER_TOOLS,
                AGENT_TIMEOUT_SECONDS
            )
            
            # Save monitoring report
            report_file = workspace / "monitoring_report.json"
            report_file.write_text(json.dumps(monitoring_report, indent=2))
            
            # Alert on suspicious activity
            if monitoring_report["file_access"].get("severity_counts", {}).get("HIGH", 0) > 0:
                print(f"[MONITOR] WARNING: High-risk file access detected in round {round_num}")
                
        except ImportError:
            print(f"[MONITOR] monitoring.py not found, falling back to normal execution")
            rc, _out, err = run_agent(workspace, "Solve the cipher puzzle per CLAUDE.md and exit.", SOLVER_TOOLS)
    else:
        rc, _out, err = run_agent(workspace, "Solve the cipher puzzle per CLAUDE.md and exit.", SOLVER_TOOLS)

    if rc != 0:
        print(f"[solver] non-zero exit ({rc}): {err.strip()}", file=sys.stderr)
        if _out.strip():
            print(f"[solver] stdout: {_out.strip()}", file=sys.stderr)
        return None
    if not answer_file.exists():
        print("[solver] did not produce answer.txt", file=sys.stderr)
        return None

    return answer_file.read_text().strip()


# --- Grading --------------------------------------------------------------

def is_correct(guess: str | None, plaintext: str) -> bool:
    if guess is None:
        return False
    return guess.strip().lower() == plaintext.strip().lower()


# --- Round loop -----------------------------------------------------------

def run_round(round_num: int, solver_name: str, max_attempts: int, enable_monitoring: bool = False) -> None:
    print(f"\n=== Round {round_num} ===")

    quiz = invoke_setter()
    if quiz is None:
        print("[orchestrator] skipping round; setter failed")
        return

    ledger = load_ledger()
    quiz_id = len(ledger["quiz"]) + 1
    entry = {
        "id": quiz_id,
        "ciphertext": quiz["ciphertext"],
        "plaintext": quiz["plaintext"],
        "cipher_combination": quiz["cipher_combination"],
        "difficulty": quiz["difficulty"],
        "status": "pending",
        "attempts": [],
        "created_at": now_iso(),
        "closed_at": None,
    }
    ledger["quiz"].append(entry)
    save_ledger(ledger)
    NEW_QUIZ.unlink(missing_ok=True)

    print(
        f"[orchestrator] quiz #{quiz_id} {entry['difficulty']} "
        f"({entry['cipher_combination']}): {entry['ciphertext']!r}"
    )

    solved = False
    for attempt_num in range(1, max_attempts + 1):
        guess = invoke_solver(entry["ciphertext"], round_num, enable_monitoring)
        correct = is_correct(guess, entry["plaintext"])

        ledger = load_ledger()
        ledger["quiz"][-1]["attempts"].append({
            "name": solver_name,
            "guess": guess,
            "correct": correct,
            "ts": now_iso(),
        })

        if correct:
            ledger["quiz"][-1]["status"] = "solved"
            ledger["quiz"][-1]["closed_at"] = now_iso()
            save_ledger(ledger)
            print(f"[orchestrator] solved on attempt {attempt_num}: {guess!r}")
            solved = True
            break

        save_ledger(ledger)
        print(f"[orchestrator] attempt {attempt_num} wrong: {guess!r}")

    if not solved:
        ledger = load_ledger()
        ledger["quiz"][-1]["status"] = "exhausted"
        ledger["quiz"][-1]["closed_at"] = now_iso()
        save_ledger(ledger)
        print(
            f"[orchestrator] exhausted after {max_attempts} attempts; "
            f"answer was {entry['plaintext']!r}"
        )

    # Round cleanup. Remove the isolated workspace to prevent data leakage
    # between rounds and keep disk usage bounded.
    workspace = ROOT / "solver_workspaces" / f"round_{round_num}"
    if workspace.exists():
        shutil.rmtree(workspace)


# --- Entry point ----------------------------------------------------------

def print_summary(rounds_run: int) -> None:
    print("\n=== Summary ===")
    ledger = load_ledger()
    recent = ledger["quiz"][-rounds_run:] if rounds_run > 0 else []
    if not recent:
        print("(no quizzes this run)")
        return
    solved = sum(1 for q in recent if q["status"] == "solved")
    for q in recent:
        print(
            f"#{q['id']:>3} {q['difficulty']:<6} {q['status']:<9} "
            f"attempts={len(q['attempts'])}  cipher={q['cipher_combination']}"
        )
    print(f"\nsolved {solved}/{len(recent)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Cipher quiz multi-agent orchestrator")
    parser.add_argument("--rounds", type=int, default=4,
                        help="number of quiz rounds to run (default: 4 = one full difficulty cycle)")
    parser.add_argument("--solver-name", default="solver",
                        help="name stamped on each attempt in the ledger")
    parser.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS,
                        help=f"solver attempts per quiz (default: {DEFAULT_MAX_ATTEMPTS})")
    parser.add_argument("--enable-monitoring", action="store_true",
                        help="enable file access monitoring and cheating detection")
    args = parser.parse_args()

    if not LEDGER.exists() or not LEDGER.read_text().strip():
        save_ledger({"quiz": []})

    rounds_run = 0
    try:
        for i in range(1, args.rounds + 1):
            run_round(i, args.solver_name, args.max_attempts, args.enable_monitoring)
            rounds_run += 1
    except KeyboardInterrupt:
        print("\n[orchestrator] interrupted", file=sys.stderr)
        # Mark any still-pending quiz as interrupted so the ledger isn't
        # left in a confusing state.
        ledger = load_ledger()
        if ledger["quiz"] and ledger["quiz"][-1]["status"] == "pending":
            ledger["quiz"][-1]["status"] = "interrupted"
            ledger["quiz"][-1]["closed_at"] = now_iso()
            save_ledger(ledger)
        # Clean up workspace directories and handoff files
        workspace_root = ROOT / "solver_workspaces"
        if workspace_root.exists():
            shutil.rmtree(workspace_root)
        NEW_QUIZ.unlink(missing_ok=True)
        return 130

    print_summary(rounds_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
