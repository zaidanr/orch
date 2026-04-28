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
    print(f"[setter] NEW_QUIZ path: {NEW_QUIZ}")
    print(f"[setter] NEW_QUIZ exists before cleanup: {NEW_QUIZ.exists()}")
    
    NEW_QUIZ.unlink(missing_ok=True)
    print(f"[setter] NEW_QUIZ exists after cleanup: {NEW_QUIZ.exists()}")

    print(f"[setter] Running in directory: {SETTER_DIR}")
    print(f"[setter] CLAUDE.md exists: {(SETTER_DIR / 'CLAUDE.md').exists()}")
    print(f"[setter] ledger.json exists: {LEDGER.exists()}")
    
    # Track what files exist before running the setter
    files_before = set(ROOT.iterdir()) if ROOT.exists() else set()
    ledger_before = set((ROOT / "problemsetter").iterdir()) if (ROOT / "problemsetter").exists() else set()
    
    rc, _out, err = run_agent(
        SETTER_DIR,
        "Generate the next quiz per CLAUDE.md and exit.",
        SETTER_TOOLS,
    )
    
    # Track what files exist after running the setter
    files_after = set(ROOT.iterdir()) if ROOT.exists() else set()
    ledger_after = set((ROOT / "problemsetter").iterdir()) if (ROOT / "problemsetter").exists() else set()
    
    print(f"[setter] Return code: {rc}")
    if _out.strip():
        print(f"[setter] stdout: {_out.strip()}")
    if err.strip():
        print(f"[setter] stderr: {err.strip()}")
    
    # Show file changes
    new_files = files_after - files_before
    if new_files:
        print(f"[setter] Files created in root:")
        for f in new_files:
            if f.is_file():
                print(f"  ✅ {f.name} ({f.stat().st_size} bytes)")
    
    modified_files = []
    for f in files_before & files_after:
        if f.is_file():
            try:
                # Simple check - if modification time is very recent, likely modified
                import time
                if time.time() - f.stat().st_mtime < 5:  # Modified within last 5 seconds
                    modified_files.append(f)
            except:
                pass
    
    if modified_files:
        print(f"[setter] Files possibly modified:")
        for f in modified_files:
            print(f"  📝 {f.name} ({f.stat().st_size} bytes)")
    
    # Show what files the setter likely accessed (basic heuristic)
    likely_accessed = []
    if LEDGER.exists():
        likely_accessed.append("../ledger.json (read for difficulty rotation)")
    if NEW_QUIZ.exists():
        likely_accessed.append("../new_quiz.json (written)")
    
    if likely_accessed:
        print(f"[setter] Likely file access pattern:")
        for access in likely_accessed:
            print(f"  📁 {access}")
    
    # Give the file system a moment to sync (potential race condition fix)
    import time
    time.sleep(0.1)
    
    print(f"[setter] new_quiz.json exists after run: {NEW_QUIZ.exists()}")
    if NEW_QUIZ.exists():
        print(f"[setter] new_quiz.json size: {NEW_QUIZ.stat().st_size} bytes")
    
    # List files in the root directory to see what was actually created
    print(f"[setter] Files in root directory:")
    for f in ROOT.iterdir():
        if f.name.startswith("new_quiz") or f.suffix == ".json":
            print(f"  {f.name} ({f.stat().st_size} bytes)")
    
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
            print(f"[solver] Running with monitoring in workspace: {workspace}")
            rc, _out, err, monitoring_report = run_solver_monitored(
                workspace, 
                "Solve the cipher puzzle per CLAUDE.md and exit.",
                SOLVER_TOOLS,
                AGENT_TIMEOUT_SECONDS
            )
            
            print(f"[solver] Return code: {rc}")
            if _out.strip():
                print(f"[solver] stdout: {_out.strip()}")
            if err.strip():
                print(f"[solver] stderr: {err.strip()}")
            
            # Give the file system a moment to sync
            import time
            time.sleep(0.1)
            
            print(f"[solver] answer.txt exists after run: {answer_file.exists()}")
            if answer_file.exists():
                print(f"[solver] answer.txt size: {answer_file.stat().st_size} bytes")
                answer_content = answer_file.read_text().strip()
                print(f"[solver] answer content: {answer_content!r}")
            
            # List files in workspace to see what was created
            print(f"[solver] Files in workspace:")
            for f in workspace.iterdir():
                if f.is_file():
                    print(f"  {f.name} ({f.stat().st_size} bytes)")
            
            # Save monitoring report
            report_file = workspace / "monitoring_report.json"
            report_file.write_text(json.dumps(monitoring_report, indent=2))
            print(f"[solver] Monitoring report saved to {report_file.name}")
            
            # Show file access summary
            file_access = monitoring_report.get("file_access", {})
            if "all_accessed_files" in file_access:
                print(f"[solver] Files accessed during execution:")
                for accessed_file in file_access["all_accessed_files"]:
                    print(f"  📁 {accessed_file}")
            
            suspicious_activities = file_access.get("suspicious_activities", [])
            if suspicious_activities:
                print(f"[solver] ⚠️  Suspicious file activities detected:")
                for activity in suspicious_activities:
                    print(f"  🚨 {activity['type']}: {activity['description']}")
            
            # Alert on suspicious activity
            if monitoring_report["file_access"].get("severity_counts", {}).get("HIGH", 0) > 0:
                print(f"[MONITOR] WARNING: High-risk file access detected in round {round_num}")
                
        except ImportError as e:
            print(f"[MONITOR] monitoring.py not found: {e}, falling back to normal execution")
            rc, _out, err = run_agent(workspace, "Solve the cipher puzzle per CLAUDE.md and exit.", SOLVER_TOOLS)
        except Exception as e:
            print(f"[MONITOR] monitoring failed: {e}, falling back to normal execution")
            rc, _out, err = run_agent(workspace, "Solve the cipher puzzle per CLAUDE.md and exit.", SOLVER_TOOLS)
    else:
        print(f"[solver] Running without monitoring in workspace: {workspace}")
        
        # Track what files exist before running the solver
        files_before = set(workspace.iterdir()) if workspace.exists() else set()
        
        rc, _out, err = run_agent(workspace, "Solve the cipher puzzle per CLAUDE.md and exit.", SOLVER_TOOLS)
        
        # Track what files exist after running the solver
        files_after = set(workspace.iterdir()) if workspace.exists() else set()
        
        print(f"[solver] Return code: {rc}")
        if _out.strip():
            print(f"[solver] stdout: {_out.strip()}")
        if err.strip():
            print(f"[solver] stderr: {err.strip()}")
        
        # Show file changes
        new_files = files_after - files_before
        if new_files:
            print(f"[solver] Files created in workspace:")
            for f in new_files:
                if f.is_file():
                    print(f"  ✅ {f.name} ({f.stat().st_size} bytes)")
        
        modified_files = []
        for f in files_before & files_after:
            if f.is_file():
                try:
                    # Simple check - if modification time is very recent, likely modified
                    import time
                    if time.time() - f.stat().st_mtime < 5:  # Modified within last 5 seconds
                        modified_files.append(f)
                except:
                    pass
        
        if modified_files:
            print(f"[solver] Files possibly modified:")
            for f in modified_files:
                print(f"  📝 {f.name} ({f.stat().st_size} bytes)")
        
        # Show what files the solver should have accessed
        expected_access = []
        if (workspace / "current_quiz.txt").exists():
            expected_access.append("current_quiz.txt (read - the ciphertext)")
        if (workspace / "CLAUDE.md").exists():
            expected_access.append("CLAUDE.md (read - instructions)")
        if (workspace / "answer.txt").exists():
            expected_access.append("answer.txt (written - the solution)")
        
        if expected_access:
            print(f"[solver] Expected file access pattern:")
            for access in expected_access:
                print(f"  📁 {access}")
        
        # Give the file system a moment to sync
        import time
        time.sleep(0.1)
        
        print(f"[solver] answer.txt exists after run: {answer_file.exists()}")
        if answer_file.exists():
            print(f"[solver] answer.txt size: {answer_file.stat().st_size} bytes")
            answer_content = answer_file.read_text().strip()
            print(f"[solver] answer content: {answer_content!r}")
        
        # List files in workspace
        print(f"[solver] Files in workspace:")
        for f in workspace.iterdir():
            if f.is_file():
                print(f"  {f.name} ({f.stat().st_size} bytes)")

    if rc != 0:
        print(f"[solver] non-zero exit ({rc})", file=sys.stderr)
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

def run_round(round_num: int, solver_name: str, max_attempts: int, enable_monitoring: bool = False, preserve_workspaces: bool = False) -> None:
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

    # Round cleanup. Preserve monitoring reports, optionally keep workspaces
    workspace = ROOT / "solver_workspaces" / f"round_{round_num}"
    if workspace.exists():
        # Always save monitoring report to permanent location if it exists
        monitoring_report = workspace / "monitoring_report.json"
        if monitoring_report.exists():
            reports_dir = ROOT / "monitoring_reports"
            reports_dir.mkdir(exist_ok=True)
            
            # Copy report with round info
            preserved_report = reports_dir / f"round_{round_num}_monitoring.json"
            shutil.copy2(monitoring_report, preserved_report)
            print(f"[orchestrator] Monitoring report preserved: {preserved_report.name}")
        
        # Remove workspace only if not preserving
        if not preserve_workspaces:
            shutil.rmtree(workspace)
            print(f"[orchestrator] Workspace cleaned up: round_{round_num}")
        else:
            print(f"[orchestrator] Workspace preserved: {workspace}")


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
    parser.add_argument("--preserve-workspaces", action="store_true",
                        help="keep solver workspaces after execution (useful for debugging)")
    args = parser.parse_args()

    if not LEDGER.exists() or not LEDGER.read_text().strip():
        save_ledger({"quiz": []})

    rounds_run = 0
    try:
        for i in range(1, args.rounds + 1):
            run_round(i, args.solver_name, args.max_attempts, args.enable_monitoring, args.preserve_workspaces)
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
        # Preserve any monitoring reports before cleanup
        workspace_root = ROOT / "solver_workspaces"
        if workspace_root.exists():
            reports_dir = ROOT / "monitoring_reports"
            reports_dir.mkdir(exist_ok=True)
            
            for workspace_dir in workspace_root.iterdir():
                if workspace_dir.is_dir():
                    monitoring_report = workspace_dir / "monitoring_report.json"
                    if monitoring_report.exists():
                        preserved_report = reports_dir / f"{workspace_dir.name}_interrupted_monitoring.json"
                        shutil.copy2(monitoring_report, preserved_report)
            
            # Clean up workspace directories unless preserving
            if not args.preserve_workspaces:
                shutil.rmtree(workspace_root)
        
        NEW_QUIZ.unlink(missing_ok=True)
        return 130

    print_summary(rounds_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
