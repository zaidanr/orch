# orch
Multi-agent Orchestration PoC - Orchestrating Claude Code without Claude API keys


python3 orchestrator.py --rounds 4
python3 orchestrator.py --rounds 1 --enable-monitoring # require strace
python3 analyze_monitoring.py solver_workspaces/
