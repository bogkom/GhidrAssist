#!/usr/bin/env bash
# Wyse isolated GhidrAssist automation fixture. No ECU411 / no Supervisor.
set -euo pipefail
ROOT="$HOME/Projekty/Codex/ga-automation-test"
GHIDRA="$HOME/Kompilacja/ReverseEngineering/ghidra_12.1.4_PUBLIC"
PROJECT="$ROOT/project/AutomationFixture.gpr"
SESSION="$ROOT/session.json"
export JAVA_TOOL_OPTIONS="-Dapplication.settingsdir=$ROOT/settings -Dapplication.cachedir=$ROOT/cache -Duser.home=$ROOT/home"
case "${1:-}" in
  manager)
    test -x "$GHIDRA/ghidraRun" || { echo "Ghidra launcher missing: $GHIDRA/ghidraRun" >&2; exit 1; }
    # Project Manager only: no .gpr, no program, no Automation API, isolated settings.
    "$GHIDRA/ghidraRun"
    ;;
  start|start-write)
    test -f "$PROJECT" || { echo "Fixture project missing: $PROJECT" >&2; exit 1; }
    if [[ "$1" == "start-write" ]]; then
      python3 "$ROOT/bin/ghidrassist-agent-start" --ghidra "$GHIDRA" --project "$PROJECT" --program synthetic-mmio.bin --session "$SESSION" --mode test --synthetic-writes
    else
      python3 "$ROOT/bin/ghidrassist-agent-start" --ghidra "$GHIDRA" --project "$PROJECT" --program synthetic-mmio.bin --session "$SESSION" --mode test
    fi
    ;;
  status|snapshot|analyze|task|mmio|review-preview|profile-select|function|xrefs|decompile|decompile-status|bundle|listing|goto)
    python3 "$ROOT/bin/ghidrassist-agent" --session "$SESSION" "$@"
    ;;
  *)
    echo "Usage: bash tools/ga18-wyse-test.sh {manager|start|start-write|status|snapshot|analyze|task|mmio|review-preview|profile-select|function|xrefs|decompile|decompile-status|listing|goto} [args]" >&2
    exit 2
    ;;
esac
