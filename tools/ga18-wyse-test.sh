#!/usr/bin/env bash
# Wyse isolated GhidrAssist automation fixture. No ECU411 / no Supervisor.
set -euo pipefail
ROOT="$HOME/Projekty/Codex/ga-automation-test"
GHIDRA="$HOME/Kompilacja/ReverseEngineering/ghidra_12.1.4_PUBLIC"
PROJECT="$ROOT/project/AutomationFixture.gpr"
SESSION="$ROOT/session.json"
export JAVA_TOOL_OPTIONS="-Dapplication.settingsdir=$ROOT/settings -Dapplication.cachedir=$ROOT/cache -Duser.home=$ROOT/home"
case "${1:-}" in
  start)
    test -f "$PROJECT" || { echo "Fixture project missing: $PROJECT" >&2; exit 1; }
    python3 "$ROOT/bin/ghidrassist-agent-start" --ghidra "$GHIDRA" --project "$PROJECT" --program synthetic-mmio.bin --session "$SESSION" --mode test
    ;;
  status|snapshot|analyze|task|mmio|review-preview|listing|goto)
    python3 "$ROOT/bin/ghidrassist-agent" --session "$SESSION" "$@"
    ;;
  *)
    echo "Usage: bash tools/ga18-wyse-test.sh {start|status|snapshot|analyze|task|mmio|review-preview|listing|goto} [args]" >&2
    exit 2
    ;;
esac
