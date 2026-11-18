#!/usr/bin/env bash
# GA-12 genuine offline project snapshot/reopen acceptance on a disposable fixture.
# Requires GHIDRA_INSTALL_DIR pointing to Ghidra 12.1.4 PUBLIC and Java 25.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEADLESS="${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
test -x "$HEADLESS"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/original" "$WORK/import"
python3 - "$WORK/import/ga12-synthetic.bin" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(bytes.fromhex("4e714e714e75"))
PY
# Import into a newly created, disposable project. Never use an existing project.
"$HEADLESS" "$WORK/original" GA12Fixture -import "$WORK/import/ga12-synthetic.bin" \
    -processor 68000:BE:32:CPU32 -overwrite \
    -scriptPath "$ROOT/ghidra_scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin \
    > "$WORK/import.log" 2>&1 || { cat "$WORK/import.log"; exit 1; }
grep -q 'GA12_REOPEN_PASS' "$WORK/import.log" || { cat "$WORK/import.log"; exit 1; }
# Ghidra has exited; project is closed before snapshot.
python3 "$ROOT/scripts/ga12-isolated-project-copy.py" snapshot \
    --source "$WORK/original" --destination "$WORK/snapshot"
python3 "$ROOT/scripts/ga12-isolated-project-copy.py" verify --source "$WORK/snapshot"
python3 "$ROOT/scripts/ga12-isolated-project-copy.py" restore \
    --source "$WORK/snapshot" --destination "$WORK/restored" \
    --authorize-isolated-restore
# Open the restored project, do not import again. A successful process exit alone
# is insufficient: require the witness from the actual restored program.
"$HEADLESS" "$WORK/restored" GA12Fixture -process ga12-synthetic.bin \
    -scriptPath "$ROOT/ghidra_scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin \
    > "$WORK/reopen.log" 2>&1 || { cat "$WORK/reopen.log"; exit 1; }
grep -q 'GA12_REOPEN_PASS' "$WORK/reopen.log" || { cat "$WORK/reopen.log"; exit 1; }
echo "GA12_GENUINE_REOPEN_PASS"
