#!/usr/bin/env bash
# GA-12 genuine offline project snapshot/reopen acceptance on a disposable fixture.
# Requires GHIDRA_INSTALL_DIR pointing to Ghidra 12.1.4 PUBLIC and Java 25.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEADLESS="${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
test -x "$HEADLESS"
python3 "$ROOT/scripts/test-ga12-multi-annotation-contract.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/original" "$WORK/import" "$WORK/scripts"
# Isolate the script compilation scope: unrelated repository scripts may require
# extension classes absent from stock Ghidra headless.
cp "$ROOT/ghidra_scripts/GA12VerifyRestoredProgram.java" "$WORK/scripts/"
python3 - "$WORK/import/ga12-synthetic.bin" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(bytes.fromhex("4e714e714e75"))
PY
# Import into a newly created, disposable project. Never use an existing project.
"$HEADLESS" "$WORK/original" GA12Fixture -import "$WORK/import/ga12-synthetic.bin" \
    -processor 68000:BE:32:CPU32 -overwrite \
    -scriptPath "$WORK/scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin seed \
    > "$WORK/import.log" 2>&1 || { cat "$WORK/import.log"; exit 1; }
grep -q 'GA12_ANALYSIS_SEEDED' "$WORK/import.log" || { cat "$WORK/import.log"; exit 1; }
# Ghidra has exited; project is closed before snapshot.
python3 "$ROOT/scripts/ga12-isolated-project-copy.py" snapshot \
    --source "$WORK/original" --destination "$WORK/snapshot"
python3 "$ROOT/scripts/ga12-isolated-project-copy.py" verify --source "$WORK/snapshot"
python3 "$ROOT/scripts/ga12-isolated-project-copy.py" restore \
    --source "$WORK/snapshot" --destination "$WORK/restored" \
    --authorize-isolated-restore
# Negative acceptance: a byte-level corrupt snapshot must be rejected before
# any destination project is created. Preserve the original valid snapshot.
cp -a "$WORK/snapshot" "$WORK/corrupt"
python3 - "$WORK/corrupt" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
files = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix != ".json")
if not files:
    raise SystemExit("GA12_NEGATIVE_FAIL: no snapshot payload")
p = files[0]
with p.open("ab") as f:
    f.write(b"GA12_CORRUPTION")
PY
if python3 "$ROOT/scripts/ga12-isolated-project-copy.py" restore \
    --source "$WORK/corrupt" --destination "$WORK/should-not-exist" \
    --authorize-isolated-restore > "$WORK/rejected.log" 2>&1; then
    echo "GA12_NEGATIVE_FAIL: corrupt snapshot was accepted" >&2
    exit 1
fi
if test -e "$WORK/should-not-exist"; then
    echo "GA12_NEGATIVE_FAIL: rejected restore created a destination" >&2
    exit 1
fi
echo "GA12_CORRUPT_RESTORE_REJECTED"
# Open the restored project, do not import again. A successful process exit alone
# is insufficient: require the witness from the actual restored program.
"$HEADLESS" "$WORK/restored" GA12Fixture -process ga12-synthetic.bin \
    -scriptPath "$WORK/scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin verify \
    > "$WORK/reopen.log" 2>&1 || { cat "$WORK/reopen.log"; exit 1; }
grep -q 'GA12_REOPEN_PASS' "$WORK/reopen.log" && \
    grep -q 'GA12_ANALYSIS_PERSISTED_PASS' "$WORK/reopen.log" || { cat "$WORK/reopen.log"; exit 1; }
# Negative control: a second seed must refuse already-persisted analysis objects.
# GhidraScript errors can be logged even when the headless process exits zero;
# therefore inspect the actual script failure marker, not only exit status.
"$HEADLESS" "$WORK/restored" GA12Fixture -process ga12-synthetic.bin \
    -scriptPath "$WORK/scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin seed \
    > "$WORK/reseed.log" 2>&1 || true
if ! grep -q 'GA12_SEED_FAIL: annotation already present' "$WORK/reseed.log" || \
    grep -q 'GA12_ANALYSIS_SEEDED' "$WORK/reseed.log"; then
    cat "$WORK/reseed.log"
    echo "GA12_NEGATIVE_FAIL: existing analysis was not rejected" >&2
    exit 1
fi
echo "GA12_EXISTING_ANALYSIS_RESEED_REJECTED"
# A failed reseed must leave the restored database intact after the process
# closes. Verify all three independent objects in a THIRD headless process.
"$HEADLESS" "$WORK/restored" GA12Fixture -process ga12-synthetic.bin \
    -scriptPath "$WORK/scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin verify \
    > "$WORK/post-rejection.log" 2>&1 || { cat "$WORK/post-rejection.log"; exit 1; }
if ! grep -q 'GA12_REOPEN_PASS' "$WORK/post-rejection.log" || \
    ! grep -q 'GA12_ANALYSIS_PERSISTED_PASS' "$WORK/post-rejection.log"; then
    cat "$WORK/post-rejection.log"
    echo "GA12_NEGATIVE_FAIL: rejected reseed changed persisted analysis" >&2
    exit 1
fi
echo "GA12_REJECTED_RESEED_NONMUTATION_PASS"
# Negative verifier calibration: restore a SECOND disposable project and mutate
# only its EOL comment. A fresh process must reject the persisted mismatch.
python3 "$ROOT/scripts/ga12-isolated-project-copy.py" restore \
    --source "$WORK/snapshot" --destination "$WORK/tampered" \
    --authorize-isolated-restore
"$HEADLESS" "$WORK/tampered" GA12Fixture -process ga12-synthetic.bin \
    -scriptPath "$WORK/scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin tamper \
    > "$WORK/tamper.log" 2>&1 || { cat "$WORK/tamper.log"; exit 1; }
grep -q 'GA12_TAMPER_APPLIED' "$WORK/tamper.log" || { cat "$WORK/tamper.log"; exit 1; }
"$HEADLESS" "$WORK/tampered" GA12Fixture -process ga12-synthetic.bin \
    -scriptPath "$WORK/scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin verify \
    > "$WORK/tamper-rejected.log" 2>&1 || true
if ! grep -q 'GA12_REOPEN_FAIL: persisted annotation missing or changed' "$WORK/tamper-rejected.log" || \
    grep -q 'GA12_ANALYSIS_PERSISTED_PASS' "$WORK/tamper-rejected.log"; then
    cat "$WORK/tamper-rejected.log"
    echo "GA12_NEGATIVE_FAIL: verifier accepted tampered analysis" >&2
    exit 1
fi
echo "GA12_TAMPER_DETECTION_PASS"
# The negative-control mutation must be isolated to the second restored copy.
# Reopen the original restored project in another independent headless process.
"$HEADLESS" "$WORK/restored" GA12Fixture -process ga12-synthetic.bin \
    -scriptPath "$WORK/scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin verify \
    > "$WORK/pristine-after-tamper.log" 2>&1 || { cat "$WORK/pristine-after-tamper.log"; exit 1; }
if ! grep -q 'GA12_REOPEN_PASS' "$WORK/pristine-after-tamper.log" || \
    ! grep -q 'GA12_ANALYSIS_PERSISTED_PASS' "$WORK/pristine-after-tamper.log"; then
    cat "$WORK/pristine-after-tamper.log"
    echo "GA12_NEGATIVE_FAIL: tamper control affected pristine restored project" >&2
    exit 1
fi
echo "GA12_TAMPER_ISOLATION_PASS"
# Independently mutate the persisted USER_DEFINED symbol in a third copy.
# The verifier must reject a renamed symbol after process restart, without
# affecting either of the original comments or the pristine project.
python3 "$ROOT/scripts/ga12-isolated-project-copy.py" restore \
    --source "$WORK/snapshot" --destination "$WORK/label-tampered" \
    --authorize-isolated-restore
"$HEADLESS" "$WORK/label-tampered" GA12Fixture -process ga12-synthetic.bin \
    -scriptPath "$WORK/scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin tamper-label \
    > "$WORK/label-tamper.log" 2>&1 || { cat "$WORK/label-tamper.log"; exit 1; }
grep -q 'GA12_LABEL_TAMPER_APPLIED' "$WORK/label-tamper.log" || { cat "$WORK/label-tamper.log"; exit 1; }
"$HEADLESS" "$WORK/label-tampered" GA12Fixture -process ga12-synthetic.bin \
    -scriptPath "$WORK/scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin verify \
    > "$WORK/label-tamper-rejected.log" 2>&1 || true
if ! grep -q 'GA12_REOPEN_FAIL: persisted annotation missing or changed' "$WORK/label-tamper-rejected.log" || \
    grep -q 'GA12_ANALYSIS_PERSISTED_PASS' "$WORK/label-tamper-rejected.log"; then
    cat "$WORK/label-tamper-rejected.log"
    echo "GA12_NEGATIVE_FAIL: verifier accepted renamed persisted symbol" >&2
    exit 1
fi
echo "GA12_LABEL_TAMPER_DETECTION_PASS"
"$HEADLESS" "$WORK/restored" GA12Fixture -process ga12-synthetic.bin \
    -scriptPath "$WORK/scripts" \
    -postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin verify \
    > "$WORK/pristine-after-label-tamper.log" 2>&1 || { cat "$WORK/pristine-after-label-tamper.log"; exit 1; }
grep -q 'GA12_ANALYSIS_PERSISTED_PASS' "$WORK/pristine-after-label-tamper.log" || {
    cat "$WORK/pristine-after-label-tamper.log"; exit 1;
}
echo "GA12_LABEL_TAMPER_ISOLATION_PASS"
echo "GA12_GENUINE_REOPEN_PASS"
