#!/usr/bin/env python3
"""Source-level contract for comments and user-defined label persistence.

This does not replace the Java 25 genuine Ghidra reopen acceptance.
"""
from pathlib import Path

source = (Path(__file__).resolve().parents[1] / "ghidra_scripts" / "GA12VerifyRestoredProgram.java").read_text()
for required in (
    'CodeUnit.PLATE_COMMENT, start',
    'CodeUnit.EOL_COMMENT, secondSite',
    'start.add(2)',
    'getComment(CodeUnit.EOL_COMMENT, secondSite)',
    'setComment(secondSite, CodeUnit.EOL_COMMENT, secondMarker)',
    '!marker.equals(observed) || !secondMarker.equals(secondObserved)',
    'GA12_ANALYSIS_PERSISTED_PASS',
    'start.add(4)',
    'getPrimarySymbol(labelSite)',
    'createLabel(labelSite, labelName, true)',
    'labelObserved.getSource() != SourceType.USER_DEFINED',
    'seededLabel.getSource() != SourceType.USER_DEFINED',
    '|| labelObserved != null',
):
    assert required in source, f"missing GA-12 second-site contract: {required}"
# The negative genuine-headless invocation must be one command, not split by
# doubled backslashes. A shell syntax check alone cannot detect this regression.
smoke = (Path(__file__).resolve().parent / "ga12-genuine-reopen-smoke.sh").read_text()
assert "GA12_SEED_FAIL: annotation already present" in smoke
assert 'GA12_EXISTING_ANALYSIS_RESEED_REJECTED' in smoke
assert (chr(92) * 2 + chr(10)) not in smoke, "double backslash before newline splits genuine headless command"
assert '-postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin seed' in smoke
assert 'GA12_REJECTED_RESEED_NONMUTATION_PASS' in smoke
assert 'GA12_NEGATIVE_FAIL: rejected reseed changed persisted analysis' in smoke
assert 'post-rejection.log' in smoke
assert smoke.count('-postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin verify') == 6
# Restored, post-rejection, tampered-copy, and pristine-after-tamper checks must each use a fresh process.
for witness in ('reopen.log', 'post-rejection.log', 'tamper-rejected.log', 'pristine-after-tamper.log', 'label-tamper-rejected.log', 'pristine-after-label-tamper.log'):
    assert witness in smoke, f'missing independent verify log: {witness}'
assert smoke.index('GA12_EXISTING_ANALYSIS_RESEED_REJECTED') < smoke.index('post-rejection.log')
assert 'args[1].equals("tamper")' in source
assert '"GA12_INTENTIONALLY_TAMPERED"' in source
assert 'GA12_TAMPER_APPLIED' in source
assert 'GA12_TAMPER_DETECTION_PASS' in smoke
assert 'GA12_TAMPER_ISOLATION_PASS' in smoke
assert smoke.index('GA12_TAMPER_DETECTION_PASS') < smoke.index('pristine-after-tamper.log')
assert 'GA12_NEGATIVE_FAIL: verifier accepted tampered analysis' in smoke
assert '-postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin tamper' in smoke
assert 'tamper-rejected.log' in smoke
assert smoke.index('GA12_TAMPER_APPLIED') < smoke.index('GA12_TAMPER_DETECTION_PASS')
assert 'args[1].equals("tamper-label")' in source
assert 'labelObserved.setName("GA12_INTENTIONALLY_RENAMED", SourceType.USER_DEFINED)' in source
assert 'GA12_LABEL_TAMPER_APPLIED' in source and 'GA12_LABEL_TAMPER_APPLIED' in smoke
assert 'GA12_LABEL_TAMPER_DETECTION_PASS' in smoke
assert 'GA12_LABEL_TAMPER_ISOLATION_PASS' in smoke
assert smoke.index('GA12_LABEL_TAMPER_DETECTION_PASS') < smoke.index('pristine-after-label-tamper.log')
assert '-postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin tamper-label' in smoke
# The CI acceptance must actually execute this contract and require each genuine
# negative-path witness, not merely the final positive reopen marker.
workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ga12-isolated-project-copy.yml").read_text()
assert "python3 scripts/test-ga12-multi-annotation-contract.py" in workflow
assert "'scripts/test-ga12-multi-annotation-contract.py'" in workflow
for marker in (
    "GA12_REJECTED_RESEED_NONMUTATION_PASS",
    "GA12_TAMPER_DETECTION_PASS",
    "GA12_TAMPER_ISOLATION_PASS",
    "GA12_LABEL_TAMPER_DETECTION_PASS",
    "GA12_LABEL_TAMPER_ISOLATION_PASS",
):
    assert marker in workflow, f"CI does not require genuine witness: {marker}"
assert "grep -Fxq \"$marker\" \"$RUNNER_TEMP/ga12-reopen.log\"" in workflow
print("GA12_ANALYSIS_OBJECTS_SOURCE_PASS")
