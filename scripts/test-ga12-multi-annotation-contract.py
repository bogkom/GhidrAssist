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
assert "\\\\\\n" not in smoke, "double backslash before newline splits genuine headless command"
assert '-postScript GA12VerifyRestoredProgram.java ga12-synthetic.bin seed' in smoke
print("GA12_ANALYSIS_OBJECTS_SOURCE_PASS")
