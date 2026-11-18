#!/usr/bin/env python3
"""Source-level contract for the two-site Ghidra persistence witness.

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
):
    assert required in source, f"missing GA-12 second-site contract: {required}"
print("GA12_MULTI_ANNOTATION_SOURCE_PASS")
