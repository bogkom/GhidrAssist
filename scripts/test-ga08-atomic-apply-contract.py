#!/usr/bin/env python3
"""Source-level guard only; actual Ghidra transaction/Undo acceptance is separate."""
from pathlib import Path

source = Path("src/main/java/ghidrassist/hardware/HardwareApplyService.java").read_text()
apply = source.split("public static Outcome apply(", 1)[1]
assert apply.index("startTransaction(") < apply.index("preflight(program,item,approved)")
assert apply.index("preflight(program,item,approved)") < apply.index("boolean applied=switch(kind)")
assert "if(current.state==State.BLOCKED)" in apply
assert "throw new IllegalStateException(" in apply
assert "if(current.state==State.ALREADY_PRESENT)" in apply
assert "program.endTransaction(transaction,commit)" in apply
assert "boolean commit=false" in apply
assert "if(!applied)" in apply
assert "Hardware Apply could not apply approved row" in apply
assert apply.index("if(!applied)") < apply.index("commit=true;")
assert "if(applied)changed++;else skipped++;" not in apply
assert "commit=true;" in apply
assert apply.index("commit=true;") > apply.index("boolean applied=switch(kind)")
print("GA08_ATOMIC_APPLY_SOURCE_CONTRACT_PASS")
