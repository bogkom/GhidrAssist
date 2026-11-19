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

# A user label matching the proposed register is not sufficient when the
# underlying bytes contain code or incompatible data. This must fail closed.
register = source.split("private static Decision registerDecision(", 1)[1].split(
    "private static Decision annotationDecision(", 1)[0]
assert register.index("boolean undefined=p.getListing().isUndefined(first,last)") < register.index(
    'return decide(State.ALREADY_PRESENT,')
assert 'return decide(State.BLOCKED,\n                        "Data/code defined with incompatible size or location"' in register
assert register.index('prior.getLength()!=item.length') < register.index(
    '"Short register label and compatible data already defined"')
assert '"Data/code defined with incompatible size or location",false' in register
assert '"Data/code defined with incompatible size or location",false' in register

# Existing matching user label + undefined bytes is a legitimate completion path:
# create the data, preserve the label and do not attempt a duplicate label.
define = source.split("private static boolean defineRegister(", 1)[1].split(
    "private static boolean annotateCandidate(", 1)[0]
assert '!prior.getName().equals(item.name)' in define
assert 'if(prior==null || prior.getSource()==SourceType.DEFAULT)' in define
assert define.index('p.getListing().createData(first,type)') < define.index(
    'p.getSymbolTable().createLabel(first,name,SourceType.USER_DEFINED)')
assert 'if(prior!=null && prior.getSource()!=SourceType.DEFAULT){' not in define

print("GA08_ATOMIC_APPLY_SOURCE_CONTRACT_PASS")
