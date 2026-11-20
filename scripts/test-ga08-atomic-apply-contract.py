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

# Memory conflicts are rejected before the first block mutation, even when
# the conflicting row appears later in the approved batch.
assert "for (HardwareApplyPlan.Item item : approved)" in apply
assert "if (item.kind != HardwareApplyPlan.Kind.MEMORY) continue;" in apply
assert "Decision initial = preflight(program, item, approved);" in apply
assert apply.index("Decision initial = preflight(program, item, approved);") < apply.index("for(HardwareApplyPlan.Kind kind:")
assert apply.index("if (initial.state == State.BLOCKED)") < apply.index("for(HardwareApplyPlan.Kind kind:")

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
# Matching USER_DEFINED label + undefined bytes must be READY, not skipped.
assert 'if(undefined) {' in register
assert '"Matching register label exists; define missing data only"' in register
assert register.index('if(undefined) {') < register.index('"Short register label and compatible data already defined"')
assert 'return decide(State.READY,' in register

# Existing matching user label + undefined bytes is a legitimate completion path:
# create the data, preserve the label and do not attempt a duplicate label.
define = source.split("private static boolean defineRegister(", 1)[1].split(
    "private static boolean annotateCandidate(", 1)[0]
assert '!prior.getName().equals(item.name)' in define
assert 'if(prior==null || prior.getSource()==SourceType.DEFAULT)' in define
assert define.index('p.getListing().createData(first,type)') < define.index(
    'p.getSymbolTable().createLabel(first,name,SourceType.USER_DEFINED)')
assert 'if(prior!=null && prior.getSource()!=SourceType.DEFAULT){' not in define


# A pre-existing user-approved TPURAM label without the provenance note is
# incomplete, not ALREADY_PRESENT. The Apply path must add only the missing
# note without attempting to create a duplicate USER_DEFINED symbol.
annotation = source.split("private static Decision annotationDecision(", 1)[1].split(
    "/** Read-only status", 1)[0]
assert "comment.contains(TPURAM_CANDIDATE_NOTE)" in annotation
assert '"Candidate label exists but provenance comment is missing' in annotation
assert annotation.index("comment.contains(TPURAM_CANDIDATE_NOTE)") < annotation.index(
    "State.ALREADY_PRESENT")
annotate = source.split("private static boolean annotateCandidate(", 1)[1].split(
    "private static boolean defineVbr(", 1)[0]
assert "if(prior==null || prior.getSource()==SourceType.DEFAULT)" in annotate
assert "String line=TPURAM_CANDIDATE_NOTE;" in annotate
assert "existing==null || !existing.contains(line)" in annotate


# A speculative candidate annotation must refuse existing instructions rather than
# silently attaching a user-defined symbol to executable analysis.
assert "getInstructionContaining(at)!=null" in annotation
assert "Candidate address contains an instruction; preserve user code" in annotation
assert annotation.index("getInstructionContaining(at)!=null") < annotation.index("Symbol prior=")

print("GA08_ATOMIC_APPLY_SOURCE_CONTRACT_PASS")

# The runtime witness must call the production JAR rather than a standalone
# reimplementation, and exercise both a stale conflict rollback and idempotency.
from pathlib import Path as _Path
_witness = _Path("tools/ghidra_scripts/GA08VerifyProductionApply.java").read_text()
_workflow = _Path(".github/workflows/hardware-extension-build.yml").read_text()
assert 'Class.forName("ghidrassist.hardware.HardwareApplyService"' in _witness
assert 'apply.invoke(null, currentProgram, List.of(first, second))' in _witness
assert 'earlier approved region survived a failed transaction' in _witness
_after = _Path("tools/ghidra_scripts/GA08VerifyProductionApplyAfterTransaction.java").read_text()
assert 'apply.invoke(null,currentProgram,List.of(first))' in _after
assert 'GA08 PRODUCTION APPLY ROLLBACK PASS:' in _witness
assert 'apply.invoke(null, currentProgram, List.of(first, vbr))' in _witness
assert 'GA08 LATE ROLLBACK REQUESTED:' in _witness
assert 'first MEMORY block survived late transaction rollback' in _after
assert 'GA08 PRODUCTION APPLY LATE ROLLBACK PASS: prior_mutations=1 surviving=0' in _after
assert "GA08 PRODUCTION APPLY LATE ROLLBACK PASS: prior_mutations=1 surviving=0" in _workflow
assert 'GA08 PRODUCTION APPLY POSITIVE PASS:' in _after
assert '-postScript GA08VerifyProductionApplyAfterTransaction.java' in _workflow
assert '-postScript GA08VerifyProductionApply.java' in _workflow
assert 'GA-08 genuine production Apply and rollback on disposable CPU32' in _workflow

# Headless can report a script exception yet exit zero. Missing assertions
# must expose the actual Ghidra log, never fail silently at grep.
assert "GA-08 missing runtime assertion: headless process exit alone is not PASS" in _workflow
assert "tail -n 160 \"$RUNNER_TEMP/ga08-production.log\"" in _workflow
assert "grep -F 'GA08 PRODUCTION APPLY'" in _workflow

# Exact range coverage is not proof of ownership by GhidrAssist.
_memory = source.split("private static Decision memoryDecision(", 1)[1].split(
    "private static Decision registerDecision(", 1)[0]
assert "Exact region belongs to existing user memory" in _memory
assert "_EXACT" not in _memory
assert "if(!legacyPart(item,existing)" in _memory
# Even a name-matching exact module is not complete if permissions differ:
# never silently bless executable, unreadable or read-only user memory.
assert "existing.isExecute() || !existing.isRead() || !existing.isWrite()" in _memory
assert _memory.index("existing.isExecute()") < _memory.index("Matching uninitialized hardware region already mapped")
assert "block.isExecute() || !block.isRead() || !block.isWrite()" in _memory
assert _memory.index("block.isExecute()") < _memory.index("Extend/join ")
assert "GA08 EXACT USER BLOCK REFUSAL PASS: preserved=1" in _witness
assert "GA08 EXACT USER BLOCK REFUSAL PASS: preserved=1" in _workflow

# Late rollback must preserve both independent user-owned blocks, not merely
# remove the newly-created module. The runtime gate must require that witness.
assert 'GA08_USER_CONFLICT' in _after and 'GA08_USER_EXACT' in _after
assert 'exactBlock.getSize()==exactLength' in _after
assert 'GA08 LATE ROLLBACK USER BLOCKS PASS: conflict=1 exact=1' in _after
assert 'GA08 LATE ROLLBACK USER BLOCKS PASS: conflict=1 exact=1' in _workflow

# User-owned negative controls must be committed before rollback injection.
_setup = _Path("tools/ghidra_scripts/GA08SetupProductionApplyFixture.java").read_text()
# Ghidra's createUninitializedBlock default access flags are not a stable
# contract. The third process requires readable/writable, non-executable
# user-owned controls, so fixture setup must explicitly establish them.
assert 'var conflictBlock=currentProgram.getMemory().createUninitializedBlock(' in _setup
assert 'var exactBlock=currentProgram.getMemory().createUninitializedBlock(' in _setup
assert 'block.setRead(true);' in _setup
assert 'block.setWrite(true);' in _setup
assert 'block.setExecute(false);' in _setup
assert _setup.index('block.setWrite(true);') < _setup.index('commit=true;')
assert 'GA08 INDEPENDENT FIXTURE SETUP PASS: conflict=1 exact=1' in _setup
assert 'GA08 INDEPENDENT FIXTURE SETUP PASS: conflict=1 exact=1' in _workflow
assert _workflow.index('-postScript GA08SetupProductionApplyFixture.java') < _workflow.index('-postScript GA08VerifyProductionApply.java')
assert 'createUninitializedBlock("GA08_USER_CONFLICT"' not in _witness
assert 'createUninitializedBlock("GA08_USER_EXACT"' not in _witness

# Durability requires a second Ghidra process, not another postScript in
# the import process. Reopen must check both user blocks and idempotency.
_reopen = _Path("tools/ghidra_scripts/GA08VerifyProductionApplyReopened.java").read_text()
assert '"ga08-synthetic.bin".equals(currentProgram.getName())' in _reopen
assert 'GA08_USER_CONFLICT' in _reopen and 'GA08_USER_EXACT' in _reopen
assert 'apply.invoke(null, currentProgram, List.of(first))' in _reopen
assert 'GA08 PRODUCTION APPLY REOPEN PASS: module=1 user_blocks=2 idempotent=1' in _reopen
assert '-process ga08-synthetic.bin -noanalysis' in _workflow
assert '-postScript GA08VerifyProductionApplyReopened.java' in _workflow
assert 'GA08 PRODUCTION APPLY REOPEN PASS: module=1 user_blocks=2 idempotent=1' in _workflow
assert _workflow.index('GA-08 genuine production Apply and rollback on disposable CPU32') < _workflow.index('GA-08 persisted production Apply after independent project reopen')

# Reopened Apply must refuse both persisted user-owned MEMORY ranges without
# corrupting them; the real Ghidra workflow requires the distinct evidence.
assert 'GA08 REOPEN USER OWNERSHIP REFUSAL PASS: conflict=1 exact=1' in _reopen
assert 'GA08 REOPEN USER OWNERSHIP REFUSAL PASS: conflict=1 exact=1' in _workflow
assert 'GA08 REOPEN PERMISSION REFUSAL PASS: executable=1 readonly=1 unreadable=1' in _reopen
assert 'GA08 REOPEN PERMISSION REFUSAL PASS: executable=1 readonly=1 unreadable=1' in _workflow
assert 'impostor.setExecute(true)' in _reopen
assert 'impostor.setWrite(false)' in _reopen
assert 'impostor.setRead(false)' in _reopen
assert 'impostor.setRead(originalRead)' in _reopen
assert 'finally {' in _reopen and 'impostor.setName(originalName)' in _reopen

assert 'apply.invoke(null, currentProgram, List.of(item))' in _reopen
assert 'reopened refused Apply altered user-owned memory' in _reopen

# Rejected Apply must not change persisted state after the second headless
# process exits; a third fresh Ghidra process checks the same saved project.
_post = _Path("tools/ghidra_scripts/GA08VerifyProductionApplyAfterRefusals.java").read_text()
assert '"ga08-synthetic.bin".equals(currentProgram.getName())' in _post
assert 'GA08_USER_CONFLICT' in _post and 'GA08_USER_EXACT' in _post
assert 'apply.invoke(null, currentProgram, List.of(memory.get(0)))' in _post
assert 'GA08 POST REFUSAL PERSISTENCE PASS: module=1 user_blocks=2 idempotent=1' in _post
assert '-postScript GA08VerifyProductionApplyAfterRefusals.java' in _workflow
assert 'GA08 POST REFUSAL PERSISTENCE PASS: module=1 user_blocks=2 idempotent=1' in _workflow
assert _workflow.index('GA-08 persisted production Apply after independent project reopen') < _workflow.index('GA-08 independent reopen after rejected Apply must preserve persisted state')
assert _workflow.index('GA-08 independent reopen after rejected Apply must preserve persisted state') < _workflow.index('Verify production interprocedural traversal')

# Across independent processes, names alone are insufficient: dimensions and
# mapping properties of both user-owned negative controls must remain stable.
assert 'item == exact ? itemType.getField("length").getInt(item) : 1' in _reopen
assert 'user block properties changed across reopen' in _reopen
assert 'i == 1 ? 1 : itemType.getField("length").getInt(item)' in _post
assert 'persisted block properties changed:' in _post

# The third fresh process must re-run production preflight and Apply refusal,
# not merely inspect names left by the previous process.
assert 'GA08 THIRD PROCESS OWNERSHIP REFUSAL PASS: conflict=1 exact=1' in _post
assert 'GA08 THIRD PROCESS OWNERSHIP REFUSAL PASS: conflict=1 exact=1' in _workflow
assert 'preflight.invoke(null, currentProgram, item, candidates)' in _post
assert 'apply.invoke(null, currentProgram, List.of(item))' in _post
assert 'fresh process refusal mutated user block' in _post
assert 'block.isRead() && block.isWrite()' in _post

# Ghidra compiles Java postScripts at runtime, after the extension build.
# Reject escaped newline text accidentally inserted into Java source (the
# 2026-11-20 third-process CI failure) before launching headless Ghidra.
for _script in (
    "GA08SetupProductionApplyFixture.java",
    "GA08VerifyProductionApply.java",
    "GA08VerifyProductionApplyAfterTransaction.java",
    "GA08VerifyProductionApplyReopened.java",
    "GA08VerifyProductionApplyAfterRefusals.java",
):
    _java = _Path("tools/ghidra_scripts") / _script
    _source = _java.read_text()
    assert "\\n                        &&" not in _source, f"literal escaped Java newline: {_script}"
assert "!block.isExecute()\n                        && block.isRead()" in _post

# A literal backslash-n inside a YAML shell conditional is not a line
# continuation. It caused the third-process evidence gate to fail before
# checking either runtime marker. Require two real shell lines.
assert " ||\n             ! grep -Fq 'GA08 POST REFUSAL PERSISTENCE PASS:" in _workflow
assert " ||\\\\n             ! grep -Fq 'GA08 POST REFUSAL PERSISTENCE PASS:" not in _workflow

# Refusal must preserve unrelated approved module and global memory inventory.
assert "GA08 THIRD PROCESS NO COLLATERAL MEMORY PASS:" in _post
assert "refused Apply changed total memory block count" in _post
assert "refused Apply changed previously approved module" in _post
assert "GA08 THIRD PROCESS NO COLLATERAL MEMORY PASS:" in _workflow\n