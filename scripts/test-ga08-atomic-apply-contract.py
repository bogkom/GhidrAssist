#!/usr/bin/env python3
"""Source-level guard only; actual Ghidra transaction/Undo acceptance is separate."""
from pathlib import Path

source = Path("src/main/java/ghidrassist/hardware/HardwareApplyService.java").read_text()
apply = source.split("public static Outcome apply(", 1)[1]
# Two approved memory candidates must not overlap even when both appear
# individually safe against the pre-Apply project database.
assert 'Hardware Apply ambiguous overlapping MEMORY approvals:' in apply
assert 'left.address <= right.last() && right.address <= left.last()' in apply
assert apply.index('Hardware Apply ambiguous overlapping MEMORY approvals:') < apply.index('Decision initial = preflight(program, item, approved);')

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

# A fully covered speculative TPURAM window may be entirely user-owned.
# Coverage must not short-circuit the ownership checks as ALREADY_PRESENT.
assert 'Entire TPURAM candidate range is mapped' not in _memory
assert 'Full coverage by unrelated user blocks is not proof that TPURAM' in _memory
assert _memory.index('!legacyPart(item,block)') < _memory.index('if(parts.isEmpty())')

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
assert "GA08 THIRD PROCESS NO COLLATERAL MEMORY PASS:" in _workflow

# Guard against escaped source line separators in the third-process Java and
# YAML shell gate: these compile/parse differently from actual newlines.
assert "\\n" not in _post
assert " ||\\n             ! grep -Fq 'GA08 THIRD PROCESS OWNERSHIP" not in _workflow
assert " ||\n             ! grep -Fq 'GA08 THIRD PROCESS OWNERSHIP" in _workflow

# Java 21 source gate must run before the genuine Java 25 Ghidra build.
assert 'GA-08 atomic Apply source regression (Java 21)' in _workflow
assert 'GA-08 Java 21 source regression environment' in _workflow
assert 'Restore Java 25 for Ghidra 12.1.4 build' in _workflow
assert _workflow.index('GA-08 Java 21 source regression environment') < _workflow.index('GA-08 atomic Apply source regression (Java 21)')
assert _workflow.index('GA-08 atomic Apply source regression (Java 21)') < _workflow.index('Restore Java 25 for Ghidra 12.1.4 build')
assert _workflow.index('Verify Java 25 for full extension build') < _workflow.index('Build complete GhidrAssist extension')

# Each rejected Apply checks BOTH persisted user blocks, including the peer
# that was not the target of the request.
assert 'for (int peer = 1; peer < 3; peer++)' in _post
assert 'refused Apply mutated unrelated user-owned block:' in _post
assert 'peerBlock.isRead() && peerBlock.isWrite()' in _post

# CS coverage is not authorization to accept executable, mapped or initialized
# user memory; check this before any ALREADY_PRESENT/MANUAL_REVIEW outcome.
_cs = _memory.split("if(csWindow(item)){", 1)[1].split("List<HardwareRegionLayout.Range> gaps=csMissing(item,parts);", 1)[0]
assert "block.isInitialized() || block.isMapped()" in _cs
assert "block.getType()!=MemoryBlockType.DEFAULT" in _cs
assert "block.isExecute() || !block.isRead() || !block.isWrite()" in _cs
assert "CS window overlaps incompatible user memory:" in _cs


# The real third-process witness constructs a synthetic CS-window candidate
# over a user-owned executable block and checks production preflight + Apply.
# This is not a claim that any physical CS device is present.
assert 'CS_WINDOW_%06X_%06X' in _post
assert 'csUser.setExecute(true)' in _post
assert 'csUser.setWrite(false)' in _post
assert 'csUser.setRead(false)' in _post
assert 'for (String permissionCase : permissionCases)' in _post
assert 'rejected CS Apply mutated peer user block' in _post
assert 'preflight.invoke(null, currentProgram, csCandidate' in _post
assert 'apply.invoke(null, currentProgram, List.of(csCandidate))' in _post
assert 'csUser.setExecute(originalExecute)' in _post
assert 'csUser.setWrite(originalWrite)' in _post
assert 'csUser.setRead(originalRead)' in _post
assert 'GA08 CS USER PERMISSION OVERLAP REFUSAL PASS: benign=1 executable=1 readonly=1 unreadable=1 volatile=1 restored=1' in _post
assert 'GA08 CS USER PERMISSION OVERLAP REFUSAL PASS: benign=1 executable=1 readonly=1 unreadable=1 volatile=1 restored=1' in _workflow

# The real CS refusal witness checks all memory blocks (including unrelated
# blocks), both after read-only preflight and after rejected production Apply.
assert 'java.util.function.Supplier<List<String>> inventory' in _post
assert 'for (MemoryBlock b : currentProgram.getMemory().getBlocks())' in _post
assert 'java.util.Collections.sort(rows)' in _post
assert 'production CS preflight mutated memory inventory:' in _post
assert 'rejected CS Apply changed memory inventory:' in _post
assert _post.index('List<String> beforeRefusal = inventory.get();') < _post.index('Object csDecision = preflight.invoke(')
assert _post.index('production CS preflight mutated memory inventory:') < _post.index('apply.invoke(null, currentProgram, List.of(csCandidate))')
assert _post.index('rejected CS Apply changed memory inventory:') > _post.index('apply.invoke(null, currentProgram, List.of(csCandidate))')

# CS refusal recovery is a positive production Apply control, not merely
# a sequence of negative preflight checks.
assert 'List<String> originalInventory = inventory.get();' in _post
assert 'inventory.get().equals(originalInventory)' in _post
assert 'Object afterCs = apply.invoke(null, currentProgram, List.of(memory.get(0)))' in _post
assert 'GA08 CS REFUSAL RECOVERY PASS: idempotent=1 inventory=1' in _post
assert 'GA08 CS REFUSAL RECOVERY PASS: idempotent=1 inventory=1' in _workflow
assert 'GA08 CS EXPLICIT POSITIVE APPLY PASS: review=1 created=1 idempotent=1' in _post
assert 'GA08 CS EXPLICIT POSITIVE APPLY PASS: review=1 created=1 idempotent=1' in _workflow
assert '"MANUAL_REVIEW".equals(positiveDecision' in _post
assert '"ALREADY_PRESENT".equals(secondDecision' in _post

# Volatile memory cannot be silently adopted as an MMIO/CS module.
assert "block.isVolatile()" in source
assert "existing.isVolatile()" in source
third = Path("tools/ghidra_scripts/GA08VerifyProductionApplyAfterRefusals.java").read_text()
assert '"volatile"' in third and "csUser.setVolatile(true)" in third
assert "csUser.setVolatile(originalVolatile)" in third
assert "b.isVolatile()" in third
assert "volatile=1 restored=1" in third

# CS ownership must be proven by generated fragment names, not by benign R/W flags.
assert 'boolean owned=block.getName().equals(item.name)' in _memory
assert 'java.util.regex.Pattern.quote(item.name)' in _memory
# Keep the ownership refusal anchored to the actual CS guard even when
# geometry checks are inserted between ownership and memory flags.
assert 'if(!owned || block.getStart().getOffset()<item.address ||' in _memory
assert 'block.getEnd().getOffset()>item.last() ||' in _memory
assert 'block.isInitialized() || block.isMapped() || block.isVolatile() ||' in _memory
assert _memory.index('boolean owned=block.getName().equals(item.name)') < _memory.index('if(!owned || block.getStart().getOffset()<item.address ||')
assert _memory.index('if(!owned || block.getStart().getOffset()<item.address ||') < _memory.index('"CS window overlaps incompatible user memory: "')
assert '"benign-user-owned"' in _post

# Boundary refusal must be enforced by the production service and genuine Ghidra gate.
_service = _Path("src/main/java/ghidrassist/hardware/HardwareApplyService.java").read_text()
assert 'block.getStart().getOffset()<item.address' in _service
assert 'block.getEnd().getOffset()>item.last()' in _service
assert 'usedNames.contains(name)' in _service
assert 'GA08 CS OUTSIDE WINDOW REFUSAL PASS: preflight=1 apply=1 restored=1' in _post
assert 'GA08 CS OUTSIDE WINDOW REFUSAL PASS: preflight=1 apply=1 restored=1' in _workflow

# Fourth independent read-only Ghidra process must observe the positive CS
# fragment persisted by the third process, not only an in-memory assertion.
_fourth = Path("tools/ghidra_scripts/GA08VerifyPositiveCsReopened.java").read_text()
assert 'ga08-synthetic.bin' in _fourth
assert 'CS_WINDOW_E00000_E0001F_PART_1' in _fourth
assert 'cs.getEnd().equals(space.getAddress(end))' in _fourth
assert 'GA08_USER_CONFLICT' in _fourth and 'GA08_USER_EXACT' in _fourth
assert 'GA08 FOURTH PROCESS POSITIVE CS PERSISTENCE PASS: fragment=1 user_controls=2' in _fourth
assert 'GA08VerifyPositiveCsReopened.java' in _workflow
assert 'GA08 FOURTH PROCESS POSITIVE CS PERSISTENCE PASS: fragment=1 user_controls=2' in _workflow
assert _workflow.index('GA08VerifyProductionApplyAfterRefusals.java') < _workflow.index('GA08VerifyPositiveCsReopened.java')
assert '-readOnly' in _workflow.split('GA08VerifyPositiveCsReopened.java')[0].split('GA-08 fourth independent reopen')[-1]

# The final headless script must use the production Apply transaction. The
# fourth independent read-only reopen, not a diagnostic marker, proves durability.
assert 'currentProgram.save(' not in _post
assert 'GA08 CS PERSISTENCE READY PASS: fragment=1' in _post
assert 'GA08 CS PERSISTENCE READY PASS: fragment=1' in _workflow
assert _post.index('GA08 CS PERSISTENCE READY PASS:') < _post.index('GA08 CS EXPLICIT POSITIVE APPLY PASS:')
_save = Path("tools/ghidra_scripts/GA08PersistPositiveCs.java").read_text()
assert 'ga08-synthetic.bin' in _save
# Ignore explanatory comments; reject executable save calls inside the postScript.\nassert not any(line.strip().startswith('currentProgram.save(') for line in _save.splitlines())
assert 'GA08 SAVE DIAGNOSTIC: programChanged=' in _save
assert 'CS_WINDOW_E00000_E0001F_PART_1' in _save
assert 'HardwareApplyService' in _save
assert 'MANUAL_REVIEW' in _save and 'ALREADY_PRESENT' in _save
assert 'GA08 FINAL TRANSACTION APPLY PASS: fragment=1' in _save
assert '-postScript GA08PersistPositiveCs.java' in _workflow
assert 'GA08 FINAL TRANSACTION APPLY PASS: fragment=1' in _workflow
assert _workflow.index('GA08VerifyProductionApplyAfterRefusals.java') < _workflow.index('GA08PersistPositiveCs.java') < _workflow.index('GA08VerifyPositiveCsReopened.java')

# The native Ghidra witnesses and synthetic binary generators are executable
# acceptance inputs. Editing them must trigger the same Java 21/25 and real
# synthetic Ghidra workflow as changes to production Apply code.
for _changed_input in ("tools/ghidra_scripts/**", "tools/generate-synthetic-*.py"):
    assert _workflow.count("      - '" + _changed_input + "'") == 2, (
        "missing push/PR integration trigger for " + _changed_input
    )

# Pushes to the active acceptance branch must execute the full integration
# workflow independently of pull_request events (including draft PRs).
_push = _workflow.split('  push:', 1)[1].split('  pull_request:', 1)[0]
assert 'work/ga08-atomic-apply-preflight-20261119' in _push
assert "      - 'tools/ghidra_scripts/**'" in _push
assert "      - 'tools/generate-synthetic-*.py'" in _push

# The production overlap guard must be witnessed in genuine disposable Ghidra,
# not just recognized as a source-code pattern.
_overlap = Path("tools/ghidra_scripts/GA08VerifyProductionApply.java").read_text()
assert 'getDeclaredConstructor(' in _overlap
assert 'GA08_DUPLICATE' in _overlap
assert 'GA08_PARTIAL' in _overlap
assert 'GA08_CONTAINED' in _overlap
assert 'overlapping MEMORY approvals' in _overlap
assert 'beforeRefusals.equals(inventory())' in _overlap
assert 'beforeContent.equals(contentFingerprint())' in _overlap
assert 'for (boolean reverse : new boolean[] {false, true})' in _overlap
assert 'List.of(conflicting, first)' in _overlap
assert 'GA08 OVERLAPPING MEMORY RUNTIME REFUSAL PASS: cases=' in _overlap
assert 'GA08 OVERLAPPING MEMORY RUNTIME REFUSAL PASS: cases=6' in _workflow

# Register rows must also have exclusive byte ownership across the approved batch.
assert 'overlapping REGISTER approvals' in _service
assert 'left.kind != HardwareApplyPlan.Kind.REGISTER' in _service
assert 'right.kind != HardwareApplyPlan.Kind.REGISTER' in _service
assert 'GA08_REGISTER_DUPLICATE' in _overlap
assert 'GA08_REGISTER_PARTIAL' in _overlap
assert 'GA08_REGISTER_CONTAINED' in _overlap
assert 'GA08_REGISTER_CONTAINING' in _overlap
assert 'GA08 OVERLAPPING REGISTER RUNTIME REFUSAL PASS: cases=' in _overlap
assert 'GA08 OVERLAPPING REGISTER RUNTIME REFUSAL PASS: cases=8' in _workflow

# Cross-kind typed writes must reject overlapping VBR and REGISTER approvals
# before any preceding MEMORY row can be committed.
assert 'ambiguous REGISTER/VBR approvals' in _service
assert 'register.kind != HardwareApplyPlan.Kind.REGISTER' in _service
assert 'vector.kind != HardwareApplyPlan.Kind.VBR_STRUCTURE' in _service
assert 'GA08_VECTOR_REGISTER' in _overlap
assert 'GA08 REGISTER VBR COLLISION REFUSAL PASS: cases=' in _overlap
assert 'GA08 REGISTER VBR COLLISION REFUSAL PASS: cases=2' in _workflow


# Competing VBR hypotheses are typed-memory claims, not proof of an active
# runtime vector base. Both orderings must fail before the mutation pass.
_vbr_guard = source.split("// Two VBR hypotheses may describe overlapping vector bytes.", 1)[1].split(
    "// Preflight the entire approved MEMORY batch", 1)[0]
assert "left.kind != HardwareApplyPlan.Kind.VBR_STRUCTURE" in _vbr_guard
assert "right.kind != HardwareApplyPlan.Kind.VBR_STRUCTURE" in _vbr_guard
assert "left.address <= right.last() && right.address <= left.last()" in _vbr_guard
assert "Hardware Apply ambiguous overlapping VBR approvals:" in _vbr_guard
assert source.index("Hardware Apply ambiguous overlapping VBR approvals:") < source.index(
    "// Preflight the entire approved MEMORY batch")

# Competing VBR proposals: genuine production Apply, both Review orders,
# immutable memory inventory and initialized-byte/symbol fingerprint.
assert 'GA08_VECTOR_DUPLICATE' in _overlap
assert 'GA08_VECTOR_PARTIAL' in _overlap
assert 'GA08_VECTOR_PARTIAL_FORWARD' in _overlap
assert 'GA08_VECTOR_PARTIAL_BACKWARD' in _overlap
# Every competing VBR row must retain the full 1024-byte typed geometry.
# Shorter 'contained' rows are rejected by the earlier geometry guard and
# cannot exercise the VBR/VBR collision branch.
assert 'vectorBase + 4, vectorLength' in _overlap
assert 'vectorBase - 4, vectorLength' in _overlap
assert 'vectorBase, vectorLength' in _overlap
assert 'GA08_VECTOR_CONTAINED' not in _overlap
assert 'ambiguous overlapping VBR approvals' in _overlap
assert 'List.of(first, conflict, vbrCollision)' in _overlap
assert 'List.of(first, vbrCollision, conflict)' in _overlap
assert 'beforeRefusals.equals(inventory())' in _overlap
assert 'beforeContent.equals(contentFingerprint())' in _overlap
assert 'GA08 INVALID VBR GEOMETRY REFUSAL PASS: cases=' in _overlap
assert 'GA08 INVALID VBR GEOMETRY REFUSAL PASS: cases=4' in _workflow
assert 'invalid VBR geometry' in apply
assert 'GA08 OVERLAPPING VBR RUNTIME REFUSAL PASS: cases=6' in _workflow

# The UI Review preflight and production Apply must agree on malformed VBR geometry.
assert "Invalid VBR geometry: requires aligned 1024-byte vector table" in _service
assert _service.index("Invalid VBR geometry: requires aligned 1024-byte vector table") < _service.index("VBR location unmapped or contains defined code/data")
assert 'Method preflight = service.getMethod("preflight"' in _overlap
assert 'malformed VBR Review preflight not BLOCKED' in _overlap

# Review must fail closed on an existing KEEP_HANDLER type collision before
# Apply enters its write transaction. This source gate is not a Ghidra runtime PASS.
_vbr_preflight = _service.split("public static Decision preflight(", 1)[1].split(
    "private static boolean createRegion(", 1)[0]
assert 'getDataType(' in _vbr_preflight
assert '"CPU32_VBR_256_VECTORS"' in _vbr_preflight
assert 'existingVectors.getLength()!=item.length' in _vbr_preflight
assert 'structure.getNumComponents()!=256' in _vbr_preflight
assert 'Incompatible existing VBR data type:' in _vbr_preflight
assert _vbr_preflight.index('Incompatible existing VBR data type:') < _vbr_preflight.index(
    'VBR location unmapped or contains defined code/data')
assert 'DataTypeConflictHandler.KEEP_HANDLER' in _service
assert 'Hardware Apply incompatible existing VBR data type:' in _service
