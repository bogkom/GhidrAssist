#@category GhidrAssist.Tests
# Synthetic-only Ghidra 12.1.4 CPU32 graph fixture bootstrap.
# Run once via Script Manager with synthetic-callgraph.bin active.
# No changes to user firmware or any other program.
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import Function

p = currentProgram
if p is None or p.getName() != "synthetic-callgraph.bin":
    raise RuntimeError("Refusing non-synthetic-callgraph program")
if p.getLanguageID().toString() != "68000:BE:32:CPU32":
    raise RuntimeError("CPU32 language required")
base = p.getAddressFactory().getDefaultAddressSpace()
manager = p.getFunctionManager()
tx = p.startTransaction("GA18 synthetic callgraph function bootstrap")
success = False
try:
    for i in range(20):
        entry = base.getAddress(0x100 + 0x30*i)
        if not p.getMemory().contains(entry):
            raise RuntimeError("Fixture not mapped at expected address: " + str(entry))
        if p.getListing().getInstructionAt(entry) is None:
            if not DisassembleCommand(entry, None, False).applyTo(p, monitor):
                raise RuntimeError("Disassembly failed at " + str(entry))
        existing = manager.getFunctionAt(entry)
        if existing is None:
            end = entry.add(0x0f)
            f = manager.createFunction("SYNTH_%02d" % i, entry,
                AddressSet(entry,end), SourceType.USER_DEFINED)
            if f is None:
                raise RuntimeError("Function creation failed at " + str(entry))
    if manager.getFunctionCount() < 20:
        raise RuntimeError("Expected >=20 functions, got " + str(manager.getFunctionCount()))
    success = True
finally:
    p.endTransaction(tx, success)
print("GA18 synthetic callgraph bootstrap: %s, functions=%d" %
      ("PASS" if success else "FAIL", manager.getFunctionCount()))
