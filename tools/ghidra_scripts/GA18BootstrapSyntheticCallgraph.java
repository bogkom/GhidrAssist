// @category GhidrAssist.Tests
// Native Ghidra Java script. Synthetic CPU32 fixture only; no Python/Jython.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class GA18BootstrapSyntheticCallgraph extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null ||
            !"synthetic-callgraph.bin".equals(currentProgram.getName())) {
            throw new IllegalStateException("Only synthetic-callgraph.bin is permitted");
        }
        if (!"68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString())) {
            throw new IllegalStateException("Expected Ghidra CPU32 language");
        }
        int tx = currentProgram.startTransaction("GA18 synthetic callgraph bootstrap");
        boolean commit = false;
        try {
            for (int i = 0; i < 20; ++i) {
                monitor.checkCancelled();
                Address entry = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(0x100L + 0x30L * i);
                if (!currentProgram.getMemory().contains(entry)) {
                    throw new IllegalStateException("Missing synthetic address: " + entry);
                }
                if (currentProgram.getListing().getInstructionAt(entry) == null) {
                    if (!new DisassembleCommand(entry, null, false)
                            .applyTo(currentProgram, monitor)) {
                        throw new IllegalStateException("Disassembly failed: " + entry);
                    }
                }
                Function existing = currentProgram.getFunctionManager().getFunctionAt(entry);
                if (existing == null) {
                    AddressSet body = new AddressSet(entry, entry.add(0x0fL));
                    Function created = currentProgram.getFunctionManager().createFunction(
                        "SYNTH_" + String.format("%02d", i), entry, body, SourceType.USER_DEFINED);
                    if (created == null) {
                        throw new IllegalStateException("Function creation failed: " + entry);
                    }
                }
            }
            commit = true;
            println("GA18 fixture: synthetic functions prepared; count=" +
                currentProgram.getFunctionManager().getFunctionCount());
        } finally {
            currentProgram.endTransaction(tx, commit);
        }
    }
}
