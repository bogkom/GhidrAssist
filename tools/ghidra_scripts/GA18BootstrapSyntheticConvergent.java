// @category GhidrAssist.Tests
// Undoable bootstrap restricted to the separate generated synthetic fixture.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class GA18BootstrapSyntheticConvergent extends GhidraScript {
    @Override protected void run() throws Exception {
        if(currentProgram == null || !"synthetic-convergent.bin".equals(currentProgram.getName()) ||
            !"68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString()))
            throw new IllegalStateException("Synthetic convergent CPU32 fixture required");
        int tx=currentProgram.startTransaction("GA18 convergent test fixture only");
        boolean commit=false;
        try {
            for(long offset:new long[]{0x100,0x130,0x160,0x190}) {
                monitor.checkCancelled();
                Address entry=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
                if(!currentProgram.getMemory().contains(entry))
                    throw new IllegalStateException("Missing fixture entry "+entry);
                if(currentProgram.getListing().getInstructionAt(entry)==null &&
                   !new DisassembleCommand(entry,null,false).applyTo(currentProgram,monitor))
                    throw new IllegalStateException("Failed to disassemble "+entry);
                if(currentProgram.getFunctionManager().getFunctionAt(entry)==null) {
                    var body=new AddressSet(entry,entry.add(0x0f));
                    if(currentProgram.getFunctionManager().createFunction(
                        "CONVERGENT_"+Long.toHexString(offset),entry,body,SourceType.USER_DEFINED)==null)
                        throw new IllegalStateException("Function not created "+entry);
                }
            }
            commit=true;
            println("GA18 CONVERGENT BOOTSTRAP PASS: functions=4");
        } finally {
            currentProgram.endTransaction(tx,commit);
        }
    }
}
