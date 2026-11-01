// @category GhidrAssist.Tests
// Isolated synthetic CPU32 only; creates two functions in one undoable transaction.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class GA18BootstrapSyntheticIndirectConstant extends GhidraScript {
    @Override protected void run() throws Exception {
        if(currentProgram==null || !"synthetic-indirect-constant.bin".equals(currentProgram.getName()) ||
           !"68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString()))
            throw new IllegalStateException("Synthetic indirect CPU32 fixture required");
        int tx=currentProgram.startTransaction("GA18 indirect synthetic fixture only");
        boolean commit=false;
        try {
            for(long off:new long[]{0x100,0x130}) {
                monitor.checkCancelled();
                var addr=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
                if(!currentProgram.getMemory().contains(addr))
                    throw new IllegalStateException("Missing fixture function "+addr);
                if(currentProgram.getListing().getInstructionAt(addr)==null &&
                   !new DisassembleCommand(addr,null,false).applyTo(currentProgram,monitor))
                    throw new IllegalStateException("Disassembly failed at "+addr);
                if(currentProgram.getFunctionManager().getFunctionAt(addr)==null) {
                    var body=new AddressSet(addr,addr.add(0x0f));
                    if(currentProgram.getFunctionManager().createFunction(
                       "INDIRECT_"+Long.toHexString(off),addr,body,SourceType.USER_DEFINED)==null)
                        throw new IllegalStateException("Cannot create function "+addr);
                }
            }
            commit=true;
            println("GA18 INDIRECT CONSTANT BOOTSTRAP PASS: functions=2");
        } finally {
            currentProgram.endTransaction(tx,commit);
        }
    }
}
