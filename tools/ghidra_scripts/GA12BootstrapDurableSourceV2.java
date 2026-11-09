// @category GhidrAssist.Tests
// GA-12: isolate and SAVE only a byte-exact synthetic CPU32 Ghidra Program.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
public class GA12BootstrapDurableSourceV2 extends GhidraScript {
    private static void require(boolean ok,String name){
        if(!ok)throw new IllegalStateException("GA12 SOURCE V2 BOOTSTRAP FAIL: "+name);
    }
    @Override protected void run()throws Exception {
        require(currentProgram!=null &&
            "synthetic-reset-indirect-vbr.bin".equals(currentProgram.getName()),
            "exact isolated fixture");
        require("68000:BE:32:CPU32".equals(
            currentProgram.getLanguageID().toString()),"CPU32");
        int tx=currentProgram.startTransaction("GA12 source V2 synthetic fixture");
        boolean commit=false;
        try {
            var space=currentProgram.getAddressFactory().getDefaultAddressSpace();
            for(long pc:new long[]{
                0x100L,0x106L,0x130L,0x132L,0x138L,0x13aL,
                0x13cL,0x13eL,0x140L,0x142L,0x144L,0x148L,
                0x14aL,0x180L,0x188L,0x200L,0x206L,
                0x208L,0x20cL,0x240L,0x242L}) {
                var at=space.getAddress(pc);
                require(currentProgram.getListing().getInstructionAt(at)!=null ||
                    new DisassembleCommand(at,null,false).applyTo(
                        currentProgram,TaskMonitor.DUMMY),
                    "real Listing CPU32 disassembly "+Long.toHexString(pc));
            }
            for(long[] body:new long[][]{
                {0x100L,0x107L},{0x130L,0x14bL},
                {0x180L,0x189L},{0x200L,0x20dL},
                {0x240L,0x243L}}){
                var start=space.getAddress(body[0]);
                var fn=currentProgram.getFunctionManager().getFunctionAt(start);
                if(fn==null)fn=currentProgram.getFunctionManager().createFunction(
                    "GA12_"+Long.toHexString(body[0]),start,
                    new AddressSet(start,space.getAddress(body[1])),
                    SourceType.USER_DEFINED);
                require(fn!=null && fn.getBody().getNumAddresses()==
                    body[1]-body[0]+1,"native function "+Long.toHexString(body[0]));
            }
            commit=true;
        }finally{currentProgram.endTransaction(tx,commit);}
        require(currentProgram.getMemory().getShort(
            currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(0x138))==(short)0x4e90,"byte-verified JSR");
        require(currentProgram.getMemory().getShort(
            currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(0x144))==(short)0x4e7b,"byte-verified MOVEC");
        println("GA12 SOURCE V2 REAL GHIDRA BOOTSTRAP PASS: functions=5");
    }
}
