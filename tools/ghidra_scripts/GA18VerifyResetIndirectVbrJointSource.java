// @category GhidrAssist.Tests
// Native isolated synthetic CPU32 source-only RESET/JSR/MOVEC correlation.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;

public class GA18VerifyResetIndirectVbrJointSource extends GhidraScript {
    private int checks;
    private void check(boolean ok,String label) {
        checks++;
        if(!ok)throw new IllegalStateException(
            "GA18 RESET JSR MOVEC JOIN FAIL: "+label);
    }
    private Address at(long pc) {
        return currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(pc);
    }
    private void decode(long pc,String mnemonic,int firstWord,int length)
            throws Exception {
        Instruction i=currentProgram.getListing().getInstructionAt(at(pc));
        check(i!=null,"decoded actual Listing site "+Long.toHexString(pc));
        String name=i.getMnemonicString().toUpperCase(java.util.Locale.ROOT);
        check(name.equals(mnemonic) || name.startsWith(mnemonic+"."),
            "Ghidra "+mnemonic+" site "+Long.toHexString(pc)+": "+name);
        check((currentProgram.getMemory().getShort(at(pc))&0xffff)==firstWord,
            "exact source opcode at "+Long.toHexString(pc));
        check(i.getLength()==length,"native CPU32 length at "+Long.toHexString(pc));
    }
    private Function function(long entry,long end) throws Exception {
        Function f=currentProgram.getFunctionManager().getFunctionAt(at(entry));
        if(f==null)f=currentProgram.getFunctionManager().createFunction(
            "GA18_"+Long.toHexString(entry),at(entry),
            new AddressSet(at(entry),at(end)),SourceType.USER_DEFINED);
        check(f!=null && f.getEntryPoint().getOffset()==entry &&
            f.getBody().getNumAddresses()==end-entry+1,
            "exact synthetic function boundary "+Long.toHexString(entry));
        return f;
    }
    private String section(String full,String header,String next) {
        int start=full.indexOf(header);
        check(start>=0,"production section "+header);
        int finish=next==null?-1:full.indexOf(next,start+header.length());
        return full.substring(start,finish>=0?finish:full.length());
    }
    @Override protected void run() throws Exception {
        check(currentProgram!=null &&
            "synthetic-reset-indirect-vbr.bin".equals(currentProgram.getName()),
            "isolated fixture identity");
        check("68000:BE:32:CPU32".equals(
            currentProgram.getLanguageID().toString()),"CPU32 language");
        String jar=System.getProperty("ga18.test.jar","");
        check(!jar.isBlank(),"built extension jar");
        int tx=currentProgram.startTransaction("GA18 isolated CPU32 join bootstrap");
        boolean commit=false;
        try {
            for(long pc:new long[]{
                    0x100,0x106,
                    0x130,0x132,0x138,0x13a,0x13c,0x13e,
                    0x140,0x142,0x144,0x148,0x14a,
                    0x180,0x188,
                    0x200,0x206,0x208,0x20c}) {
                monitor.checkCancelled();
                if(currentProgram.getListing().getInstructionAt(at(pc))==null)
                    check(new DisassembleCommand(at(pc),null,false)
                        .applyTo(currentProgram,monitor),
                        "Ghidra disassembly "+Long.toHexString(pc));
            }
            function(0x100,0x107);
            function(0x130,0x14b);
            function(0x180,0x189);
            function(0x200,0x20d);
            commit=true;
        } finally {
            currentProgram.endTransaction(tx,commit);
        }
        decode(0x100,"JSR",0x4eb9,6);
        decode(0x130,"BNE",0x6612,2);
        decode(0x132,"MOVEA",0x207c,6);
        decode(0x138,"JSR",0x4e90,2);
        decode(0x13a,"BRA",0x600e,2);
        decode(0x144,"MOVEC",0x4e7b,4);
        decode(0x14a,"RTS",0x4e75,2);
        decode(0x180,"MOVE",0x33fc,8);
        decode(0x200,"MOVEA",0x207c,6);
        decode(0x206,"JSR",0x4e90,2);
        decode(0x208,"MOVEC",0x4e7b,4);

        Instruction branch=currentProgram.getListing().getInstructionAt(at(0x130));
        Set<Long> branchEdges=new LinkedHashSet<>();
        if(branch.getFallThrough()!=null)
            branchEdges.add(branch.getFallThrough().getOffset());
        for(Address flow:branch.getFlows())branchEdges.add(flow.getOffset());
        check(branchEdges.equals(Set.of(0x132L,0x144L)),
            "real CPU32 branch separates indirect JSR and MOVEC sources");
        Instruction skip=currentProgram.getListing().getInstructionAt(at(0x13a));
        check(skip.getFlows().length==1 &&
            skip.getFlows()[0].getOffset()==0x14aL,
            "real BRA escapes MOVEC arm");

        // Reuse Ghidra module-owning class loaders, not duplicate Ghidra APIs
        // in an artifact-jar URLClassLoader.
        final ClassLoader[] owners={
            ghidra.program.model.pcode.PcodeOp.class.getClassLoader(),
            Program.class.getClassLoader(),
            ghidra.program.model.lang.Register.class.getClassLoader(),
            ghidra.program.model.mem.MemoryAccessException.class.getClassLoader(),
            Address.class.getClassLoader(),
            ghidra.program.model.scalar.Scalar.class.getClassLoader(),
            ghidra.program.model.symbol.Reference.class.getClassLoader(),
            ghidra.util.exception.CancelledException.class.getClassLoader(),
            TaskMonitor.class.getClassLoader(),
            GhidraScript.class.getClassLoader()
        };
        ClassLoader bridge=new ClassLoader(getClass().getClassLoader()){
            @Override protected Class<?> loadClass(String name,boolean resolve)
                    throws ClassNotFoundException {
                if(name.startsWith("ghidra."))
                    for(ClassLoader owner:owners) {
                        if(owner==null)continue;
                        try{return owner.loadClass(name);}
                        catch(ClassNotFoundException ignored){}
                    }
                return super.loadClass(name,resolve);
            }
        };
        try(URLClassLoader loader=new URLClassLoader(
                new URL[]{Path.of(jar).toUri().toURL()},bridge)) {
            Class<?> service=Class.forName(
                "ghidrassist.hardware.GhidraHardwareFlowService",true,loader);
            Object instance=service.getConstructor().newInstance();
            Method analyze=service.getMethod("analyze",
                Program.class,TaskMonitor.class,boolean.class);
            Field markdown=null;
            Object generic=analyze.invoke(instance,currentProgram,monitor,false);
            markdown=generic.getClass().getField("markdown");
            String raw=(String)markdown.get(generic);
            check(raw.contains("Not evaluated: explicit MC68332 profile required"),
                "generic CPU32 cannot infer SIMCR/MM source");
            String genericJoin=section(raw,
                "## RESET / indirect MMIO / VBR source co-location",null);
            check(genericJoin.contains("Not evaluated: explicit MC68332"),
                "generic CPU32 joint-source refusal");

            Object selected=analyze.invoke(instance,currentProgram,monitor,true);
            String report=(String)markdown.get(selected);
            String join=section(report,
                "## RESET / indirect MMIO / VBR source co-location",
                "## Bounded same-function JSR / MOVEC CFG routes");
            String cfg=section(report,
                "## Bounded same-function JSR / MOVEC CFG routes",
                "## ");
            check(join.contains("co-located pairs: 2"),
                "two independently source-witnessed co-located pairs");
            check(join.contains("0x00000130 | 0x00000138 | 0x00000180 | 0x00000144"),
                "RESET subset function JSR and MOVEC exact source identity");
            check(join.contains("0x00000200 | 0x00000206 | 0x00000180 | 0x00000208"),
                "disconnected function exact independent JSR/MOVEC source");
            check(join.contains("IN_OBSERVED_RESET_CALL_SUBSET") &&
                join.contains("OUTSIDE_OBSERVED_RESET_CALL_SUBSET") &&
                join.contains("STATIC SAME-FUNCTION SOURCE CO-LOCATION ONLY"),
                "static RESET relation classified, never execution");
            check(join.contains("STATIC_MAY_MM"),
                "MMIO STORE in computed target is MAY evidence, never write proof");
            check(cfg.contains("0x00000130 | 0x00000138 | 0x00000144 | NO_OBSERVED_ORDERED_ROUTE"),
                "branch-separated native JSR/MOVEC CFG sources");
            check(cfg.contains("0x00000200 | 0x00000206 | 0x00000208 | POSSIBLE_JSR_BEFORE_MOVEC"),
                "disconnected function has possible JSR before MOVEC");
            check(cfg.contains("CALL fallthrough") &&
                cfg.contains("does not prove callee return"),
                "no executed JSR / selected VBR / active MM conclusion");
        }
        println("GA18 REAL RESET JSR MOVEC JOINT PASS: assertions="+checks+
            " (two native CPU32 source pairs, branching CFG, RESET subset, "+
            "MM MAY, generic CPU32 refusal; STATIC ONLY)");
    }
}
