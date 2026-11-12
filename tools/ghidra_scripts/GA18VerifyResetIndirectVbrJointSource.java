// @category GhidrAssist.Tests
// Native isolated synthetic CPU32 source-only RESET/JSR/MOVEC correlation.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
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
                    0x200,0x206,0x208,0x20c,
                    0x240,0x242}) {
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
            function(0x240,0x243);
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
        decode(0x240,"JSR",0x4e91,2);
        check(currentProgram.getListing().getInstructionAt(at(0x240))
            .getFlowType().isComputed(),
            "unresolved computed JSR (A1) remains unknown and disconnected");

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
            // Production Report's immutable, non-durable source snapshot
            // is the only input accepted by Automation source pagination.
            Object inventory=selected.getClass().getField("sourceInventory").get(selected);
            check(inventory!=null,"production report retains bounded live source inventory");
            // New function-level coverage must be derived from the SAME
            // production Ghidra source inventory, not a test-only fixture.
            Class<?> correlation=Class.forName(
                "ghidrassist.hardware.HardwareResetIndirectVbrCorrelation",
                true,loader);
            Object coverage=correlation.getMethod("coverage",inventory.getClass())
                .invoke(null,inventory);
            Class<?> coverageType=coverage.getClass();
            int both=(Integer)coverageType.getMethod("functionsWithBoth")
                .invoke(coverage);
            int jsrOnly=(Integer)coverageType.getMethod("indirectOnlySites")
                .invoke(coverage);
            int vbrOnly=(Integer)coverageType.getMethod("vbrOnlySites")
                .invoke(coverage);
            boolean incomplete=(Boolean)coverageType.getMethod("inventoryIncomplete")
                .invoke(coverage);
            check(both==2 && jsrOnly==0 && vbrOnly==0 && incomplete,
                "real native JSR/MOVEC inventory coverage preserves omitted computed JSR");
            Method page=inventory.getClass().getMethod("page",int.class,int.class);
            Object firstPage=page.invoke(inventory,0,1);
            Method total=firstPage.getClass().getMethod("colocatedPairs");
            Method rows=firstPage.getClass().getMethod("rows");
            Method hasMore=firstPage.getClass().getMethod("hasMore");
            Method nextOffset=firstPage.getClass().getMethod("nextOffset");
            check(((Integer)total.invoke(firstPage))==2 &&
                ((java.util.List<?>)rows.invoke(firstPage)).size()==1 &&
                ((Boolean)hasMore.invoke(firstPage)) &&
                ((Integer)nextOffset.invoke(firstPage))==1,
                "production native source inventory first page is complete and bounded");
            Object secondPage=page.invoke(inventory,1,1);
            check(((Integer)total.invoke(secondPage))==2 &&
                ((java.util.List<?>)rows.invoke(secondPage)).size()==1 &&
                !((Boolean)hasMore.invoke(secondPage)) &&
                ((Integer)nextOffset.invoke(secondPage))==2,
                "production native inventory second page is stable and exhaustive");
            Object lastPage=page.invoke(inventory,2,1);
            check(((java.util.List<?>)rows.invoke(lastPage)).isEmpty() &&
                !((Boolean)hasMore.invoke(lastPage)),
                "production native inventory end page does not repeat sources");
            String join=section(report,
                "## RESET / indirect MMIO / VBR source co-location",
                "## Bounded same-function JSR / MOVEC CFG routes");
            String cfg=section(report,
                "## Bounded same-function JSR / MOVEC CFG routes",
                "## ");
            check(join.contains("omitted indirect witnesses: 1") &&
                join.contains("INCOMPLETE SOURCE INVENTORY/DISPLAY"),
                "one unproven computed JSR is counted as omitted/UNKNOWN, "
                +"not an absent indirect call or missing MMIO conclusion");
            check(join.contains("page offset: 0") &&
                join.contains("page limit: 32") &&
                join.contains("next offset: 2") &&
                join.contains("has more pages: false"),
                "same-Program production join publishes exact bounded page metadata");
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
            check(report.contains(
                    "Initial SSP source quality: ALIGNED_BUT_MEMORY_UNVERIFIED") &&
                    report.contains("NOT proof of mapped RAM") &&
                    report.contains("0x00FFF7FC"),
                "native selected MC68332 report separates valid source SSP from RAM/execution proof");
            // A real synthetic Ghidra Program with a CPU32 32-bit PC whose
            // high byte is set must NOT be turned into a selected MC68332
            // 24-bit RESET root by truncating its address. The same bytes
            // remain a generic CPU32 (wide) source observation. The project
            // is isolated and the original fixture bytes are restored.
            Method resetGate=service.getDeclaredMethod("resetStaticCandidates",
                Program.class,java.util.List.class,java.util.List.class,boolean.class);
            resetGate.setAccessible(true);
            byte originalPcHigh=currentProgram.getMemory().getByte(at(4));
            check(originalPcHigh==0,"synthetic original vector high byte");
            int mutateVector=currentProgram.startTransaction(
                "GA18 isolated high-PC vector source probe");
            try{
                currentProgram.getMemory().setByte(at(4),(byte)1);
            }finally{
                currentProgram.endTransaction(mutateVector,true);
            }
            try{
                Object selectedHigh=resetGate.invoke(null,currentProgram,
                    java.util.List.of(),java.util.List.of(),true);
                Method resetMd=selectedHigh.getClass().getDeclaredMethod("markdown");
                resetMd.setAccessible(true);
                String selectedText=(String)resetMd.invoke(selectedHigh);
                check(selectedText.contains(
                        "UNKNOWN RESET ROOT — SELECTED MC68332 24-BIT SOURCE BOUND") &&
                        selectedText.contains("0x01000100") &&
                        selectedText.contains("No Ghidra function/RESET CALL graph"),
                    "native selected MC68332 refuses a high-PC physical alias");
                Object genericHigh=resetGate.invoke(null,currentProgram,
                    java.util.List.of(),java.util.List.of(),false);
                String genericText=(String)resetMd.invoke(genericHigh);
                check(genericText.contains("0x01000100") &&
                        !genericText.contains("SELECTED MC68332 24-BIT SOURCE BOUND"),
                    "native generic CPU32 does not inherit MC68332 physical limit");
            }finally{
                int restoreVector=currentProgram.startTransaction(
                    "GA18 restore isolated CPU32 reset vector bytes");
                try{
                    currentProgram.getMemory().setByte(at(4),originalPcHigh);
                }finally{
                    currentProgram.endTransaction(restoreVector,true);
                }
            }
            check(currentProgram.getMemory().getByte(at(4))==originalPcHigh,
                "original isolated synthetic RESET vector byte restored");
            println("GA18 REAL MC68332 RESET SOURCE-SCOPE PASS: highPcRefused=1 genericWide=1 stackSource=1");
            // Mutation occurs inside the ACTUAL production Analyze call,
            // after its revision capture and after N real TaskMonitor
            // checkpoints. A separate, isolated Program transaction changes
            // Ghidra's own modification number (not any test-only token).
            // The method must throw, never return a stale partial Report.
            for(int trigger:new int[]{1,12}) {
                AtomicInteger ticks=new AtomicInteger();
                AtomicBoolean changed=new AtomicBoolean(false);
                long before=currentProgram.getModificationNumber();
                TaskMonitor injecting=(TaskMonitor)Proxy.newProxyInstance(
                    TaskMonitor.class.getClassLoader(),
                    new Class<?>[]{TaskMonitor.class},
                    (proxy,method,args)->{
                        if(method.getName().equals("checkCancelled") &&
                                ticks.incrementAndGet()==trigger) {
                            int edit=currentProgram.startTransaction(
                                "GA18 isolated revision-in-flight probe "+trigger);
                            try {
                                currentProgram.getListing().setComment(
                                    at(0x100),CodeUnit.EOL_COMMENT,
                                    "GA18 isolated revision probe "+trigger);
                            } finally {
                                currentProgram.endTransaction(edit,true);
                            }
                            changed.set(true);
                        }
                        try { return method.invoke(monitor,args); }
                        catch(InvocationTargetException e){throw e.getCause();}
                    });
                boolean refused=false;
                try {
                    Object stale=analyze.invoke(instance,currentProgram,
                        injecting,true);
                    throw new IllegalStateException(
                        "Production Analyze returned instead of rejecting stale revision");
                } catch(InvocationTargetException e) {
                    Throwable cause=e.getCause();
                    refused=cause!=null &&
                        (cause.getClass().getName().contains("StaleRevision") ||
                         cause instanceof ghidra.util.exception.CancelledException);
                    if(!refused)
                        throw new IllegalStateException(
                            "Unexpected native revision probe exception",cause);
                }
                check(changed.get() && ticks.get()>=trigger &&
                    currentProgram.getModificationNumber()!=before,
                    "real Ghidra Program revision mutated after "+
                    trigger+" native monitor checks");
                check(refused,
                    "in-flight edit rejects complete source report: "+
                    trigger+" checks (no stale Markdown or Report escaped)");
            }
        }
        // A completed Automation source-page cursor is invalidated by an
        // explicit GA-12 stage clear even without another Program edit.
        try(URLClassLoader loader=new URLClassLoader(
                new URL[]{Path.of(jar).toUri().toURL()},bridge)) {
            Class<?> stages=Class.forName(
                "ghidrassist.hardware.HardwareFlowStageCache",true,loader);
            long epoch=(Long)stages.getMethod("sourcePageEpoch",Program.class)
                .invoke(null,currentProgram);
            boolean before=(Boolean)stages.getMethod("sourcePageEpochCurrent",
                Program.class,long.class).invoke(null,currentProgram,epoch);
            check(before,"native source-page epoch is current before clear");
            stages.getMethod("clear",Program.class).invoke(null,currentProgram);
            boolean after=(Boolean)stages.getMethod("sourcePageEpochCurrent",
                Program.class,long.class).invoke(null,currentProgram,epoch);
            check(!after,"native GA-12 explicit stage clear invalidates source page");
        }
        println("GA18 REAL JOINT SOURCE PAGE PASS: pairs=2 pages=2 stale_epoch=1");
        println("GA18 REAL JOINT REVISION REFUSAL PASS: injected=2 unresolved=1");
        println("GA18 REAL RESET JSR MOVEC JOINT PASS: assertions="+checks+
            " (two native CPU32 source pairs, unresolved JSR, branching CFG, "+
            "two real Ghidra in-flight revision mutations, RESET subset, "+
            "MM MAY, generic CPU32 refusal; STATIC ONLY)");
    }
}
