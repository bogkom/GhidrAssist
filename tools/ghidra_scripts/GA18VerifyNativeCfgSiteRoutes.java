// @category GhidrAssist.Tests
// Isolated real Ghidra 12.1.4 CPU32 Listing CFG; static-only source evidence.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class GA18VerifyNativeCfgSiteRoutes extends GhidraScript {
    private int assertions;

    private void check(boolean valid,String message) {
        assertions++;
        if(!valid)throw new IllegalStateException(
            "GA18 NATIVE CFG ROUTES FAIL: "+message);
    }
    private Address at(long pc) {
        return currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(pc);
    }
    private Instruction instruction(long pc,String mnemonic,int word)
            throws Exception {
        Instruction insn=currentProgram.getListing().getInstructionAt(at(pc));
        check(insn!=null,"Real Ghidra disassembly at "+Long.toHexString(pc));
        String decoded=insn.getMnemonicString().toUpperCase(java.util.Locale.ROOT);
        String base=mnemonic.toUpperCase(java.util.Locale.ROOT);
        // CPU32 Sleigh may render a size suffix (BNE.B / BRA.B).
        // Exact opcode word is asserted independently below.
        check(decoded.equals(base) || decoded.startsWith(base+"."),
            "Ghidra decoded "+decoded+" expected "+base+
            " at "+Long.toHexString(pc));
        check((currentProgram.getMemory().getShort(at(pc))&0xffff)==word,
            "CPU32 source bytes match "+Long.toHexString(pc));
        check(insn.getLength()==2,"CPU32 short instruction length");
        return insn;
    }
    private List<Long> successors(Instruction insn,Set<Long> body) {
        LinkedHashSet<Long> next=new LinkedHashSet<>();
        Address fall=insn.getFallThrough();
        if(fall!=null && body.contains(fall.getOffset()))
            next.add(fall.getOffset());
        if(!insn.getFlowType().isCall())
            for(Address edge:insn.getFlows())
                if(body.contains(edge.getOffset()))
                    next.add(edge.getOffset());
        return new ArrayList<>(next);
    }
    private List<Object> realNodes(Constructor<?> constructor,long[] pcs,
            String[] mnemonics,int[] words,long[][] expected) throws Exception {
        Set<Long> body=new LinkedHashSet<>();
        for(long pc:pcs)body.add(pc);
        List<Object> nodes=new ArrayList<>();
        for(int i=0;i<pcs.length;i++){
            monitor.checkCancelled();
            Instruction insn=instruction(pcs[i],mnemonics[i],words[i]);
            List<Long> edges=successors(insn,body);
            check(new LinkedHashSet<>(edges).equals(toSet(expected[i])),
                "Ghidra actual CFG successors at "+Long.toHexString(pcs[i])+
                ": "+edges+" expected "+toSet(expected[i]));
            nodes.add(constructor.newInstance(pcs[i],edges));
        }
        return nodes;
    }
    private Set<Long> toSet(long[] pcs) {
        LinkedHashSet<Long> set=new LinkedHashSet<>();
        for(long pc:pcs)set.add(pc);
        return set;
    }
    private void relation(Method inspect,long entry,List<Object> nodes,
            boolean complete,long a,long b,String expected) throws Exception {
        Object answer=inspect.invoke(null,entry,nodes,complete,a,b);
        check(expected.equals(answer.toString()),
            "CFG relation expected "+expected+" got "+answer);
    }
    @Override protected void run() throws Exception {
        check(currentProgram!=null &&
            "synthetic-cfg-routes.bin".equals(currentProgram.getName()),
            "Only generated synthetic CPU32 test image");
        check("68000:BE:32:CPU32".equals(
            currentProgram.getLanguageID().toString()),"CPU32 language");
        String jar=System.getProperty("ga18.test.jar","");
        check(!jar.isBlank(),"Exact extension under test required");
        // Actual Ghidra DisassembleCommand populates Listing instruction
        // boundaries and flows: no handwritten CFG supplied as test input.
        int tx=currentProgram.startTransaction("GA18 native synthetic CFG bytes");
        boolean committed=false;
        try {
            // -noanalysis intentionally does not pursue every conditional
            // branch destination. Explicitly disassemble each reviewed
            // instruction site, then read native Ghidra flow metadata.
            for(long entry:new long[]{
                    0x100L,0x102L,0x104L,0x108L,0x10aL,
                    0x140L,0x142L,0x144L,0x146L,0x148L,
                    0x180L,0x182L,0x184L,
                    0x1c0L,0x1c2L,0x1c4L}) {
                monitor.checkCancelled();
                if(currentProgram.getListing().getInstructionAt(at(entry))==null)
                    check(new DisassembleCommand(at(entry),null,false)
                        .applyTo(currentProgram,monitor),
                        "Ghidra disassemble "+Long.toHexString(entry));
            }
            committed=true;
        } finally {
            currentProgram.endTransaction(tx,committed);
        }
        try(URLClassLoader loader=new URLClassLoader(
                new URL[]{Path.of(jar).toUri().toURL()},
                getClass().getClassLoader())) {
            Class<?> node=Class.forName(
                "ghidrassist.hardware.HardwareCfgSiteOrder$Node",true,loader);
            Class<?> analyzer=Class.forName(
                "ghidrassist.hardware.HardwareCfgSiteOrder",true,loader);
            Constructor<?> constructor=node.getConstructor(long.class,List.class);
            Method inspect=analyzer.getMethod("inspect",
                long.class,List.class,boolean.class,long.class,long.class);

            var diamond=realNodes(constructor,
                new long[]{0x100,0x102,0x104,0x108,0x10a},
                new String[]{"BNE","NOP","BRA","NOP","RTS"},
                new int[]{0x6606,0x4e71,0x6004,0x4e71,0x4e75},
                new long[][]{{0x102,0x108},{0x104},{0x10a},
                    {0x10a},{}});
            relation(inspect,0x100,diamond,true,0x102,0x108,
                "NO_OBSERVED_ORDERED_ROUTE");
            relation(inspect,0x100,diamond,true,0x102,0x10a,
                "POSSIBLE_JSR_BEFORE_MOVEC");
            relation(inspect,0x100,diamond,true,0x10a,0x102,
                "POSSIBLE_MOVEC_BEFORE_JSR");

            var loop=realNodes(constructor,
                new long[]{0x140,0x142,0x144,0x146,0x148},
                new String[]{"NOP","BNE","NOP","BRA","RTS"},
                new int[]{0x4e71,0x6604,0x4e71,0x60fa,0x4e75},
                new long[][]{{0x142},{0x144,0x148},{0x146},
                    {0x142},{}});
            relation(inspect,0x140,loop,true,0x142,0x146,
                "POSSIBLE_BOTH_ORDERS");
            relation(inspect,0x140,loop,true,0x148,0x142,
                "POSSIBLE_MOVEC_BEFORE_JSR");

            var linear=realNodes(constructor,
                new long[]{0x180,0x182,0x184},
                new String[]{"NOP","NOP","RTS"},
                new int[]{0x4e71,0x4e71,0x4e75},
                new long[][]{{0x182},{0x184},{}});
            relation(inspect,0x180,linear,true,0x180,0x184,
                "POSSIBLE_JSR_BEFORE_MOVEC");
            relation(inspect,0x180,linear,false,0x180,0x184,
                "UNKNOWN");

            Instruction indirect=instruction(0x1c0,"JMP",0x4ed0);
            check(indirect.getFlowType().isComputed(),
                "Real computed JMP remains computed, not direct edge");
            var computed=realNodes(constructor,
                new long[]{0x1c0,0x1c2,0x1c4},
                new String[]{"JMP","NOP","RTS"},
                new int[]{0x4ed0,0x4e71,0x4e75},
                new long[][]{{},{0x1c4},{}});
            relation(inspect,0x1c0,computed,true,0x1c0,0x1c2,
                "UNKNOWN");
            relation(inspect,0x1c0,computed,false,0x1c0,0x1c2,
                "UNKNOWN");
            relation(inspect,0x100,diamond,true,0x102,0x106,
                "UNKNOWN");
        }
        println("GA18 NATIVE CFG SITE ROUTES PASS: assertions="+assertions+
            " (real Ghidra 12.1.4 CPU32 BNE/BRA cycle and computed JMP; "+
            "static CFG only, no firmware/hardware execution)");
    }
}
