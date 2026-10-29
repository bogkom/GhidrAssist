package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Read-only CFG/P-code register-write evidence. Each site describes a
 * possible store in one recognized function, NOT a runtime instruction
 * trace, feasible branch, or interprocedural state transfer.
 */
public final class HardwareCfgWriteAudit {
    private HardwareCfgWriteAudit() {}
    public static final int MAX_SHOWN=100;

    public enum PriorSimcr {
        NO_MATCH_IN_MODELED_FUNCTION_PREFIX,
        POSSIBLE_MATCH_ON_SOME_CFG_PATHS,
        MATCH_ON_EVERY_MODELED_CFG_PATH,
        UNKNOWN_DUE_TO_BARRIER_OR_LIMIT
    }
    public record Site(long function, long pc, String register, long address,
                       boolean indirect, int widthBits, Integer literal,
                       int priorSimcrMin, int priorSimcrMax,
                       boolean unknownCall, boolean unknownStore,
                       boolean functionIncomplete) {}
    public record Finding(long function,long pc,String register,long address,
                          boolean indirect,int widthBits,Integer literal,
                          PriorSimcr simcrPrefix,boolean mayAliasAnyMmio,
                          Integer mmLiteralBit) {
        public boolean fullWordLiteral(){
            return widthBits==16 && literal!=null;
        }
    }
    public record Report(List<Finding> sites,int fullWordLiterals,
                         int partialOrUnresolvedWrites,int indirectStores,
                         int unresolvedAliases,boolean analysisIncomplete) {
        public Report {sites=List.copyOf(sites);}
        public String markdown(){
            StringBuilder b=new StringBuilder();
            b.append("## CFG/P-code MMIO store candidates and SIMCR prefix evidence\n\n")
             .append("- Static candidate stores: ").append(sites.size())
             .append("; full 16-bit literals: ").append(fullWordLiterals)
             .append("; partial/unknown-width/value: ")
             .append(partialOrUnresolvedWrites)
             .append("; indirect resolved candidates: ").append(indirectStores)
             .append("; unresolved pointer/alias stores: ")
             .append(unresolvedAliases).append("; graph or dataflow incomplete: ")
             .append(analysisIncomplete).append(".\n")
             .append("- **Only reachable in a modeled intraprocedural CFG**; ")
             .append("no feasibility proof, execution count, branch ordering ")
             .append("or interprocedural register state is established.\n")
             .append("- SIMCR prefix states count possible matching static stores ")
             .append("before each instruction **within its function**. ")
             .append("Unknown calls, unknown pointer destinations and truncation ")
             .append("prevent conclusions about a real first write. ")
             .append("MM is write-once; its hardware latch remains UNKNOWN.\n")
             .append("- A byte/long/unknown-size write cannot be decoded ")
             .append("as a known 16-bit register word. The MM literal bit ")
             .append("is meaningful only when MC68332 was explicitly selected; ")
             .append("even then it is not the active hardware MM state.\n")
             .append("- Results supplement, rather than replace or combine as ")
             .append("a runtime sequence with, the direct XREF inventory. ")
             .append("No CSBAR/CSOR state is assembled across branches/functions.\n\n")
             .append("| Function | PC | Register candidate | Address | Access | Width | ")
             .append("16-bit literal | Prior SIMCR in function | MM literal |\n")
             .append("|---|---|---|---|---|---|---|---|---|\n");
            for(int i=0;i<Math.min(sites.size(),MAX_SHOWN);i++){
                Finding f=sites.get(i);
                b.append("| ").append(hex(f.function()))
                 .append(" | ").append(hex(f.pc()))
                 .append(" | ").append(f.register())
                 .append(" | ").append(f.address()<0?"UNKNOWN":hex(f.address()))
                 .append(" | ").append(f.indirect()?"INDIRECT":"DIRECT")
                 .append(" | ").append(f.widthBits())
                 .append(" | ").append(f.fullWordLiteral() ?
                     String.format(Locale.ROOT,"0x%04X",f.literal()):"UNKNOWN")
                 .append(" | ").append(f.simcrPrefix())
                 .append(" | ").append(f.mmLiteralBit()==null?"UNKNOWN":
                     f.mmLiteralBit()+" (source literal only)")
                 .append(" |\n");
            }
            if(sites.size()>MAX_SHOWN)
                b.append("\n- ").append(sites.size()-MAX_SHOWN)
                 .append(" additional candidate sites omitted from display.\n");
            return b.append("\n").toString();
        }
    }
    private static String hex(long x){
        return String.format(Locale.ROOT,"0x%08X",x);
    }

    public static PriorSimcr prefix(int min,int max,boolean unknownCall,
                                    boolean unknownStore,boolean incomplete) {
        if(min<0 || max<min || max>2)
            throw new IllegalArgumentException("Invalid saturated SIMCR history");
        if(incomplete || unknownCall || unknownStore)
            return PriorSimcr.UNKNOWN_DUE_TO_BARRIER_OR_LIMIT;
        if(min>0)return PriorSimcr.MATCH_ON_EVERY_MODELED_CFG_PATH;
        if(max>0)return PriorSimcr.POSSIBLE_MATCH_ON_SOME_CFG_PATHS;
        return PriorSimcr.NO_MATCH_IN_MODELED_FUNCTION_PREFIX;
    }

    public static Report inspect(boolean selectedMc68332,List<Site> observations){
        if(observations==null)
            throw new IllegalArgumentException("Null CFG observations");
        List<Finding> findings=new ArrayList<>();
        int words=0,unknown=0,indirect=0,aliases=0;
        boolean incomplete=false;
        for(Site s:observations){
            if(s==null || s.function()<0 || s.pc()<0 ||
                    s.register()==null || s.register().isBlank() ||
                    (s.address()<0 && !s.register().equals("UNRESOLVED_ALIAS")) ||
                    (s.address()>=0 && s.register().equals("UNRESOLVED_ALIAS")))
                throw new IllegalArgumentException("Untrusted CFG store site");
            if(s.widthBits()!=8 && s.widthBits()!=16 && s.widthBits()!=32)
                throw new IllegalArgumentException("Unsupported write width");
            if(s.literal()!=null && (s.literal()<0 || s.literal()>65535))
                throw new IllegalArgumentException("Invalid literal word");
            // Ghidra snapshot literal is populated only by a full word STORE.
            // Do not promote a byte/long coincidental scalar to a word value.
            Integer word=s.widthBits()==16?s.literal():null;
            if(word==null)unknown++;else words++;
            if(s.indirect())indirect++;
            if(s.address()<0)aliases++;
            incomplete|=s.functionIncomplete();
            PriorSimcr prior=prefix(s.priorSimcrMin(),s.priorSimcrMax(),
                s.unknownCall(),s.unknownStore(),s.functionIncomplete());
            Integer mm=selectedMc68332 &&
                s.register().equals("SIMCR") && word!=null ?
                ((word&0x40)!=0?1:0):null;
            findings.add(new Finding(s.function(),s.pc(),
                selectedMc68332?s.register():"UNVERIFIED_MCU_REGISTER",
                s.address(),s.indirect(),s.widthBits(),word,prior,
                s.unknownStore() || s.address()<0,mm));
        }
        findings.sort(Comparator.comparingLong(Finding::function)
            .thenComparingLong(Finding::pc)
            .thenComparing(Finding::register)
            .thenComparingLong(Finding::address));
        return new Report(findings,words,unknown,indirect,aliases,incomplete);
    }
}
