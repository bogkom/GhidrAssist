package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * GA-01/02/03/11: read-only co-location of source-proven indirect JSR
 * MAY-SIMCR effects with MOVEC-to-VBR sites in the SAME function.
 *
 * This is NOT an interprocedural edge, CFG path, operation order, active
 * MM/VBR, ISR execution, hardware proof or authorization to Apply.
 */
public final class HardwareResetIndirectVbrCorrelation {
    private HardwareResetIndirectVbrCorrelation() {}
    public static final int MAX_INDIRECT_SOURCES=64;
    public static final int MAX_VBR_SOURCES=32;
    public static final int MAX_DISPLAY=32;
    private static final long MCU_MAX=0xffffffL;

    public record Indirect(long caller,long pc,long target,
            boolean mayMm,boolean uncertain) {
        public Indirect {
            if(caller<0 || caller>MCU_MAX || pc<caller || pc>MCU_MAX ||
                    target<0 || target>MCU_MAX ||
                    (caller&1)!=0 || (pc&1)!=0 || (target&1)!=0)
                throw new IllegalArgumentException("Invalid indirect JSR source");
        }
    }
    public record Vbr(long function,long pc,Long tableBase,
            boolean uncertain) {
        public Vbr {
            if(function<0 || function>MCU_MAX || pc<function || pc>MCU_MAX ||
                    (function&1)!=0 || (pc&1)!=0 ||
                    tableBase!=null && (tableBase<0 || tableBase>MCU_MAX))
                throw new IllegalArgumentException("Invalid MOVEC source");
        }
    }
    public enum ResetRelation {
        IN_OBSERVED_RESET_CALL_SUBSET,
        OUTSIDE_OBSERVED_RESET_CALL_SUBSET,
        RESET_ROOT_UNKNOWN
    }
    public record Pair(long function,long indirectPc,long indirectTarget,
            long vbrPc,Long candidateVbrBase,
            ResetRelation resetRelation,boolean resetGraphIncomplete,
            boolean mayMm,boolean uncertain) {}
    public record Result(int indirectSources,int vbrSources,
            int colocatedPairs,int omittedIndirect,int omittedVbr,
            boolean displayTruncated,boolean resetRootRecognized,
            boolean resetGraphIncomplete,List<Pair> rows) {
        public Result { rows=List.copyOf(rows); }
        private static String hex(long n) {
            return String.format(Locale.ROOT,"0x%08X",n);
        }
        public String markdown() {
            StringBuilder b=new StringBuilder(
                "## RESET / indirect MMIO / VBR source co-location (GA-01/02/03/11)\n\n")
                .append("- **STATIC SAME-FUNCTION SOURCE CO-LOCATION ONLY**. ")
                .append("A byte-witnessed indirect JSR MAY reach a SIMCR/MM ")
                .append("STORE in its target subtree; a separate MOVEC ")
                .append("instruction MAY source a VBR table. Matching ")
                .append("function identity does NOT establish a path between ")
                .append("the instructions, their execution order, a direct ")
                .append("CALL edge, active SIMCR/MM, selected VBR, an ISR or ")
                .append("Review/Apply permission. RESET graph membership is ")
                .append("only bounded static direct-CALL reachability.\n")
                .append("- Indirect JSR sources: ").append(indirectSources)
                .append("; MOVEC-to-VBR sources: ").append(vbrSources)
                .append("; co-located pairs: ").append(colocatedPairs)
                .append("; displayed: ").append(rows.size())
                .append("; omitted indirect witnesses: ").append(omittedIndirect)
                .append("; omitted MOVEC sites: ").append(omittedVbr)
                .append("; RESET root recognized: ").append(resetRootRecognized)
                .append("; RESET graph incomplete: ").append(resetGraphIncomplete)
                .append(".\n");
            if(omittedIndirect>0 || omittedVbr>0 || displayTruncated)
                b.append("- **INCOMPLETE SOURCE INVENTORY/DISPLAY**: omitted ")
                    .append("matches and effects remain UNKNOWN.\n");
            if(rows.isEmpty())
                b.append("- No co-located pair in the bounded sources; ")
                    .append("NOT proof of absent indirect MMIO or VBR.\n");
            else {
                b.append("\n| Function | Indirect JSR PC | MAY target | MOVEC PC | ")
                    .append("Candidate VBR base | RESET relation | MM MAY | ")
                    .append("Unknown source/CFG | RESET incomplete |\n")
                    .append("|---|---|---|---|---|---|---|---|---|\n");
                for(Pair p:rows)
                    b.append("| ").append(hex(p.function()))
                     .append(" | ").append(hex(p.indirectPc()))
                     .append(" | ").append(hex(p.indirectTarget()))
                     .append(" | ").append(hex(p.vbrPc()))
                     .append(" | ").append(p.candidateVbrBase()==null?
                         "UNKNOWN":hex(p.candidateVbrBase()))
                     .append(" | ").append(p.resetRelation())
                     .append(" | ").append(p.mayMm()?"STATIC_MAY_MM":"UNKNOWN")
                     .append(" | ").append(p.uncertain())
                     .append(" | ").append(p.resetGraphIncomplete())
                     .append(" |\n");
            }
            return b.append("\n").toString();
        }
    }

    public static Result inspect(List<Indirect> indirect,List<Vbr> vbr,
            Set<Long> resetVisited,boolean resetRootRecognized,
            boolean resetGraphIncomplete,int omittedIndirect,int omittedVbr,
            int maxRows) {
        if(indirect==null || vbr==null || resetVisited==null ||
                indirect.size()>MAX_INDIRECT_SOURCES ||
                vbr.size()>MAX_VBR_SOURCES || omittedIndirect<0 ||
                omittedVbr<0 || maxRows<1 || maxRows>MAX_DISPLAY)
            throw new IllegalArgumentException("Invalid bounded source join");
        for(Long entry:resetVisited)
            if(entry==null || entry<0 || entry>MCU_MAX || (entry&1)!=0)
                throw new IllegalArgumentException("Invalid RESET source entry");
        List<Indirect> jsrs=new ArrayList<>(indirect);
        List<Vbr> movecs=new ArrayList<>(vbr);
        if(jsrs.contains(null) || movecs.contains(null))
            throw new IllegalArgumentException("Missing source witness");
        jsrs.sort(Comparator.comparingLong(Indirect::caller)
            .thenComparingLong(Indirect::pc).thenComparingLong(Indirect::target));
        movecs.sort(Comparator.comparingLong(Vbr::function)
            .thenComparingLong(Vbr::pc));
        Set<Long> indirectPcs=new HashSet<>(),vbrPcs=new HashSet<>();
        for(Indirect jsr:jsrs)
            if(!indirectPcs.add(jsr.pc()))
                throw new IllegalArgumentException("Duplicate indirect PC");
        for(Vbr movec:movecs)
            if(!vbrPcs.add(movec.pc()))
                throw new IllegalArgumentException("Duplicate MOVEC PC");
        List<Pair> rows=new ArrayList<>();
        int count=0;
        for(Indirect jsr:jsrs)
            for(Vbr movec:movecs) {
                if(jsr.caller()!=movec.function())continue;
                count++;
                if(rows.size()>=maxRows)continue;
                ResetRelation relation=!resetRootRecognized?
                    ResetRelation.RESET_ROOT_UNKNOWN:
                    resetVisited.contains(jsr.caller())?
                        ResetRelation.IN_OBSERVED_RESET_CALL_SUBSET:
                        ResetRelation.OUTSIDE_OBSERVED_RESET_CALL_SUBSET;
                rows.add(new Pair(jsr.caller(),jsr.pc(),jsr.target(),
                    movec.pc(),movec.tableBase(),relation,
                    resetGraphIncomplete || !resetRootRecognized,
                    jsr.mayMm(),jsr.uncertain()||movec.uncertain()||
                        movec.tableBase()==null));
            }
        return new Result(jsrs.size(),movecs.size(),count,
            omittedIndirect,omittedVbr,count>rows.size(),
            resetRootRecognized,resetGraphIncomplete,rows);
    }
}
