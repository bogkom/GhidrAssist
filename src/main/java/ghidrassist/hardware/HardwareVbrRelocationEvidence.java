package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * GA-11: bounded planning of read-only *source image* exception-table
 * candidates named by a MOVEC-to-VBR instruction. Static CFG reachability
 * and a possible register value are never evidence of active runtime VBR,
 * ISR execution or relocation having occurred.
 */
public final class HardwareVbrRelocationEvidence {
    private HardwareVbrRelocationEvidence() {}
    public static final int MAX_SOURCE_SITES=256;
    public static final int MAX_TABLES=3;
    public static final int MAX_REPORTED_SITES=32;
    public static final long MAX_24BIT=0xffffffL;
    private static final long TABLE_BYTES=1024L; // MC68332UM CPU32 VBR, 256 x 4

    public enum Relation {
        IN_OBSERVED_RESET_CALL_SUBSET,
        OUTSIDE_OBSERVED_RESET_CALL_SUBSET,
        RESET_ROOT_UNKNOWN
    }
    public enum TableState {
        TABLE_BYTES_CANDIDATE,
        UNKNOWN_SOURCE_REGISTER,
        UNALIGNED_SOURCE,
        CROSSES_24BIT_LIMIT
    }
    /** One decoded MOVEC-to-VBR site; value is a local joined CFG hypothesis. */
    public record Site(long functionEntry,long instruction,Long sourceValue,
                       boolean incompleteCfg,boolean priorUnknownCall) {
        public Site {
            if(functionEntry<0 || functionEntry>MAX_24BIT ||
                    instruction<0 || instruction>MAX_24BIT ||
                    sourceValue!=null && (sourceValue<0 ||
                            sourceValue>MAX_24BIT))
                throw new IllegalArgumentException("Invalid VBR source coordinates");
        }
    }
    public record Row(long functionEntry,long instruction,Long sourceValue,
                      Relation resetRelation,TableState tableState,
                      boolean incompleteCfg,boolean priorUnknownCall,
                      boolean resetGraphIncomplete) {}
    /** Plan only; table memory is read separately from the current Program. */
    public record Plan(int observedSourceSites,int unknownSourceValues,
                       int invalidSourceValues,int eligibleTableBases,
                       boolean tableScanTruncated,boolean siteDisplayTruncated,
                       List<Long> tableBases,List<Row> rows) {
        public Plan {
            tableBases=List.copyOf(tableBases);
            rows=List.copyOf(rows);
        }
        public String markdown(){
            StringBuilder out=new StringBuilder();
            out.append("## Relocated VBR source-table candidates (GA-11)\n\n")
               .append("- Provenance: decoded MOVEC-to-VBR sites and bounded ")
               .append("intraprocedural joined source registers; **runtime VBR UNKNOWN**. ")
               .append("RESET direct-call subset is source reachability, not execution.\n")
               .append("- MOVEC source sites sampled: ").append(observedSourceSites)
               .append("; unknown source registers: ").append(unknownSourceValues)
               .append("; unaligned / out-of-range sources: ")
               .append(invalidSourceValues)
               .append("; distinct eligible table bases: ")
               .append(eligibleTableBases).append("; inspected bases: ")
               .append(tableBases.size()).append(".\n")
               .append("- Table bytes: read-only current Ghidra memory image at ")
               .append("VBR candidate + (vector number × 4); 256 × 4 bytes. ")
               .append("No inference of a runtime relocation, physical memory map, ")
               .append("active IRQ, ISR invocation, or a prior SIMCR/MM write.\n");
            if(tableScanTruncated)
                out.append("- **INCOMPLETE:** more distinct table bases than ")
                   .append("the bounded scan budget; omitted bases are UNKNOWN.\n");
            if(siteDisplayTruncated)
                out.append("- Site display truncated; source count covers all ")
                   .append("bounded incoming sites.\n");
            if(rows.isEmpty())
                out.append("- No MOVEC-to-VBR source sites observed. ")
                   .append("This does NOT prove VBR was never written.\n");
            else {
                out.append("\n| Function | MOVEC PC | Candidate VBR source | ")
                   .append("RESET relation | Table bytes | CFG incomplete | ")
                   .append("Prior unknown CALL | RESET callgraph incomplete |\n")
                   .append("|---|---|---|---|---|---|---|---|\n");
                for(Row row:rows){
                    out.append("| ").append(hex(row.functionEntry()))
                       .append(" | ").append(hex(row.instruction())).append(" | ")
                       .append(row.sourceValue()==null?"UNKNOWN":hex(row.sourceValue()))
                       .append(" | ").append(row.resetRelation())
                       .append(" | ").append(row.tableState())
                       .append(" | ").append(row.incompleteCfg())
                       .append(" | ").append(row.priorUnknownCall())
                       .append(" | ").append(row.resetGraphIncomplete())
                       .append(" |\n");
                }
            }
            return out.append("\n- **STATIC SOURCE CANDIDATES ONLY:** neither ")
                .append("MOVEC instruction presence nor RESET graph reachability ")
                .append("proves the relocated exception table was selected or ")
                .append("that any ISR was entered.\n\n").toString();
        }
    }
    private static String hex(long value){
        return String.format(Locale.ROOT,"0x%08X",value);
    }
    private static TableState tableState(Long base) {
        if(base==null)return TableState.UNKNOWN_SOURCE_REGISTER;
        if((base&3)!=0)return TableState.UNALIGNED_SOURCE;
        if(base>MAX_24BIT-(TABLE_BYTES-1))
            return TableState.CROSSES_24BIT_LIMIT;
        return TableState.TABLE_BYTES_CANDIDATE;
    }
    /**
     * Deterministic source-plan over up to MAX_SOURCE_SITES recognized sites.
     * No implicit profile detection: callers must check explicit MC68332
     * selection before offering VBR candidates to this planner.
     */
    public static Plan plan(List<Site> sites,boolean resetRootRecognized,
            boolean resetGraphIncomplete,Set<Long> resetVisited,
            int maxTables,int maxRows) {
        if(sites==null || resetVisited==null ||
                sites.size()>MAX_SOURCE_SITES || maxTables<1 ||
                maxTables>MAX_TABLES || maxRows<1 ||
                maxRows>MAX_REPORTED_SITES)
            throw new IllegalArgumentException("Unbounded VBR source candidates");
        List<Site> ordered=new ArrayList<>(sites);
        if(ordered.contains(null))
            throw new IllegalArgumentException("Null MOVEC site");
        ordered.sort(Comparator.comparingLong(Site::instruction));
        Set<Long> seenPc=new HashSet<>();
        TreeSet<Long> bases=new TreeSet<>();
        List<Row> rows=new ArrayList<>();
        int unknown=0,invalid=0;
        for(Site site:ordered){
            if(site==null || !seenPc.add(site.instruction()))
                throw new IllegalArgumentException("Duplicate/null MOVEC site");
            TableState table=tableState(site.sourceValue());
            if(table==TableState.UNKNOWN_SOURCE_REGISTER)unknown++;
            else if(table!=TableState.TABLE_BYTES_CANDIDATE)invalid++;
            else bases.add(site.sourceValue());
            Relation rel=!resetRootRecognized?Relation.RESET_ROOT_UNKNOWN:
                resetVisited.contains(site.functionEntry())?
                    Relation.IN_OBSERVED_RESET_CALL_SUBSET:
                    Relation.OUTSIDE_OBSERVED_RESET_CALL_SUBSET;
            if(rows.size()<maxRows)rows.add(new Row(site.functionEntry(),
                site.instruction(),site.sourceValue(),rel,table,
                site.incompleteCfg(),site.priorUnknownCall(),
                resetGraphIncomplete));
        }
        List<Long> selected=new ArrayList<>();
        for(Long base:bases){
            if(selected.size()>=maxTables)break;
            selected.add(base);
        }
        return new Plan(sites.size(),unknown,invalid,bases.size(),
            bases.size()>selected.size(),rows.size()<sites.size(),
            selected,rows);
    }
}
