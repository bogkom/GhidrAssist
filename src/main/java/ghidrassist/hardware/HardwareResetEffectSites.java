package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Read-only join of independently observed instruction PCs with bounded
 * RESET direct-CALL function-entry paths. A join is NOT execution evidence.
 */
public final class HardwareResetEffectSites {
    private HardwareResetEffectSites() {}
    public static final int MAX_SITES=5000;
    public enum Kind { MEMORY_STORE, MOVEC_VBR }
    public enum Status { STATIC_CALL_CHAIN, UNKNOWN_FRONTIER,
        NOT_OBSERVED_WITHIN_BOUND, UNKNOWN_FUNCTION_INVENTORY }
    public record Site(long functionEntry,long instructionPc,Kind kind) {
        public Site {
            if(!address(functionEntry) || !address(instructionPc) ||
                    (functionEntry&1)!=0 || (instructionPc&1)!=0 ||
                    instructionPc<functionEntry || kind==null)
                throw new IllegalArgumentException("Invalid effect source site");
        }
    }
    public record Row(Site site,Status status,List<Long> chain) {
        public Row {
            if(site==null || status==null || chain==null ||
                    chain.size()>HardwareResetHandlerWitness.MAX_DEPTH+1 ||
                    (status==Status.STATIC_CALL_CHAIN)!=(!chain.isEmpty()) ||
                    !chain.isEmpty() &&
                        chain.get(chain.size()-1)!=site.functionEntry())
                throw new IllegalArgumentException("Contradictory effect site row");
            chain=List.copyOf(chain);
        }
    }
    public record Report(long resetEntry,boolean incomplete,List<Row> rows,
            int omittedSites) {
        public Report {
            if(!address(resetEntry) || rows==null || omittedSites<0 ||
                    rows.size()>MAX_SITES)throw new IllegalArgumentException("Invalid site report");
            rows=List.copyOf(rows);
        }
        public String markdown() {
            StringBuilder b=new StringBuilder("## RESET static instruction-site provenance\n\n");
            b.append("RESET ").append(hex(resetEntry))
                .append("; incomplete ").append(incomplete)
                .append("; omitted sites ").append(omittedSites)
                .append(". STATIC ONLY: no executed STORE, active VBR/ISR or physical mapping.\n\n");
            for(Row row:rows) {
                b.append("- ").append(row.site().kind()).append(" at ")
                    .append(hex(row.site().instructionPc())).append(" in ")
                    .append(hex(row.site().functionEntry())).append(": ")
                    .append(row.status());
                if(!row.chain().isEmpty())
                    b.append(" via ").append(row.chain().stream()
                        .map(HardwareResetEffectSites::hex)
                        .reduce((a,c)->a+" -> "+c).orElse(""));
                b.append("\n");
            }
            return b.toString();
        }
    }
    private static boolean address(long x){return x>=0 && x<=0xffffffffL;}
    private static String hex(long x){return String.format(java.util.Locale.ROOT,"0x%08X",x);}
    public static Report correlate(HardwareResetHandlerWitness.Report witness,
            List<HardwareCallEffects.FunctionNode> inventory,List<Site> sites) {
        if(witness==null || inventory==null || sites==null ||
                inventory.size()>HardwareCallEffects.MAX_SOURCE_FUNCTIONS ||
                sites.size()>MAX_SITES)
            throw new IllegalArgumentException("Unbounded source inventory");
        Map<Long,HardwareCallEffects.FunctionNode> functions=new HashMap<>();
        for(var node:inventory)
            if(node==null || functions.putIfAbsent(node.entry(),node)!=null)
                throw new IllegalArgumentException("Invalid function inventory");
        Map<Long,List<Long>> stores=new HashMap<>(),vbr=new HashMap<>();
        for(var chain:witness.memoryStoreSources())
            put(stores,chain,witness.resetEntry());
        for(var chain:witness.vbrWriteSources())
            put(vbr,chain,witness.resetEntry());
        Set<Site> unique=new HashSet<>();
        List<Row> rows=new ArrayList<>();
        for(Site site:sites.stream().sorted(Comparator
                .comparingLong(Site::functionEntry)
                .thenComparingLong(Site::instructionPc)
                .thenComparing(Site::kind)).toList()) {
            if(site==null || !unique.add(site))
                throw new IllegalArgumentException("Duplicate or null effect site");
            var function=functions.get(site.functionEntry());
            Map<Long,List<Long>> chains=site.kind()==Kind.MEMORY_STORE?stores:vbr;
            // Site evidence and node classification must agree: a source
            // coordinate alone cannot manufacture a reachable effect.
            if(function!=null && !(site.kind()==Kind.MEMORY_STORE?
                    function.memoryStore():function.vbrWrite()))
                throw new IllegalArgumentException("Effect site disagrees with node evidence");
            List<Long> chain=chains.get(site.functionEntry());
            Status status;
            if(chain!=null && function!=null)status=Status.STATIC_CALL_CHAIN;
            else if(!functions.containsKey(site.functionEntry()))
                status=Status.UNKNOWN_FUNCTION_INVENTORY;
            else if(witness.incomplete())status=Status.UNKNOWN_FRONTIER;
            else status=Status.NOT_OBSERVED_WITHIN_BOUND;
            rows.add(new Row(site,status,chain!=null && function!=null?chain:List.of()));
        }
        return new Report(witness.resetEntry(),witness.incomplete(),rows,0);
    }
    private static void put(Map<Long,List<Long>> paths,List<Long> chain,long root) {
        if(chain==null || chain.isEmpty() || chain.get(0)!=root ||
                chain.size()>HardwareResetHandlerWitness.MAX_DEPTH+1 ||
                paths.putIfAbsent(chain.get(chain.size()-1),List.copyOf(chain))!=null)
            throw new IllegalArgumentException("Invalid source path provenance");
    }
}
