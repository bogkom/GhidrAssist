package ghidrassist.hardware;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * GA-01/02/03/11: read-only RESET-to-vector-handler direct-CALL witnesses.
 * A path is a static candidate, never proof of execution or active ISR/VBR.
 */
public final class HardwareResetHandlerWitness {
    private HardwareResetHandlerWitness() {}
    public static final int MAX_DEPTH=8, MAX_NODES=100;
    /** Input limit is independent of BFS visit budget and frontier cap. */
    public static final int MAX_SOURCE_EDGES=HardwareCallEffects.MAX_SOURCE_EDGES;

    public enum Status { OBSERVED_STATIC_PATH, NOT_OBSERVED_WITHIN_BOUND,
        UNKNOWN_RESET_ROOT, UNKNOWN_FRONTIER, UNKNOWN_HANDLER_NOT_IN_GRAPH, INTERIOR_NOT_ENTRY }
    public record Row(int vector, long handler, Status status, List<Long> chain) {
        public Row {
            if(vector<2 || vector>255 || handler<0 || handler>0xffffffffL ||
                    (handler&1)!=0 || status==null || chain==null ||
                    chain.size()>MAX_DEPTH+1 ||
                    chain.stream().anyMatch(x->x==null || x<0 ||
                        x>0xffffffffL || (x&1)!=0) ||
                    (status==Status.OBSERVED_STATIC_PATH)!=(!chain.isEmpty()) ||
                    !chain.isEmpty() && chain.get(chain.size()-1)!=handler)
                throw new IllegalArgumentException("Invalid RESET witness");
            chain=List.copyOf(chain);
        }
    }
    public record Report(long resetEntry, boolean incomplete, boolean missingRoot,
            int inspected, List<Row> rows, List<List<Long>> frontiers,
            List<List<Long>> unresolvedCallSources,
            List<List<Long>> memoryStoreSources, List<List<Long>> vbrWriteSources) {
        public Report {
            if(resetEntry<0 || resetEntry>0xffffffffL ||
                    (resetEntry&1)!=0 || inspected<0 || inspected>MAX_NODES ||
                    rows==null || rows.size()>254 ||
                    rows.stream().anyMatch(java.util.Objects::isNull) ||
                    frontiers==null || unresolvedCallSources==null ||
                    memoryStoreSources==null || vbrWriteSources==null ||
                    missingRoot && (!incomplete || inspected!=0) ||
                    !missingRoot && inspected==0)
                throw new IllegalArgumentException("Invalid RESET report");
            Set<Integer> slots=new HashSet<>();
            for(Row row:rows)
                if(!slots.add(row.vector()) ||
                        !row.chain().isEmpty() &&
                            row.chain().get(0)!=resetEntry)
                    throw new IllegalArgumentException(
                        "Conflicting vector slot or RESET path origin");
            // Public records may be reconstructed by an API caller. No
            // arbitrary unbounded/foreign source chain may be printed or
            // passed to downstream STORE/VBR correlation.
            verifyPaths(frontiers,resetEntry,MAX_DEPTH+2,true);
            verifyPaths(unresolvedCallSources,resetEntry,MAX_DEPTH+1,false);
            verifyPaths(memoryStoreSources,resetEntry,MAX_DEPTH+1,false);
            verifyPaths(vbrWriteSources,resetEntry,MAX_DEPTH+1,false);
            if(missingRoot && (!frontiers.isEmpty() ||
                    !unresolvedCallSources.isEmpty() ||
                    !memoryStoreSources.isEmpty() || !vbrWriteSources.isEmpty() ||
                    rows.stream().anyMatch(row->
                        row.status()==Status.OBSERVED_STATIC_PATH)))
                throw new IllegalArgumentException(
                    "Missing RESET root cannot produce source paths");
            rows=List.copyOf(rows);
            frontiers=frontiers.stream().map(List::copyOf).toList();
            unresolvedCallSources=unresolvedCallSources.stream().map(List::copyOf).toList();
            memoryStoreSources=memoryStoreSources.stream().map(List::copyOf).toList();
            vbrWriteSources=vbrWriteSources.stream().map(List::copyOf).toList();
        }
        private static void verifyPaths(List<List<Long>> paths,long root,
                int maxLength,boolean frontier) {
            if(paths.size()>MAX_NODES)
                throw new IllegalArgumentException("Oversized RESET path inventory");
            for(List<Long> chain:paths) {
                if(chain==null || chain.isEmpty() ||
                        chain.size()>(frontier?MAX_DEPTH+2:maxLength) ||
                        chain.size()>maxLength ||
                        chain.get(0)==null || chain.get(0)!=root ||
                        frontier && chain.size()<2)
                    throw new IllegalArgumentException("Invalid RESET source chain");
                for(int i=0;i<chain.size();i++) {
                    Long pc=chain.get(i);
                    // An unrecognized frontier endpoint may have a malformed
                    // instruction address, but all inspected functions have
                    // aligned CPU32 entry identities.
                    if(pc==null || pc<0 || pc>0xffffffffL ||
                            (i!=chain.size()-1 || !frontier) && (pc&1)!=0)
                        throw new IllegalArgumentException(
                            "Malformed RESET source function identity");
                }
            }
        }
        public Report(long resetEntry, boolean incomplete, boolean missingRoot,
                int inspected, List<Row> rows, List<List<Long>> frontiers,
                List<List<Long>> unresolvedCallSources) {
            this(resetEntry,incomplete,missingRoot,inspected,rows,frontiers,
                unresolvedCallSources,List.of(),List.of());
        }
        public Report(long resetEntry, boolean incomplete, boolean missingRoot,
                int inspected, List<Row> rows, List<List<Long>> frontiers) {
            this(resetEntry,incomplete,missingRoot,inspected,rows,frontiers,List.of(),List.of(),List.of());
        }
        public String markdown() {
            StringBuilder b=new StringBuilder("## RESET to ISR-handler static CALL witnesses\n\n");
            b.append("RESET source ").append(hex(resetEntry))
                .append("; inspected ").append(inspected)
                .append("; incomplete ").append(incomplete)
                .append("; missing root ").append(missingRoot)
                .append("; unresolved CALL source nodes ").append(unresolvedCallSources.size())
                .append("; uninspected frontiers ").append(frontiers.size())
                .append(". STATIC ONLY: no executed path, active VBR, IRQ or physical mapping is established.\n\n");
            b.append("| Vector | Handler | Status | Direct CALL function-entry chain |\n")
                .append("|---|---|---|---|\n");
            for(Row r:rows) {
                b.append("| ").append(r.vector()).append(" | ").append(hex(r.handler()))
                    .append(" | ").append(r.status()).append(" | ")
                    .append(render(r.chain())).append(" |\n");
            }
            for(List<Long> f:frontiers)
                b.append("- NOT INSPECTED frontier: ").append(render(f)).append("\n");
            for(List<Long> source:unresolvedCallSources)
                b.append("- UNRESOLVED CALL source: ").append(render(source)).append("\n");
            for(List<Long> source:memoryStoreSources)
                b.append("- POSSIBLE STORE source: ").append(render(source)).append("\n");
            for(List<Long> source:vbrWriteSources)
                b.append("- POSSIBLE MOVEC/VBR source: ").append(render(source)).append("\n");
            return b.toString();
        }
    }
    private record Step(long id,int depth) {}
    private static String hex(long a) {
        return String.format(java.util.Locale.ROOT,"0x%08X",a);
    }
    private static String render(List<Long> path) {
        if(path.isEmpty())return "NONE";
        return String.join(" -> ",path.stream().map(HardwareResetHandlerWitness::hex).toList());
    }
    private static List<Long> path(Map<Long,Long> parents,long at) {
        ArrayDeque<Long> out=new ArrayDeque<>();
        Long id=at;
        while(id!=null) {
            if(out.size()>MAX_NODES+1)throw new IllegalStateException("Cyclic parent map");
            out.addFirst(id);
            id=parents.get(id);
        }
        return List.copyOf(out);
    }
    public static Report inspect(long resetEntry,boolean resetGraphIncomplete,
            Collection<HardwareCallEffects.FunctionNode> graph,
            List<HardwareVectorResetCorrelation.Target> targets) {
        if(resetEntry<0 || resetEntry>0xffffffffL || (resetEntry&1)!=0 ||
                graph==null || targets==null ||
                graph.size()>HardwareCallEffects.MAX_SOURCE_FUNCTIONS ||
                targets.size()>HardwareVectorResetCorrelation.MAX_RECOGNIZED_VECTOR_TARGETS)
            throw new IllegalArgumentException("Invalid bounded RESET inputs");
        Map<Long,HardwareCallEffects.FunctionNode> nodes=new HashMap<>();
        long sourceEdges=0;
        for(var node:graph) {
            if(node==null || nodes.putIfAbsent(node.entry(),node)!=null)
                throw new IllegalArgumentException("Duplicate or null CALL node");
            sourceEdges+=node.directCallees().size();
            if(sourceEdges>MAX_SOURCE_EDGES)
                throw new IllegalArgumentException(
                    "Oversized RESET direct-CALL source inventory");
        }
        Set<Integer> slots=new HashSet<>();
        for(var t:targets)
            if(t==null || !slots.add(t.vectorNumber()))
                throw new IllegalArgumentException("Duplicate vector slot");
        Map<Long,Long> parents=new HashMap<>();
        Set<Long> seen=new HashSet<>();
        ArrayDeque<Step> q=new ArrayDeque<>();
        List<List<Long>> frontiers=new ArrayList<>();
        List<List<Long>> unresolvedCallSources=new ArrayList<>();
        List<List<Long>> memoryStoreSources=new ArrayList<>();
        List<List<Long>> vbrWriteSources=new ArrayList<>();
        boolean missingRoot=!nodes.containsKey(resetEntry);
        boolean incomplete=resetGraphIncomplete || missingRoot;
        if(!missingRoot) {
            seen.add(resetEntry);
            q.add(new Step(resetEntry,0));
        }
        int inspected=0;
        while(!q.isEmpty()) {
            Step s=q.removeFirst();
            var node=nodes.get(s.id());
            inspected++;
            if(node.memoryStore())memoryStoreSources.add(path(parents,s.id()));
            if(node.vbrWrite())vbrWriteSources.add(path(parents,s.id()));
            if(node.unresolvedFlow()) {
                incomplete=true;
                unresolvedCallSources.add(path(parents,s.id()));
            }
            // FunctionNode already canonicalizes adjacency; do not sort
            // and materialize this potentially 200k-edge list a second time.
            for(long next:node.directCallees()) {
                if(seen.contains(next))continue;
                if(s.depth()>=MAX_DEPTH || seen.size()>=MAX_NODES ||
                        !nodes.containsKey(next)) {
                    incomplete=true;
                    var f=new ArrayList<>(path(parents,s.id()));
                    f.add(next);
                    // One source witness per observed frontier edge, bounded.
                    if(frontiers.size()<MAX_NODES)frontiers.add(List.copyOf(f));
                    continue;
                }
                seen.add(next);
                parents.put(next,s.id());
                q.addLast(new Step(next,s.depth()+1));
            }
        }
        List<Row> rows=new ArrayList<>();
        for(var t:targets.stream().sorted(Comparator.comparingInt(
                HardwareVectorResetCorrelation.Target::vectorNumber)).toList()) {
            Status status;
            List<Long> chain=List.of();
            if(!t.exactEntry())status=Status.INTERIOR_NOT_ENTRY;
            else if(missingRoot)status=Status.UNKNOWN_RESET_ROOT;
            else if(seen.contains(t.functionEntry())) {
                status=Status.OBSERVED_STATIC_PATH;
                chain=path(parents,t.functionEntry());
            } else if(incomplete)status=Status.UNKNOWN_FRONTIER;
            else if(!nodes.containsKey(t.functionEntry()))
                status=Status.UNKNOWN_HANDLER_NOT_IN_GRAPH;
            else status=Status.NOT_OBSERVED_WITHIN_BOUND;
            rows.add(new Row(t.vectorNumber(),t.functionEntry(),status,chain));
        }
        return new Report(resetEntry,incomplete,missingRoot,inspected,rows,frontiers,
            unresolvedCallSources,memoryStoreSources,vbrWriteSources);
    }
}
