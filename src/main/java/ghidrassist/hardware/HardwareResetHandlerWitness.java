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

    public enum Status { OBSERVED_STATIC_PATH, NOT_OBSERVED_WITHIN_BOUND,
        UNKNOWN_RESET_ROOT, UNKNOWN_FRONTIER, UNKNOWN_HANDLER_NOT_IN_GRAPH, INTERIOR_NOT_ENTRY }
    public record Row(int vector, long handler, Status status, List<Long> chain) {
        public Row {
            if(vector<2 || vector>255 || handler<0 || handler>0xffffffffL ||
                    status==null || chain==null || chain.size()>MAX_DEPTH+1 ||
                    chain.stream().anyMatch(x->x==null || x<0 || x>0xffffffffL) ||
                    (status==Status.OBSERVED_STATIC_PATH)!=(!chain.isEmpty()) ||
                    !chain.isEmpty() && chain.get(chain.size()-1)!=handler)
                throw new IllegalArgumentException("Invalid RESET witness");
            chain=List.copyOf(chain);
        }
    }
    public record Report(long resetEntry, boolean incomplete, boolean missingRoot,
            int inspected, List<Row> rows, List<List<Long>> frontiers,
            List<List<Long>> unresolvedCallSources) {
        public Report {
            if(resetEntry<0 || resetEntry>0xffffffffL || inspected<0 ||
                    inspected>MAX_NODES || rows==null || frontiers==null || unresolvedCallSources==null)
                throw new IllegalArgumentException("Invalid RESET report");
            rows=List.copyOf(rows);
            frontiers=frontiers.stream().map(List::copyOf).toList();
            unresolvedCallSources=unresolvedCallSources.stream().map(List::copyOf).toList();
            if(frontiers.stream().anyMatch(p->p.isEmpty()) ||
                    unresolvedCallSources.stream().anyMatch(p->p.isEmpty()))
                throw new IllegalArgumentException("Empty source chain");
        }
        public Report(long resetEntry, boolean incomplete, boolean missingRoot,
                int inspected, List<Row> rows, List<List<Long>> frontiers) {
            this(resetEntry,incomplete,missingRoot,inspected,rows,frontiers,List.of());
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
        for(var node:graph)
            if(node==null || nodes.putIfAbsent(node.entry(),node)!=null)
                throw new IllegalArgumentException("Duplicate or null CALL node");
        Set<Integer> slots=new HashSet<>();
        for(var t:targets)
            if(t==null || !slots.add(t.vectorNumber()))
                throw new IllegalArgumentException("Duplicate vector slot");
        Map<Long,Long> parents=new HashMap<>();
        Set<Long> seen=new HashSet<>();
        ArrayDeque<Step> q=new ArrayDeque<>();
        List<List<Long>> frontiers=new ArrayList<>();
        List<List<Long>> unresolvedCallSources=new ArrayList<>();
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
            if(node.unresolvedFlow()) {
                incomplete=true;
                unresolvedCallSources.add(path(parents,s.id()));
            }
            for(long next:node.directCallees().stream().sorted().toList()) {
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
        return new Report(resetEntry,incomplete,missingRoot,inspected,rows,frontiers,unresolvedCallSources);
    }
}
