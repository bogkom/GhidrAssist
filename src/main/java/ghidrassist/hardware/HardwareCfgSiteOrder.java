package ghidrassist.hardware;

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * GA-01/02/03/11: bounded, read-only intra-function CFG source ordering.
 * A possible instruction route is NOT execution, ordering across CALLs,
 * active SIMCR/MM, active VBR, or ISR evidence.
 */
public final class HardwareCfgSiteOrder {
    private HardwareCfgSiteOrder() {}
    public static final int MAX_NODES=1500;
    private static final long MAX_ADDRESS=0xffffffL;

    public record Node(long pc,List<Long> successors) {
        public Node {
            if(pc<0 || pc>MAX_ADDRESS || (pc&1L)!=0 ||
                    successors==null || successors.size()>MAX_NODES)
                throw new IllegalArgumentException("Invalid CFG node");
            successors=List.copyOf(successors);
            for(Long next:successors)
                if(next==null || next<0 || next>MAX_ADDRESS || (next&1L)!=0)
                    throw new IllegalArgumentException("Invalid CFG edge");
        }
    }
    public enum Relation {
        POSSIBLE_JSR_BEFORE_MOVEC,
        POSSIBLE_MOVEC_BEFORE_JSR,
        POSSIBLE_BOTH_ORDERS,
        NO_OBSERVED_ORDERED_ROUTE,
        UNKNOWN
    }

    /**
     * Only a caller-proven fully decoded, nontruncated function may pass
     * complete=true. Return UNKNOWN on missing/foreign nodes, off-graph
     * successors, unreachable source sites, or a path budget exceeded.
     * Ghidra CALL fallthrough is a static possible route, not a proven return.
     */
    public static Relation inspect(long entry,List<Node> graph,
            boolean complete,long jsrPc,long movecPc) {
        if(entry<0 || entry>MAX_ADDRESS || (entry&1L)!=0 ||
                jsrPc<0 || jsrPc>MAX_ADDRESS || (jsrPc&1L)!=0 ||
                movecPc<0 || movecPc>MAX_ADDRESS || (movecPc&1L)!=0)
            throw new IllegalArgumentException("Invalid source PC");
        if(!complete || graph==null || graph.isEmpty() ||
                graph.size()>MAX_NODES || jsrPc==movecPc)
            return Relation.UNKNOWN;
        Map<Long,List<Long>> edges=new HashMap<>();
        for(Node node:graph)
            if(node==null || edges.putIfAbsent(node.pc(),node.successors())!=null)
                return Relation.UNKNOWN;
        if(!edges.containsKey(entry) || !edges.containsKey(jsrPc) ||
                !edges.containsKey(movecPc))return Relation.UNKNOWN;
        for(List<Long> successors:edges.values())
            for(Long dest:successors)
                if(!edges.containsKey(dest))return Relation.UNKNOWN;
        Set<Long> entryReach=reachable(entry,edges);
        if(!entryReach.contains(jsrPc) || !entryReach.contains(movecPc))
            return Relation.UNKNOWN;
        boolean forward=reachable(jsrPc,edges).contains(movecPc);
        boolean backward=reachable(movecPc,edges).contains(jsrPc);
        if(forward && backward)return Relation.POSSIBLE_BOTH_ORDERS;
        if(forward)return Relation.POSSIBLE_JSR_BEFORE_MOVEC;
        if(backward)return Relation.POSSIBLE_MOVEC_BEFORE_JSR;
        return Relation.NO_OBSERVED_ORDERED_ROUTE;
    }
    private static Set<Long> reachable(long start,Map<Long,List<Long>> edges) {
        Set<Long> seen=new HashSet<>();
        ArrayDeque<Long> pending=new ArrayDeque<>();
        pending.add(start);
        while(!pending.isEmpty()){
            long pc=pending.removeFirst();
            if(!seen.add(pc))continue;
            for(Long next:edges.get(pc))
                if(!seen.contains(next))pending.addLast(next);
        }
        return seen;
    }
}
