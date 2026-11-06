package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Bounded read-only static call-graph effect inventory. It classifies
 * POSSIBLE transitive effects, not runtime execution or reset path ordering.
 * Missing targets, recursion and depth/size limits are explicitly uncertain.
 */
public final class HardwareCallEffects {
    private HardwareCallEffects() {}
    public static final int MAX_SOURCE_FUNCTIONS=50_000;
    public static final int MAX_SOURCE_EDGES=200_000;
    public static final int MAX_REQUESTED_FUNCTIONS=50_000;

    public record FunctionNode(long entry,boolean memoryStore,boolean vbrWrite,
            boolean unresolvedFlow,List<Long> directCallees) {
        public FunctionNode {
            if(entry<0 || directCallees==null ||
                    directCallees.stream().anyMatch(callee ->
                        callee==null || callee<0))
                throw new IllegalArgumentException("Invalid call graph node");
            directCallees=List.copyOf(directCallees);
        }
    }
    public record Summary(boolean possibleMemoryStore,boolean possibleVbrWrite,
            boolean unresolved,boolean recursive,boolean truncated,int visited) {
        public String description(){
            return "transitive_memory_STORE_candidate="+possibleMemoryStore+
                "; transitive_VBR_write_candidate="+possibleVbrWrite+
                "; unresolved_flow_or_target="+unresolved+
                "; recursive_call="+recursive+
                "; bounded="+truncated+"; visited_functions="+visited+
                "; NOT an execution/reset-path proof";
        }
    }
    private static final class Acc {
        boolean memory,vbr,unknown,cycle,cap;
        int visits;
    }
    private record Layer(long entry,int depth) {}

    /**
     * Explore by SHORTEST observed direct-call distance. A depth-first
     * completed-set cache can hide a side effect: the same function may first
     * be visited on a long path at the depth cap and then skipped from a
     * shorter path that would have exposed its callees. Breadth-first search
     * avoids that source-evidence loss. It remains bounded and static only.
     */
    public static Summary summarize(long root,Collection<FunctionNode> nodes,
            int maxDepth,int maxFunctions) {
        if(root<0 || nodes==null || nodes.size()>MAX_SOURCE_FUNCTIONS ||
                maxDepth<0 || maxDepth>MAX_SOURCE_FUNCTIONS ||
                maxFunctions<1 || maxFunctions>MAX_REQUESTED_FUNCTIONS)
            throw new IllegalArgumentException("Bad bounded call graph limits");
        Map<Long,FunctionNode> graph=new HashMap<>();
        long sourceEdges=0;
        for(FunctionNode n:nodes) {
            if(n==null || graph.putIfAbsent(n.entry(),n)!=null)
                throw new IllegalArgumentException("Duplicate/bad function entry");
            sourceEdges+=n.directCallees().size();
            if(sourceEdges>MAX_SOURCE_EDGES)
                throw new IllegalArgumentException("Unbounded source-call edges");
        }
        Acc out=new Acc();
        java.util.ArrayDeque<Layer> queue=new java.util.ArrayDeque<>();
        Set<Long> discovered=new HashSet<>();
        Set<Long> inspected=new HashSet<>();
        queue.addLast(new Layer(root,0));
        discovered.add(root);
        while(!queue.isEmpty()) {
            if(out.visits>=maxFunctions) {
                out.cap=true;out.unknown=true;
                break;
            }
            Layer current=queue.removeFirst();
            FunctionNode node=graph.get(current.entry());
            if(node==null) {
                out.unknown=true;
                continue;
            }
            inspected.add(current.entry());
            out.visits++;
            out.memory|=node.memoryStore();
            out.vbr|=node.vbrWrite();
            out.unknown|=node.unresolvedFlow();
            for(long callee:node.directCallees()) {
                if(!graph.containsKey(callee)) {
                    out.unknown=true;
                    continue;
                }
                if(current.depth()>=maxDepth) {
                    if(!discovered.contains(callee)) {
                        out.cap=true;out.unknown=true;
                    }
                    continue;
                }
                if(!discovered.contains(callee)) {
                    // Bound the QUEUED frontier, not just completed visits.
                    // Omitted callees could contain MMIO/VBR source sites:
                    // truncation must retain explicit uncertainty.
                    if(discovered.size()>=maxFunctions) {
                        out.cap=true;out.unknown=true;
                    } else {
                        discovered.add(callee);
                        queue.addLast(new Layer(callee,current.depth()+1));
                    }
                }
            }
        }
        if(!queue.isEmpty()) {
            out.cap=true;out.unknown=true;
        }

        // A deterministic bounded graph can contain loops even when the BFS
        // shortest-path tree does not. Kahn's cycle check avoids recursion
        // and does not mistake an ordinary diamond join for a cycle.
        Map<Long,Integer> inDegree=new HashMap<>();
        for(long id:inspected)inDegree.put(id,0);
        for(long id:inspected) {
            for(long child:graph.get(id).directCallees()) {
                if(inspected.contains(child))
                    inDegree.put(child,inDegree.get(child)+1);
            }
        }
        java.util.ArrayDeque<Long> roots=new java.util.ArrayDeque<>();
        for(var e:inDegree.entrySet())if(e.getValue()==0)roots.addLast(e.getKey());
        int removed=0;
        while(!roots.isEmpty()) {
            long id=roots.removeFirst();
            removed++;
            for(long child:graph.get(id).directCallees()) {
                if(!inDegree.containsKey(child))continue;
                int next=inDegree.get(child)-1;
                inDegree.put(child,next);
                if(next==0)roots.addLast(child);
            }
        }
        if(removed<inspected.size()) {
            out.cycle=true;out.unknown=true;
        }
        return new Summary(out.memory,out.vbr,out.unknown,
            out.cycle,out.cap,out.visits);
    }
}
