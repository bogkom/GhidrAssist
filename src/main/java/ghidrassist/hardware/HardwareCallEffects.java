package ghidrassist.hardware;

import java.util.ArrayDeque;
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
            // CALL targets are identities, not execution or source-PC
            // order. Canonical adjacency keeps both finite BFS search
            // membership and RESET witness chains invariant under the
            // order of Ghidra's references. Repeated edges remain present.
            List<Long> canonical=new ArrayList<>(directCallees);
            canonical.sort(Long::compare);
            directCallees=List.copyOf(canonical);
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
    /**
     * A typed source-only route through *recognized direct* function calls.
     * MISSING_TARGET is an observed absent function definition; depth/node
     * limits denote NOT-INSPECTED routes. No route proves execution.
     */
    public enum WitnessKind {
        MEMORY_STORE, MOVEC_VBR, UNKNOWN_FLOW, MISSING_TARGET,
        DEPTH_CUTOFF, NODE_CUTOFF
    }
    public record SourceWitness(WitnessKind kind,List<Long> chain) {
        public SourceWitness {
            if(kind==null || chain==null || chain.isEmpty() ||
                    chain.size()>MAX_SOURCE_FUNCTIONS+1)
                throw new IllegalArgumentException("Invalid static source witness");
            for(Long entry:chain)
                if(entry==null || entry<0)
                    throw new IllegalArgumentException("Invalid witness address");
            chain=List.copyOf(chain);
        }
    }
    /** Flags remain the original conservative bounded-graph Summary. */
    public record Detailed(long root,Summary summary,SourceWitness storeWitness,
            SourceWitness vbrWitness,SourceWitness observedUnknownWitness,
            SourceWitness frontierWitness) {
        public Detailed {
            if(root<0 || summary==null ||
                    !valid(root,storeWitness,WitnessKind.MEMORY_STORE) ||
                    !valid(root,vbrWitness,WitnessKind.MOVEC_VBR) ||
                    !valid(root,observedUnknownWitness,WitnessKind.UNKNOWN_FLOW,
                        WitnessKind.MISSING_TARGET) ||
                    !valid(root,frontierWitness,WitnessKind.DEPTH_CUTOFF,
                        WitnessKind.NODE_CUTOFF) ||
                    storeWitness!=null && !summary.possibleMemoryStore() ||
                    vbrWitness!=null && !summary.possibleVbrWrite() ||
                    observedUnknownWitness!=null && !summary.unresolved() ||
                    frontierWitness!=null &&
                        (!summary.truncated() || !summary.unresolved()))
                throw new IllegalArgumentException(
                    "Contradictory transitive CALL source witnesses");
        }
        private static boolean valid(long root,SourceWitness witness,
                WitnessKind... allowed) {
            if(witness==null)return true;
            if(witness.chain().get(0)!=root)return false;
            for(WitnessKind kind:allowed)if(witness.kind()==kind)return true;
            return false;
        }
    }
    private static final class Acc {
        boolean memory,vbr,unknown,cycle,cap;
        int visits;
    }
    private record Layer(long entry,int depth) {}
    private static List<Long> path(Map<Long,Long> parents,long entry) {
        ArrayDeque<Long> reversed=new ArrayDeque<>();
        Long at=entry;
        while(at!=null) {
            if(reversed.size()>MAX_SOURCE_FUNCTIONS)
                throw new IllegalStateException("Unbounded CALL witness chain");
            reversed.addFirst(at);
            at=parents.get(at);
        }
        return List.copyOf(reversed);
    }
    private static SourceWitness at(WitnessKind kind,Map<Long,Long> parents,
            long entry) {
        return new SourceWitness(kind,path(parents,entry));
    }
    private static SourceWitness edge(WitnessKind kind,Map<Long,Long> parents,
            long from,long to) {
        List<Long> chain=new ArrayList<>(path(parents,from));
        chain.add(to);
        return new SourceWitness(kind,chain);
    }
    /**
     * Do not reconstruct a longer chain when an earlier BFS witness
     * is already strictly shorter. Without this guard, a 50k-function
     * survey containing STORE in every node would rebuild quadratic
     * aggregate path prefixes although its first source is known.
     */
    private static boolean couldImprove(SourceWitness current,int chainLength) {
        return current==null || chainLength<=current.chain().size();
    }
    private static SourceWitness best(SourceWitness current,
            SourceWitness candidate) {
        if(current==null)return candidate;
        int size=Integer.compare(current.chain().size(),candidate.chain().size());
        if(size<0)return current;
        if(size>0)return candidate;
        for(int i=0;i<current.chain().size();i++){
            int compare=Long.compare(current.chain().get(i),
                candidate.chain().get(i));
            if(compare<0)return current;
            if(compare>0)return candidate;
        }
        return current.kind().ordinal()<=candidate.kind().ordinal()?
            current:candidate;
    }

    /**
     * Explore by SHORTEST observed direct-call distance. A depth-first
     * completed-set cache can hide a side effect: the same function may first
     * be visited on a long path at the depth cap and then skipped from a
     * shorter path that would have exposed its callees. Breadth-first search
     * avoids that source-evidence loss. It remains bounded and static only.
     */
    public static Summary summarize(long root,Collection<FunctionNode> nodes,
            int maxDepth,int maxFunctions) {
        return inspect(root,nodes,maxDepth,maxFunctions).summary();
    }
    /** Same finite BFS and cycle scan as summarize(), with typed source paths. */
    public static Detailed inspect(long root,Collection<FunctionNode> nodes,
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
        ArrayDeque<Layer> queue=new ArrayDeque<>();
        Set<Long> discovered=new HashSet<>();
        Set<Long> inspected=new HashSet<>();
        Map<Long,Long> parents=new HashMap<>();
        SourceWitness store=null,vbr=null,observedUnknown=null,frontier=null;
        queue.addLast(new Layer(root,0));
        discovered.add(root);
        parents.put(root,null);
        while(!queue.isEmpty()) {
            if(out.visits>=maxFunctions) {
                out.cap=true;out.unknown=true;
                Layer skipped=queue.peekFirst();
                if(skipped!=null &&
                        couldImprove(frontier,skipped.depth()+1))
                    frontier=best(frontier,at(WitnessKind.NODE_CUTOFF,
                        parents,skipped.entry()));
                break;
            }
            Layer current=queue.removeFirst();
            FunctionNode node=graph.get(current.entry());
            if(node==null) {
                out.unknown=true;
                if(couldImprove(observedUnknown,current.depth()+1))
                    observedUnknown=best(observedUnknown,
                        at(WitnessKind.MISSING_TARGET,parents,current.entry()));
                continue;
            }
            inspected.add(current.entry());
            out.visits++;
            if(node.memoryStore() &&
                    couldImprove(store,current.depth()+1))
                store=best(store,at(WitnessKind.MEMORY_STORE,
                    parents,current.entry()));
            if(node.vbrWrite() &&
                    couldImprove(vbr,current.depth()+1))
                vbr=best(vbr,at(WitnessKind.MOVEC_VBR,
                    parents,current.entry()));
            if(node.unresolvedFlow() &&
                    couldImprove(observedUnknown,current.depth()+1))
                observedUnknown=best(observedUnknown,
                    at(WitnessKind.UNKNOWN_FLOW,parents,current.entry()));
            out.memory|=node.memoryStore();
            out.vbr|=node.vbrWrite();
            out.unknown|=node.unresolvedFlow();
            for(long callee:node.directCallees()) {
                if(!graph.containsKey(callee)) {
                    out.unknown=true;
                    if(couldImprove(observedUnknown,current.depth()+2))
                        observedUnknown=best(observedUnknown,
                            edge(WitnessKind.MISSING_TARGET,parents,
                                current.entry(),callee));
                    continue;
                }
                if(current.depth()>=maxDepth) {
                    if(!discovered.contains(callee)) {
                        out.cap=true;out.unknown=true;
                        if(couldImprove(frontier,current.depth()+2))
                            frontier=best(frontier,
                                edge(WitnessKind.DEPTH_CUTOFF,parents,
                                    current.entry(),callee));
                    }
                    continue;
                }
                if(!discovered.contains(callee)) {
                    // Budget is charged to distinct scheduled targets, NOT
                    // the incidental order or number of Ghidra references.
                    if(discovered.size()>=maxFunctions) {
                        out.cap=true;out.unknown=true;
                        if(couldImprove(frontier,current.depth()+2))
                            frontier=best(frontier,
                                edge(WitnessKind.NODE_CUTOFF,parents,
                                    current.entry(),callee));
                    } else {
                        discovered.add(callee);
                        parents.put(callee,current.entry());
                        queue.addLast(new Layer(callee,current.depth()+1));
                    }
                }
            }
        }
        if(!queue.isEmpty()) {
            out.cap=true;out.unknown=true;
            if(frontier==null)
                frontier=at(WitnessKind.NODE_CUTOFF,parents,queue.peekFirst().entry());
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
        Summary summary=new Summary(out.memory,out.vbr,out.unknown,
            out.cycle,out.cap,out.visits);
        return new Detailed(root,summary,store,vbr,observedUnknown,frontier);
    }
}
