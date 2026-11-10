package ghidrassist.hardware;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Reset-vector-rooted, bounded *static candidate* call paths.
 * This is deliberately not an execution trace, path feasibility solver or
 * register-state transfer across functions. Only explicit direct calls are
 * represented by FunctionNode.directCallees().
 */
public final class HardwareResetFlow {
    private HardwareResetFlow() {}
    public static final int MAX_DEPTH=32;
    public static final int MAX_NODES=10_000;
    public static final int MAX_EVIDENCE=1_000;
    public static final int MAX_INPUT_NODES=50_000;
    public static final int MAX_INPUT_EDGES=200_000;

    public record Vector(long initialSp, long resetPc, boolean valid, String reason) {
        public Vector {
            if(reason==null)throw new IllegalArgumentException("reason");
        }
    }

    /**
     * A RESET vector into a function body is NOT the function's entry.
     * Treating the containing function's complete CALL graph as reachable
     * would include instructions BEFORE the real vector PC and could invent
     * initialization/ISR/MMIO source paths. Do not silently round backward
     * to Ghidra's function entry; retain an UNKNOWN RESET root instead.
     * This is a source-entry gate, not proof of CPU execution.
     */
    public static boolean exactFunctionEntry(long vectorPc,long functionEntry) {
        return vectorPc>=0 && vectorPc<=0xffffffffL &&
            functionEntry>=0 && functionEntry<=0xffffffffL &&
            (vectorPc&1)==0 && (functionEntry&1)==0 &&
            vectorPc==functionEntry;
    }

    /** CPU32/68000 vector words are unsigned big-endian values at image 0..7. */
    public static Vector readVector(byte[] eightBytes) {
        if(eightBytes==null || eightBytes.length!=8)
            return new Vector(0,0,false,"vector bytes unavailable or incomplete");
        long sp=word(eightBytes,0),pc=word(eightBytes,4);
        if(pc==0 || pc==0xffffffffL || (pc&1)!=0)
            return new Vector(sp,pc,false,"reset PC is null, erased or odd");
        return new Vector(sp,pc,true,"candidate vector; firmware origin not independently verified");
    }

    /**
     * GA-01/11: the vector's initial A7/SSP word and its PC are distinct
     * source observations. A suspicious stack pointer must be reported,
     * not silently substituted for proof that the reset PC executed.
     * The 24-bit rule is *only* selected for a concrete MC68332 profile:
     * generic 32-bit CPU32 projects may legitimately use wider addresses.
     *
     * An initial SP of 0x01000000 may be the top (one past the last
     * address) of a downward-growing 24-bit stack; it is NOT a mapped
     * stack witness or a reason to reject an otherwise eligible reset PC.
     */
    public enum InitialStackEvidence {
        NULL_OR_ERASED_SOURCE,
        ODD_WORD_ACCESS_RISK,
        ONE_PAST_MCU24_TOP_CANDIDATE,
        OUTSIDE_SELECTED_MCU24_CONTEXT,
        ALIGNED_BUT_MEMORY_UNVERIFIED
    }

    public static InitialStackEvidence inspectInitialStack(long initialSp,
            boolean selectedMc68332) {
        if(initialSp<0 || initialSp>0xffffffffL)
            throw new IllegalArgumentException("Invalid RESET initial stack word");
        if(initialSp==0 || initialSp==0xffffffffL)
            return InitialStackEvidence.NULL_OR_ERASED_SOURCE;
        if((initialSp&1L)!=0)
            return InitialStackEvidence.ODD_WORD_ACCESS_RISK;
        if(selectedMc68332 && initialSp==0x1000000L)
            return InitialStackEvidence.ONE_PAST_MCU24_TOP_CANDIDATE;
        if(selectedMc68332 && initialSp>0xffffffL)
            return InitialStackEvidence.OUTSIDE_SELECTED_MCU24_CONTEXT;
        return InitialStackEvidence.ALIGNED_BUT_MEMORY_UNVERIFIED;
    }

    /**
     * Fail closed before joining Ghidra functions when an explicitly
     * selected MC68332 reset PC is outside its 24-bit source-image address
     * range. The CPU32 has a 32-bit programmer model, so a value with high
     * address bits might alias on a physical bus; WITHOUT independent
     * remapping evidence, do not invent that alias or a RESET CALL graph.
     * Generic CPU32 analysis retains its original 32-bit interpretation.
     */
    public static boolean sourceResetPcEligible(Vector vector,
            boolean selectedMc68332) {
        return vector!=null && vector.valid() &&
            (!selectedMc68332 || vector.resetPc()<=0xffffffL);
    }

    private static long word(byte[] bytes,int start){
        long result=0;
        for(int n=start;n<start+4;n++)result=(result<<8)|(bytes[n]&0xffL);
        return result;
    }

    public record Evidence(long functionEntry, String chain, int depth,
                           boolean possibleMemoryStore, boolean possibleVbrWrite) {}

    public record Summary(boolean rootRecognized, int visitedFunctions,
                          boolean unresolved, boolean recursive,
                          boolean truncated, List<Evidence> evidence, Set<Long> visitedEntries) {
        public Summary {
            evidence=List.copyOf(evidence);
            visitedEntries=Set.copyOf(visitedEntries);
        }
        public String markdown(long vectorPc,long rootEntry) {
            StringBuilder out=new StringBuilder();
            out.append("- RESET PC candidate: ").append(hex(vectorPc))
               .append("; containing function entry: ").append(hex(rootEntry)).append("\n")
               .append("- Function recognized: ").append(rootRecognized)
               .append("; reachable static-call candidate nodes: ")
               .append(visitedFunctions)
               .append("; unresolved call/control-flow: ").append(unresolved)
               .append("; recursion: ").append(recursive)
               .append("; search bounded/truncated: ").append(truncated).append("\n");
            for(Evidence e:evidence)
                out.append("  - candidate chain ").append(e.chain())
                   .append("; matched hardware register evidence at ")
                   .append(hex(e.functionEntry())).append("; local STORE candidate=")
                   .append(e.possibleMemoryStore())
                   .append("; local VBR write candidate=")
                   .append(e.possibleVbrWrite()).append("\n");
            if(evidence.isEmpty())
                out.append("- No matching hardware sites found in the bounded recognized ")
                   .append("direct-call subset; **not** proof of no initialization.\n");
            out.append("- **STATIC CANDIDATES ONLY**: direct calls can be conditional or ")
               .append("unreachable; indirect calls, tail branches, exception paths, ")
               .append("state crossing call boundaries and actual reset execution ")
               .append("are UNKNOWN. Address order is not execution order.\n");
            return out.toString();
        }
    }

    private record QueueEntry(long entry,List<Long> path,int depth) {}

    private static String hex(long address){
        return String.format(Locale.ROOT,"0x%08X",address);
    }

    private static String chain(List<Long> path) {
        StringBuilder out=new StringBuilder();
        for(long id:path) {
            if(out.length()>0)out.append(" -> ");
            out.append(hex(id));
        }
        return out.toString();
    }

    /**
     * Cycle detection is independent of the BFS shortest-path tree. A
     * convergent diamond is not a cycle, while cross-edges between already
     * scheduled functions may form real source-level recursion. Kahn's
     * algorithm works on the bounded observed subgraph without Java recursion.
     */
    private static boolean observedCycle(Map<Long,HardwareCallEffects.FunctionNode> graph,
            Set<Long> visited) {
        Map<Long,Integer> indegree=new HashMap<>();
        for(long pc:visited)indegree.put(pc,0);
        for(long pc:visited)
            for(long callee:graph.get(pc).directCallees())
                if(indegree.containsKey(callee))
                    indegree.put(callee,indegree.get(callee)+1);
        ArrayDeque<Long> ready=new ArrayDeque<>();
        for(var entry:indegree.entrySet())
            if(entry.getValue()==0)ready.addLast(entry.getKey());
        int removed=0;
        while(!ready.isEmpty()) {
            long pc=ready.removeFirst();removed++;
            for(long callee:graph.get(pc).directCallees())
                if(indegree.containsKey(callee)) {
                    int remaining=indegree.get(callee)-1;
                    indegree.put(callee,remaining);
                    if(remaining==0)ready.addLast(callee);
                }
        }
        return removed<visited.size();
    }

    /**
     * Evidence IDs are functions with independently observed MMIO/VBR sites.
     * This method does not infer reachability via gaps or indirect branches.
     * Cycles, missing direct targets and budget ceilings remain explicit.
     */
    public static Summary trace(long root,Collection<HardwareCallEffects.FunctionNode> nodes,
            Collection<Long> evidenceFunctions,int maxDepth,int maxNodes,int maxEvidence) {
        if(root<0 || nodes==null || evidenceFunctions==null ||
                maxDepth<0 || maxDepth>MAX_DEPTH ||
                maxNodes<1 || maxNodes>MAX_NODES ||
                maxEvidence<1 || maxEvidence>MAX_EVIDENCE ||
                nodes.size()>MAX_INPUT_NODES ||
                evidenceFunctions.size()>MAX_INPUT_NODES)
            throw new IllegalArgumentException("Invalid bounded reset graph input");
        Map<Long,HardwareCallEffects.FunctionNode> graph=new HashMap<>();
        long edges=0;
        for(HardwareCallEffects.FunctionNode n:nodes) {
            if(n==null || graph.putIfAbsent(n.entry(),n)!=null)
                throw new IllegalArgumentException("Duplicate/bad function entry");
            edges+=n.directCallees().size();
            if(edges>MAX_INPUT_EDGES)
                throw new IllegalArgumentException("Unbounded direct-call edges");
        }
        for(Long id:evidenceFunctions)
            if(id==null || id<0)
                throw new IllegalArgumentException("Invalid evidence function");
        if(!graph.containsKey(root))
            return new Summary(false,0,true,false,false,List.of(),Set.of());
        Set<Long> evidenceIds=new HashSet<>(evidenceFunctions);
        Set<Long> visited=new HashSet<>();
        Set<Long> scheduled=new HashSet<>();
        ArrayDeque<QueueEntry> queue=new ArrayDeque<>();
        queue.add(new QueueEntry(root,List.of(root),0));
        scheduled.add(root);
        List<Evidence> matched=new ArrayList<>();
        boolean unresolved=false,recursive=false,truncated=false;
        while(!queue.isEmpty()){
            QueueEntry current=queue.removeFirst();
            if(visited.contains(current.entry()))continue;
            if(visited.size()>=maxNodes){truncated=true;unresolved=true;break;}
            HardwareCallEffects.FunctionNode node=graph.get(current.entry());
            if(node==null){unresolved=true;continue;}
            visited.add(node.entry());
            if(node.unresolvedFlow())unresolved=true;
            if(evidenceIds.contains(node.entry())){
                if(matched.size()<maxEvidence)
                    matched.add(new Evidence(node.entry(),chain(current.path()),
                        current.depth(),node.memoryStore(),node.vbrWrite()));
                else {truncated=true;unresolved=true;}
            }
            if(current.depth()>=maxDepth){
                if(!node.directCallees().isEmpty()){truncated=true;unresolved=true;}
                continue;
            }
            for(long id:node.directCallees()){
                if(id<0 || !graph.containsKey(id)){unresolved=true;continue;}
                if(!scheduled.contains(id)) {
                    // Count queued targets as well as examined functions.
                    // A wide graph cannot enqueue unbounded alternate paths
                    // before the visited-node budget becomes effective.
                    if(scheduled.size()>=maxNodes) {
                        truncated=true;unresolved=true;
                        continue;
                    }
                    scheduled.add(id);
                    List<Long> extended=new ArrayList<>(current.path());
                    extended.add(id);
                    queue.addLast(new QueueEntry(id,List.copyOf(extended),current.depth()+1));
                }
            }
        }
        recursive=observedCycle(graph,visited);
        if(recursive)unresolved=true;
        return new Summary(true,visited.size(),unresolved,recursive,truncated,matched,visited);
    }
}
