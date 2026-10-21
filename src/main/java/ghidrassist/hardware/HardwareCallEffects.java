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

    public record FunctionNode(long entry,boolean memoryStore,boolean vbrWrite,
            boolean unresolvedFlow,List<Long> directCallees) {
        public FunctionNode {
            if(entry<0 || directCallees==null)
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
    private static void explore(long id,int depth,int limitDepth,int limitNodes,
            Map<Long,FunctionNode> graph,Set<Long> visiting,Set<Long> completed,
            Acc out){
        if(visiting.contains(id)){out.cycle=true;out.unknown=true;return;}
        if(completed.contains(id))return;
        if(depth>limitDepth || out.visits>=limitNodes){
            out.cap=true;out.unknown=true;return;
        }
        FunctionNode n=graph.get(id);
        if(n==null){out.unknown=true;return;}
        out.visits++;
        out.memory|=n.memoryStore();
        out.vbr|=n.vbrWrite();
        out.unknown|=n.unresolvedFlow();
        visiting.add(id);
        for(long callee:n.directCallees())
            explore(callee,depth+1,limitDepth,limitNodes,
                graph,visiting,completed,out);
        visiting.remove(id);
        completed.add(id);
    }

    public static Summary summarize(long root,Collection<FunctionNode> nodes,
            int maxDepth,int maxFunctions) {
        if(nodes==null || maxDepth<0 || maxFunctions<1)
            throw new IllegalArgumentException("Bad call graph limits");
        Map<Long,FunctionNode> graph=new HashMap<>();
        for(FunctionNode n:nodes)
            if(n==null || graph.putIfAbsent(n.entry(),n)!=null)
                throw new IllegalArgumentException("Duplicate/bad function entry");
        Acc out=new Acc();
        explore(root,0,maxDepth,maxFunctions,graph,new HashSet<>(),
            new HashSet<>(),out);
        return new Summary(out.memory,out.vbr,out.unknown,
            out.cycle,out.cap,out.visits);
    }
}
