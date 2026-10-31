package ghidrassist.hardware;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Bounded, intraprocedural *potential* first-site search for SIMCR.
 * Does NOT determine the first write after hardware RESET, path feasibility,
 * active MM mode, write-once latch or execution chronology.
 */
public final class HardwareSimcrLocalFirst {
    private HardwareSimcrLocalFirst(){}
    public enum Effect { NONE, WORD_LITERAL, UNKNOWN_WORD, ALIAS_OR_CALL_BARRIER }
    public record Node(long pc,List<Long> successors,Effect effect,Integer word) {
        public Node {
            if(pc<0 || successors==null || effect==null ||
                    effect==Effect.WORD_LITERAL &&
                        (word==null || word<0 || word>0xffff) ||
                    effect!=Effect.WORD_LITERAL && word!=null)
                throw new IllegalArgumentException("Invalid local CFG SIMCR node");
            successors=List.copyOf(successors);
        }
    }
    public record FirstSite(long pc,int word) {}
    public record Result(long function,List<FirstSite> literalCandidates,
            boolean unknownFirstPossible,boolean exitWithoutSimcr,
            boolean cyclesOrIncompleteEdges,boolean workLimitReached,
            int visitedNodes) {
        public Result {literalCandidates=List.copyOf(literalCandidates);}
    }
    public static Result inspect(long function,long entry,
            Collection<Node> graph,boolean otherUncertainty,int visitBudget) {
        if(function<0 || entry<0 || graph==null || visitBudget<1 ||
                graph.size()>50000)
            throw new IllegalArgumentException("Invalid first-site search budget");
        Map<Long,Node> nodes=new HashMap<>();
        for(Node n:graph) {
            if(n==null || nodes.putIfAbsent(n.pc(),n)!=null)
                throw new IllegalArgumentException("Duplicate/invalid CFG node");
        }
        if(!nodes.containsKey(entry))
            return new Result(function,List.of(),true,false,true,false,0);
        Map<Long,FirstSite> candidates=new TreeMap<>();
        // Iterative DFS uses WHITE/GRAY/BLACK state, not merely a visited
        // set. A second predecessor of a completed (BLACK) node is a CFG
        // join, NOT proof of a cycle. Only an edge back to the active
        // (GRAY) traversal stack demonstrates a modeled cycle.
        //
        // First SIMCR writes terminate that path, so successors beyond an
        // already identified first write cannot create false uncertainty.
        Map<Long,Byte> color=new HashMap<>();
        ArrayDeque<TraversalFrame> pending=new ArrayDeque<>();
        pending.push(new TraversalFrame(nodes.get(entry)));
        boolean unknown=otherUncertainty,exit=false,uncertainEdges=false,limited=false;
        while(!pending.isEmpty()) {
            TraversalFrame frame=pending.peek();
            Node n=frame.node;
            if(!frame.entered) {
                if(color.size()>=visitBudget) {
                    limited=true;unknown=true;
                    break;
                }
                frame.entered=true;
                color.put(n.pc(),(byte)1); // GRAY: active DFS ancestry
                if(n.effect()==Effect.WORD_LITERAL) {
                    candidates.put(n.pc(),new FirstSite(n.pc(),n.word()));
                    color.put(n.pc(),(byte)2);
                    pending.pop();
                    continue;
                }
                if(n.effect()==Effect.UNKNOWN_WORD) {
                    unknown=true; // A possible first write has unknown value.
                    color.put(n.pc(),(byte)2);
                    pending.pop();
                    continue;
                }
                if(n.effect()==Effect.ALIAS_OR_CALL_BARRIER)
                    unknown=true; // May or may not write SIMCR.
                if(n.successors().isEmpty())exit=true;
            }
            if(frame.successorIndex==n.successors().size()) {
                color.put(n.pc(),(byte)2); // BLACK: all successors explored
                pending.pop();
                continue;
            }
            long successor=n.successors().get(frame.successorIndex++);
            Node next=nodes.get(successor);
            if(next==null) {
                unknown=true;uncertainEdges=true;
            }else {
                Byte state=color.get(successor);
                if(state==null) {
                    pending.push(new TraversalFrame(next));
                }else if(state==1) {
                    // A real graph back-edge may permit indefinite looping.
                    // Do not confuse a converging diamond with a cycle.
                    unknown=true;uncertainEdges=true;
                }
            }
        }
        return new Result(function,new ArrayList<>(candidates.values()),
            unknown,exit,uncertainEdges,limited,color.size());
    }
    private static final class TraversalFrame {
        final Node node;
        int successorIndex;
        boolean entered;
        TraversalFrame(Node node){this.node=node;}
    }
    public static String markdown(List<Result> results,int omittedFunctions) {
        if(results==null || omittedFunctions<0)
            throw new IllegalArgumentException("Missing static first-site evidence");
        StringBuilder out=new StringBuilder(
            "## Possible first SIMCR source sites within individual functions\n\n")
            .append("A first source PC below is only FIRST ON A MODELED ")
            .append("INTRAPROCEDURAL CFG PATH. It is **not** the first ")
            .append("executed SIMCR write after RESET, a reachable MCU ")
            .append("boot path, a proven branch predicate or a latched MM bit. ")
            .append("Other functions, callees, interrupts and actual ")
            .append("hardware state are UNKNOWN.\n\n")
            .append("- Examined local functions: ").append(results.size())
            .append("; omitted because of function/global caps: ")
            .append(omittedFunctions).append(".\n\n");
        int shown=Math.min(results.size(),60);
        for(int i=0;i<shown;i++){
            Result r=results.get(i);
            out.append("- function ")
                .append(String.format(Locale.ROOT,"0x%08X",r.function()))
                .append(": possible source-first literal sites ");
            if(r.literalCandidates().isEmpty())out.append("NONE IDENTIFIED");
            for(FirstSite f:r.literalCandidates())
                out.append(String.format(Locale.ROOT,
                    "[PC 0x%08X -> word 0x%04X] ",f.pc(),f.word()));
            out.append("; unknown first effects=").append(r.unknownFirstPossible())
                .append("; exit without known SIMCR=").append(r.exitWithoutSimcr())
                .append("; cycles/CFG gaps=").append(r.cyclesOrIncompleteEdges())
                .append("; work limited=").append(r.workLimitReached())
                .append("; explored nodes=").append(r.visitedNodes()).append("\n");
        }
        if(results.size()>shown)out.append("- More functions omitted from display.\n");
        return out.append("\n").toString();
    }
}
