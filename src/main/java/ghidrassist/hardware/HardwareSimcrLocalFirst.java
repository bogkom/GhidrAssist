package ghidrassist.hardware;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
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
        ArrayDeque<Long> pending=new ArrayDeque<>();
        Set<Long> visited=new HashSet<>();
        pending.add(entry);
        boolean unknown=otherUncertainty,exit=false,uncertainEdges=false,limited=false;
        while(!pending.isEmpty()) {
            long pc=pending.removeFirst();
            if(visited.contains(pc)){
                // Cycles admit paths of arbitrary length. Never infer that
                // one discovered candidate necessarily executes first.
                uncertainEdges=true;unknown=true;
                continue;
            }
            if(visited.size()>=visitBudget) {
                limited=true;unknown=true;
                break;
            }
            visited.add(pc);
            Node n=nodes.get(pc);
            if(n==null) {unknown=true;uncertainEdges=true;continue;}
            if(n.effect()==Effect.WORD_LITERAL) {
                candidates.put(pc,new FirstSite(pc,n.word()));
                continue; // The first matching write on this modeled path.
            }
            if(n.effect()==Effect.UNKNOWN_WORD) {
                unknown=true;continue; // First write value is unresolved.
            }
            if(n.effect()==Effect.ALIAS_OR_CALL_BARRIER)
                unknown=true; // Could write SIMCR, or leave it unchanged.
            if(n.successors().isEmpty())exit=true;
            for(long successor:n.successors()) {
                if(!nodes.containsKey(successor)){
                    unknown=true;uncertainEdges=true;
                    continue;
                }
                pending.addLast(successor);
            }
        }
        return new Result(function,new ArrayList<>(candidates.values()),
            unknown,exit,uncertainEdges,limited,visited.size());
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
