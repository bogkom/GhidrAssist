package ghidrassist.hardware;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * GA-02/03: a bounded, read-only, input-independent post-return constant
 * summary for a *fully decoded, acyclic* CPU32 leaf containing conditional
 * branches. A constant is returned only if EVERY CFG path to EVERY RTS
 * establishes the exact same value. Never infer branch feasibility.
 */
public final class HardwareVerifiedBranchReturn {
    private HardwareVerifiedBranchReturn(){}
    public static final int MAX_INSTRUCTIONS=48;
    public static final int MAX_EDGES=96;
    private static final Pattern CONDITIONAL=Pattern.compile(
        "B(?:CC|CS|EQ|NE|GE|GT|HI|LE|LS|LT|MI|PL|VC|VS)(?:\\.[BWSL])?");
    private static final Pattern UNCONDITIONAL=Pattern.compile("BRA(?:\\.[BWSL])?");
    private static final Set<String> CONSTANTS=Set.of("MOVE.L","MOVEA.L");

    private static void agree(Map<String,Long> prior,Map<String,Long> incoming){
        prior.entrySet().removeIf(e->!e.getValue().equals(incoming.get(e.getKey())));
    }

    /**
     * lengths MUST come from actual decoded Ghidra instructions. Requiring
     * exact contiguous byte coverage prevents omitted bytes from becoming
     * an invented proof. Unsupported kinds/edges, cycles and disconnected
     * regions fail closed.
     */
    public static Map<String,Long> summarize(long entry,long bodyBytes,
            List<HardwareDataflow.Step> steps,Map<Long,Integer> lengths){
        if(entry<0 || bodyBytes<6 || bodyBytes>MAX_INSTRUCTIONS*6L ||
                steps==null || lengths==null || steps.size()<3 ||
                steps.size()>MAX_INSTRUCTIONS || steps.size()!=lengths.size())
            return Map.of();
        List<HardwareDataflow.Step> sorted=new ArrayList<>(steps);
        if(sorted.contains(null))return Map.of();
        sorted.sort(Comparator.comparingLong(s->s.address));
        Map<Long,HardwareDataflow.Step> nodes=new LinkedHashMap<>();
        Map<Long,Integer> remaining=new HashMap<>();
        long cursor=entry;
        int edgeCount=0;
        int branches=0;
        for(HardwareDataflow.Step step:sorted){
            Integer len=lengths.get(step.address);
            if(len==null || step.address!=cursor ||
                    len<2 || len>6 || (len&1)!=0 ||
                    nodes.putIfAbsent(step.address,step)!=null)
                return Map.of();
            cursor+=len;
            if(step.sideEffectRegisters.size()>0 &&
                    !("RTS".equals(step.mnemonic) &&
                      step.sideEffectRegisters.equals(Set.of("A7"))))
                return Map.of();
            int successorCount=step.successors.size();
            if(step.kind==HardwareDataflow.Kind.SET_POINTER &&
                    CONSTANTS.contains(step.mnemonic) &&
                    step.register!=null &&
                    step.register.matches("[AD][0-6]|D7") &&
                    len==6 && successorCount==1 &&
                    step.successors.get(0)==cursor){
                // A canonical immediate full-width register definition.
            } else if(step.kind==HardwareDataflow.Kind.OTHER &&
                    "RTS".equals(step.mnemonic) &&
                    len==2 && successorCount==0){
                // Ordinary subroutine return; no synthetic fallthrough.
            } else if(step.kind==HardwareDataflow.Kind.OTHER &&
                    "NOP".equals(step.mnemonic) &&
                    len==2 && successorCount==1 &&
                    step.successors.get(0)==cursor){
                // Known inert CPU32 instruction.
            } else if(step.kind==HardwareDataflow.Kind.OTHER &&
                    UNCONDITIONAL.matcher(step.mnemonic).matches() &&
                    successorCount==1){
                branches++;
            } else if(step.kind==HardwareDataflow.Kind.OTHER &&
                    CONDITIONAL.matcher(step.mnemonic).matches() &&
                    successorCount==2 &&
                    step.successors.contains(cursor) &&
                    !step.successors.get(0).equals(step.successors.get(1))){
                branches++;
            } else return Map.of();
            edgeCount+=successorCount;
            if(edgeCount>MAX_EDGES)return Map.of();
            remaining.put(step.address,0);
        }
        if(cursor-entry!=bodyBytes || branches==0)return Map.of();
        for(HardwareDataflow.Step step:sorted){
            for(Long next:step.successors){
                if(next==null || !nodes.containsKey(next))return Map.of();
                remaining.put(next,remaining.get(next)+1);
            }
        }
        if(remaining.get(entry)!=0)return Map.of();
        ArrayDeque<Long> ready=new ArrayDeque<>();
        for(HardwareDataflow.Step step:sorted)
            if(remaining.get(step.address)==0)ready.add(step.address);
        Map<Long,Map<String,Long>> incoming=new HashMap<>();
        incoming.put(entry,new HashMap<>());
        Map<String,Long> returnConstants=null;
        int processed=0,returns=0;
        while(!ready.isEmpty()){
            long pc=ready.removeFirst();
            Map<String,Long> before=incoming.get(pc);
            // Unreachable or disconnected blocks can hide unsafe effects.
            if(before==null)return Map.of();
            HardwareDataflow.Step step=nodes.get(pc);
            Map<String,Long> out=new HashMap<>(before);
            if(step.kind==HardwareDataflow.Kind.SET_POINTER)
                out.put(step.register,step.operand&HardwareDataflow.MASK24);
            if("RTS".equals(step.mnemonic)){
                returns++;
                if(returnConstants==null)returnConstants=new HashMap<>(out);
                else agree(returnConstants,out);
            }
            for(Long next:step.successors){
                Map<String,Long> old=incoming.get(next);
                if(old==null)incoming.put(next,new HashMap<>(out));
                else agree(old,out);
                int left=remaining.get(next)-1;
                remaining.put(next,left);
                if(left==0)ready.add(next);
            }
            processed++;
        }
        // All vertices must be processed in a DAG, all exits must be RTS,
        // and every returned constant must agree on every possible path.
        return processed==nodes.size() && returns>0 &&
                returnConstants!=null && !returnConstants.isEmpty()?
                Map.copyOf(returnConstants):Map.of();
    }
}
