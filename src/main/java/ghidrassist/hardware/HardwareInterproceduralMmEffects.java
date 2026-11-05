package ghidrassist.hardware;

import java.util.*;

/** Read-only transitive CALL-site MM effects, not executed RESET ordering. */
public final class HardwareInterproceduralMmEffects {
    private HardwareInterproceduralMmEffects(){}
    public record FunctionNode(long entry,boolean mm,boolean unknownAlias,
            boolean unknownControl,List<Long> calls) {
        public FunctionNode {
            if(entry<0 || calls==null || calls.stream().anyMatch(x->x==null || x<0))
                throw new IllegalArgumentException("Invalid function node");
            calls=List.copyOf(calls);
        }
    }
    public record CallSite(long function,long pc,Long target) {
        public CallSite {
            if(function<0 || pc<0 || target!=null && target<0)
                throw new IllegalArgumentException("Invalid CALL site");
        }
    }
    public record Summary(boolean mayMm,boolean unknownAlias,
            boolean unknownControl,boolean cycle,boolean limited,int visited){
        public boolean uncertainOrMm(){
            return mayMm || unknownAlias || unknownControl || cycle || limited;
        }
    }
    public record Row(CallSite call,Summary summary){}
    public record Report(List<Row> rows,int omitted){
        public Report {rows=List.copyOf(rows);}
        public String markdown(){
            StringBuilder b=new StringBuilder(
                "## Interprocedural SIMCR/MM candidates by CALL instruction\n\n")
                .append("Static possible paths only: NOT execution, feasible ")
                .append("RESET ordering, a latched MM bit, or physical mapping. ")
                .append("No caller/callee values propagated. An unresolved ")
                .append("callee or alias is not evidence of no MM write.\n")
                .append("- Rows: ").append(rows.size())
                .append("; additional rows omitted: ").append(omitted).append(".\n");
            for(Row row:rows){
                CallSite site=row.call();Summary s=row.summary();
                b.append("- caller ").append(hex(site.function()))
                    .append(" PC ").append(hex(site.pc())).append(" -> ")
                    .append(site.target()==null?"UNKNOWN":hex(site.target()))
                    .append("; possible SIMCR/MM low-byte STORE=").append(s.mayMm())
                    .append("; unknown alias/width=").append(s.unknownAlias())
                    .append("; unknown callee/flow=").append(s.unknownControl())
                    .append("; cycle=").append(s.cycle())
                    .append("; cap=").append(s.limited())
                    .append("; examined=").append(s.visited()).append("\n");
            }
            return b.append("\n").toString();
        }
    }
    private static String hex(long n){
        return String.format(Locale.ROOT,"0x%08X",n);
    }

    /**
     * Unknown effective addresses AND unknown STORE widths are possible
     * aliases to SIMCR; a source address alone does not make a zero-width
     * or unmodeled P-code memory mutation safe to exclude.
     */
    static boolean unknownMemoryWrite(Long effectiveAddress,int widthBits){
        return effectiveAddress==null ||
            (widthBits!=8 && widthBits!=16 && widthBits!=32);
    }
    /** Maximum distinct scheduled CALL targets across one analysis batch. */
    public static final int MAX_BATCH_SCHEDULED=16_384;
    private static final class BatchBudget {
        int remaining=MAX_BATCH_SCHEDULED;
    }
    private record Work(long pc,int depth){}
    private record DfsFrame(long pc,Iterator<Long> remaining){}

    /**
     * An explicit DFS stack avoids stack overflow in a wide graph where all
     * nodes are reached within the requested BFS depth but a source-only
     * cross-edge chain is thousands of functions long. Edges outside the
     * bounded inspected subgraph remain UNKNOWN via the caller's cap flag.
     */
    private static boolean cycle(long root,Map<Long,FunctionNode> graph,
            Set<Long> visited){
        if(!visited.contains(root))return false;
        Set<Long> gray=new HashSet<>(),black=new HashSet<>();
        ArrayDeque<DfsFrame> stack=new ArrayDeque<>();
        gray.add(root);
        stack.push(new DfsFrame(root,graph.get(root).calls().iterator()));
        while(!stack.isEmpty()){
            DfsFrame frame=stack.peek();
            if(!frame.remaining().hasNext()){
                gray.remove(frame.pc());
                black.add(frame.pc());
                stack.pop();
                continue;
            }
            long callee=frame.remaining().next();
            if(!visited.contains(callee))continue;
            if(gray.contains(callee))return true;
            if(!black.contains(callee)){
                FunctionNode next=graph.get(callee);
                if(next==null)continue; // never infer a missing target as closed
                gray.add(callee);
                stack.push(new DfsFrame(callee,next.calls().iterator()));
            }
        }
        return false;
    }
    private static Summary inspect(Long target,Map<Long,FunctionNode> graph,
            int maxDepth,int maxCount,BatchBudget budget){
        if(target==null)return new Summary(false,false,true,false,false,0);
        // Exhaustion is UNKNOWN, never a closed negative MM conclusion.
        if(budget.remaining==0)return new Summary(false,false,true,false,true,0);
        budget.remaining--;
        Set<Long> seen=new HashSet<>();
        // One queue entry per distinct PC, including missing targets.
        // Previously a many-to-one call graph could enqueue unbounded
        // duplicate nodes before the visited-node cap was reached.
        Set<Long> scheduled=new HashSet<>();
        ArrayDeque<Work> queue=new ArrayDeque<>();
        queue.add(new Work(target,0));
        scheduled.add(target);
        boolean mm=false,alias=false,unknown=false,limit=false;
        while(!queue.isEmpty()){
            Work w=queue.removeFirst();
            if(seen.contains(w.pc()))continue;
            if(seen.size()>=maxCount){limit=true;unknown=true;break;}
            FunctionNode n=graph.get(w.pc());
            if(n==null){unknown=true;continue;}
            seen.add(w.pc());
            mm|=n.mm();alias|=n.unknownAlias();unknown|=n.unknownControl();
            for(long callee:n.calls()){
                if(w.depth()>=maxDepth){
                    limit=true;unknown=true;
                }else if(!scheduled.contains(callee)){
                    // An omitted node may contain a STORE or unknown
                    // control flow. Preserve the cap as uncertainty; never
                    // publish a negative MM conclusion from a truncated set.
                    if(scheduled.size()>=maxCount || budget.remaining==0){
                        limit=true;unknown=true;
                    }else{
                        scheduled.add(callee);
                        budget.remaining--;
                        queue.addLast(new Work(callee,w.depth()+1));
                    }
                }
            }
        }
        boolean cyclic=cycle(target,graph,seen);
        return new Summary(mm,alias,unknown||cyclic,cyclic,limit,seen.size());
    }
    public static Report analyze(Collection<FunctionNode> functions,
            Collection<CallSite> calls,Collection<Long> interestingCallers,
            int maxDepth,int maxCount,int rowCap){
        if(functions==null || calls==null || interestingCallers==null ||
                maxDepth<0 || maxDepth>32 || maxCount<1 || maxCount>10000 ||
                rowCap<1 || rowCap>1000 || functions.size()>50000 ||
                calls.size()>200000)
            throw new IllegalArgumentException("Invalid bounded call graph");
        Map<Long,FunctionNode> graph=new HashMap<>();
        for(FunctionNode n:functions)
            if(n==null || graph.putIfAbsent(n.entry(),n)!=null)
                throw new IllegalArgumentException("Duplicate/null function");
        List<CallSite> sorted=new ArrayList<>(calls);
        if(sorted.contains(null))throw new IllegalArgumentException("Null call");
        sorted.sort(Comparator.comparingLong(CallSite::function)
            .thenComparingLong(CallSite::pc)
            .thenComparing(CallSite::target,
                Comparator.nullsFirst(Long::compare)));
        if(interestingCallers.size()>50000)
            throw new IllegalArgumentException("Unbounded interesting caller set");
        for(Long caller:interestingCallers)
            if(caller==null || caller<0)
                throw new IllegalArgumentException("Invalid interesting caller");
        Set<Long> interesting=new HashSet<>(interestingCallers);
        // A repeated exact target must reuse its first deterministic summary.
        // A separate cap on total scheduled PCs prevents O(callSites * maxCount)
        // work and retains explicit LIMITED/UNKNOWN for unseen targets.
        Map<Long,Summary> summaries=new HashMap<>();
        BatchBudget budget=new BatchBudget();
        List<Row> rows=new ArrayList<>();int omitted=0;
        for(CallSite site:sorted){
            Summary s=summaries.computeIfAbsent(site.target(),
                target->inspect(target,graph,maxDepth,maxCount,budget));
            if(!interesting.contains(site.function()) && !s.uncertainOrMm())continue;
            if(rows.size()<rowCap)rows.add(new Row(site,s));
            else omitted++;
        }
        return new Report(rows,omitted);
    }
}
