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
            // A FunctionNode contains target identities, not CALL-PC
            // ordering. The shared finite BFS budget must never depend
            // on the incidental Ghidra Listing/reference discovery order.
            // Retain duplicates (they cannot consume extra scheduled nodes)
            // but visit source targets in one canonical numeric order.
            List<Long> canonical=new ArrayList<>(calls);
            canonical.sort(Long::compare);
            calls=List.copyOf(canonical);
        }
    }
    public record CallSite(long function,long pc,Long target) {
        public CallSite {
            if(function<0 || pc<0 || target!=null && target<0)
                throw new IllegalArgumentException("Invalid CALL site");
        }
    }
    /**
     * One shortest, canonical function-only chain to an observed modeled
     * source or an explicitly uninspected frontier. No CALL-site PCs,
     * branch feasibility, register propagation or execution are asserted.
     */
    public enum WitnessKind {
        MM_SOURCE, STORE_ALIAS, UNKNOWN_FLOW, MISSING_TARGET,
        DEPTH_CUTOFF, NODE_CUTOFF, BATCH_CUTOFF
    }
    public record SourceWitness(WitnessKind kind,List<Long> chain) {
        public SourceWitness {
            if(kind==null || chain==null || chain.isEmpty() ||
                    chain.size()>34)
                throw new IllegalArgumentException("Invalid source witness");
            for(Long entry:chain)
                if(entry==null || entry<0)
                    throw new IllegalArgumentException("Invalid witness function");
            chain=List.copyOf(chain);
        }
    }
    public record Summary(boolean mayMm,boolean unknownAlias,
            boolean unknownControl,boolean cycle,boolean limited,int visited,
            SourceWitness mmWitness,SourceWitness aliasWitness,
            SourceWitness unknownWitness){
        public Summary {
            if(visited<0 || mmWitness!=null &&
                    (!mayMm || mmWitness.kind()!=WitnessKind.MM_SOURCE) ||
                    aliasWitness!=null &&
                    (!unknownAlias ||
                        aliasWitness.kind()!=WitnessKind.STORE_ALIAS) ||
                    unknownWitness!=null &&
                    (!unknownControl || unknownWitness.kind()==WitnessKind.MM_SOURCE ||
                        unknownWitness.kind()==WitnessKind.STORE_ALIAS))
                throw new IllegalArgumentException("Contradictory source witness");
        }
        /** Preserve existing read-only summary callers without fabricated paths. */
        public Summary(boolean mayMm,boolean unknownAlias,
                boolean unknownControl,boolean cycle,boolean limited,int visited){
            this(mayMm,unknownAlias,unknownControl,cycle,limited,visited,
                null,null,null);
        }
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
                .append("Chains are shortest function-only source witnesses or ")
                .append("uninspected frontiers, not executed paths; NONE does ")
                .append("not negate a true uncertainty/cycle flag. ")
                .append("No caller/callee values propagated. An unresolved ")
                .append("callee or alias is not evidence of no MM write.\n")
                .append("- Rows: ").append(rows.size())
                .append("; additional rows omitted: ").append(omitted).append(".\n")
                .append("Selected source callers receive computation and ")
                .append("display priority within the shared finite budget; ")
                .append("all visible rows remain sorted by caller/CALL PC/target. ")
                .append("Dropped and uninspected source possibilities remain UNKNOWN.\n");
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
                    .append("; examined=").append(s.visited())
                    .append("; MM source chain=").append(witness(s.mmWitness()))
                    .append("; alias source chain=").append(witness(s.aliasWitness()))
                    .append("; unknown/frontier chain=")
                    .append(witness(s.unknownWitness())).append("\n");
            }
            return b.append("\n").toString();
        }
    }
    private static String hex(long n){
        return String.format(Locale.ROOT,"0x%08X",n);
    }
    private static String witness(SourceWitness w){
        if(w==null)return "NONE";
        StringJoiner out=new StringJoiner(" -> ",w.kind()+":","\u0020");
        for(long entry:w.chain())out.add(hex(entry));
        return out.toString().trim();
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
    /** Guard the source graph, not just the number of functions/CALL PCs. */
    public static final int MAX_FUNCTION_EDGES=200_000;
    private static final class BatchBudget {
        int remaining=MAX_BATCH_SCHEDULED;
    }
    private record Work(long pc,int depth){}
    private record DfsFrame(long pc,Iterator<Long> remaining){}

    /** Parent tree follows the canonical bounded BFS, not Listing order. */
    private static List<Long> chain(Map<Long,Long> parent,long node){
        ArrayDeque<Long> reversed=new ArrayDeque<>();
        Long current=node;
        while(current!=null){
            if(reversed.size()>=34)
                throw new IllegalStateException("Unbounded source witness");
            reversed.addFirst(current);
            current=parent.get(current);
        }
        return List.copyOf(reversed);
    }
    /** The cutoff target has NOT been visited or verified as a source. */
    private static List<Long> frontier(Map<Long,Long> parent,
            long known,long unknownTarget){
        List<Long> path=new ArrayList<>(chain(parent,known));
        path.add(unknownTarget);
        return List.copyOf(path);
    }

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
        if(budget.remaining==0)return new Summary(false,false,true,false,true,0,
            null,null,new SourceWitness(WitnessKind.BATCH_CUTOFF,List.of(target)));
        budget.remaining--;
        Set<Long> seen=new HashSet<>();
        // One queue entry per distinct PC, including missing targets.
        // Previously a many-to-one call graph could enqueue unbounded
        // duplicate nodes before the visited-node cap was reached.
        Set<Long> scheduled=new HashSet<>();
        ArrayDeque<Work> queue=new ArrayDeque<>();
        queue.add(new Work(target,0));
        scheduled.add(target);
        Map<Long,Long> parent=new HashMap<>();
        parent.put(target,null);
        SourceWitness mmWitness=null,aliasWitness=null,unknownWitness=null;
        boolean mm=false,alias=false,unknown=false,limit=false;
        while(!queue.isEmpty()){
            Work w=queue.removeFirst();
            if(seen.contains(w.pc()))continue;
            if(seen.size()>=maxCount){
                limit=true;unknown=true;
                if(unknownWitness==null)
                    unknownWitness=new SourceWitness(WitnessKind.NODE_CUTOFF,
                        chain(parent,w.pc()));
                break;
            }
            FunctionNode n=graph.get(w.pc());
            if(n==null){
                unknown=true;
                if(unknownWitness==null)
                    unknownWitness=new SourceWitness(WitnessKind.MISSING_TARGET,
                        chain(parent,w.pc()));
                continue;
            }
            seen.add(w.pc());
            if(n.mm() && mmWitness==null)
                mmWitness=new SourceWitness(WitnessKind.MM_SOURCE,
                    chain(parent,w.pc()));
            if(n.unknownAlias() && aliasWitness==null)
                aliasWitness=new SourceWitness(WitnessKind.STORE_ALIAS,
                    chain(parent,w.pc()));
            if(n.unknownControl() && unknownWitness==null)
                unknownWitness=new SourceWitness(WitnessKind.UNKNOWN_FLOW,
                    chain(parent,w.pc()));
            mm|=n.mm();alias|=n.unknownAlias();unknown|=n.unknownControl();
            for(long callee:n.calls()){
                if(w.depth()>=maxDepth){
                    limit=true;unknown=true;
                    if(unknownWitness==null)
                        unknownWitness=new SourceWitness(WitnessKind.DEPTH_CUTOFF,
                            frontier(parent,w.pc(),callee));
                }else if(!scheduled.contains(callee)){
                    // A frontier is NOT a decoded MMIO source: retain the
                    // missing observation, not a fabricated false result.
                    if(scheduled.size()>=maxCount || budget.remaining==0){
                        limit=true;unknown=true;
                        if(unknownWitness==null)
                            unknownWitness=new SourceWitness(
                                budget.remaining==0?WitnessKind.BATCH_CUTOFF:
                                    WitnessKind.NODE_CUTOFF,
                                frontier(parent,w.pc(),callee));
                    }else{
                        scheduled.add(callee);
                        budget.remaining--;
                        parent.put(callee,w.pc());
                        queue.addLast(new Work(callee,w.depth()+1));
                    }
                }
            }
        }
        boolean cyclic=cycle(target,graph,seen);
        return new Summary(mm,alias,unknown||cyclic,cyclic,limit,seen.size(),
            mmWitness,aliasWitness,unknownWitness);
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
        long edges=0;
        for(FunctionNode n:functions) {
            if(n==null || graph.putIfAbsent(n.entry(),n)!=null)
                throw new IllegalArgumentException("Duplicate/null function");
            edges+=n.calls().size();
            if(edges>MAX_FUNCTION_EDGES)
                throw new IllegalArgumentException("Unbounded source CALL edges");
        }
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
        // Reserve bounded computation and display for selected callers FIRST.
        // An unrelated earlier CALL must not consume the entire shared budget
        // (or report rowCap) before the user-selected analysis reaches its
        // target. Still give every other CALL its own fail-closed summary.
        // Caller/PC rows AND each function's direct target adjacency
        // are canonical. A capped graph may still be UNKNOWN/LIMITED, but
        // which source nodes receive the finite budget is deterministic
        // regardless of how Ghidra reported source reference order.
        // Cache never persists or spans revisions.
        Map<Long,Summary> summaries=new HashMap<>();
        BatchBudget budget=new BatchBudget();
        List<Row> rows=new ArrayList<>();
        int omitted=0;
        for(int priority=0;priority<2;priority++) {
            for(CallSite site:sorted) {
                boolean selected=interesting.contains(site.function());
                if(selected!=(priority==0))continue;
                Summary summary=summaries.computeIfAbsent(site.target(),
                    target->inspect(target,graph,maxDepth,maxCount,budget));
                if(!selected && !summary.uncertainOrMm())continue;
                if(rows.size()<rowCap)rows.add(new Row(site,summary));
                else omitted++;
            }
        }
        // Priority controls which rows survive a cap, never the visible
        // CALL/PC/target ordering of the returned report.
        rows.sort(Comparator.comparingLong((Row r)->r.call().function())
            .thenComparingLong(r->r.call().pc())
            .thenComparing(r->r.call().target(),
                Comparator.nullsFirst(Long::compare)));
        return new Report(rows,omitted);
    }
}
