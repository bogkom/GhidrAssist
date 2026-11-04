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
                    .append("; unknown alias=").append(s.unknownAlias())
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
    private record Work(long pc,int depth){}
    private static boolean cycle(long pc,Map<Long,FunctionNode> graph,
            Set<Long> known,Set<Long> gray,Set<Long> black){
        if(gray.contains(pc))return true;
        if(!black.add(pc))return false;
        gray.add(pc);
        FunctionNode n=graph.get(pc);
        if(n!=null)for(long callee:n.calls())
            if(known.contains(callee) &&
                    cycle(callee,graph,known,gray,black))return true;
        gray.remove(pc);
        return false;
    }
    private static Summary inspect(Long target,Map<Long,FunctionNode> graph,
            int maxDepth,int maxCount){
        if(target==null)return new Summary(false,false,true,false,false,0);
        Set<Long> seen=new HashSet<>();
        ArrayDeque<Work> queue=new ArrayDeque<>();
        queue.add(new Work(target,0));
        boolean mm=false,alias=false,unknown=false,limit=false;
        while(!queue.isEmpty()){
            Work w=queue.removeFirst();
            if(seen.contains(w.pc()))continue;
            if(seen.size()>=maxCount){limit=true;unknown=true;break;}
            FunctionNode n=graph.get(w.pc());
            if(n==null){unknown=true;continue;}
            seen.add(w.pc());
            mm|=n.mm();alias|=n.unknownAlias();unknown|=n.unknownControl();
            for(long callee:n.calls())
                if(w.depth()>=maxDepth){limit=true;unknown=true;}
                else if(!seen.contains(callee))queue.addLast(new Work(callee,w.depth()+1));
        }
        boolean cyclic=cycle(target,graph,seen,new HashSet<>(),new HashSet<>());
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
            .thenComparingLong(CallSite::pc));
        Set<Long> interesting=new HashSet<>(interestingCallers);
        List<Row> rows=new ArrayList<>();int omitted=0;
        for(CallSite site:sorted){
            Summary s=inspect(site.target(),graph,maxDepth,maxCount);
            if(!interesting.contains(site.function()) && !s.uncertainOrMm())continue;
            if(rows.size()<rowCap)rows.add(new Row(site,s));
            else omitted++;
        }
        return new Report(rows,omitted);
    }
}
