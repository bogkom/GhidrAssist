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

/**
 * Bounded path-existence evidence between candidate MMIO write sites.
 * A CFG edge denotes a syntactic possibility, not a feasible path or a
 * temporal ordering of two writes in a real running microcontroller.
 */
public final class HardwareCfgStorePaths {
    private HardwareCfgStorePaths(){}
    public static final int MAX_SITES_PER_FUNCTION=12;
    public static final int MAX_DISPLAYED_RELATIONS=90;
    public record Node(long pc,List<Long> successors) {
        public Node {
            if(pc<0 || successors==null)
                throw new IllegalArgumentException("Invalid CFG node");
            successors=List.copyOf(successors);
        }
    }
    public record Store(long pc,String register){
        public Store {
            if(pc<0 || register==null || register.isBlank())
                throw new IllegalArgumentException("Invalid candidate store");
        }
    }
    public enum Relationship {
        A_MAY_PRECEDE_B,
        B_MAY_PRECEDE_A,
        BOTH_DIRECTIONS_POSSIBLE_IN_CYCLE,
        NO_CONNECTING_PATH_IN_MODELED_CFG,
        SEARCH_LIMIT_UNKNOWN
    }
    public record Pair(long function,long aPc,long bPc,String aRegister,
                       String bRegister,Relationship relation,
                       boolean unknownFunctionControlFlow) {}
    public record Report(List<Pair> relations,boolean truncated,boolean unknownFlow) {
        public Report {relations=List.copyOf(relations);}
    }
    private enum Reach { YES, NO_MODELED_PATH, LIMIT }
    private static Reach reachable(Map<Long,Node> graph,long start,long goal,
                                  int maxVisits){
        ArrayDeque<Long> queue=new ArrayDeque<>();
        Set<Long> seen=new HashSet<>();
        queue.add(start);
        while(!queue.isEmpty()){
            long current=queue.removeFirst();
            if(!seen.add(current))continue;
            if(seen.size()>maxVisits)return Reach.LIMIT;
            if(current==goal)return Reach.YES;
            Node node=graph.get(current);
            if(node==null)continue;
            for(long next:node.successors())
                if(graph.containsKey(next) && !seen.contains(next))
                    queue.addLast(next);
        }
        return Reach.NO_MODELED_PATH;
    }
    public static Report analyze(long function,Collection<Node> nodes,
                                 Collection<Store> stores,boolean functionUncertain,
                                 int visitBudget) {
        if(function<0 || nodes==null || stores==null || visitBudget<1 ||
                nodes.size()>50000)
            throw new IllegalArgumentException("Invalid bounded CFG evidence");
        Map<Long,Node> graph=new HashMap<>();
        boolean gaps=false;
        for(Node n:nodes) {
            if(n==null || graph.putIfAbsent(n.pc(),n)!=null)
                throw new IllegalArgumentException("Duplicate/invalid CFG nodes");
        }
        for(Node node:graph.values())
            for(long next:node.successors())
                if(!graph.containsKey(next))gaps=true;
        List<Store> selected=new ArrayList<>();
        Set<Long> distinctPcs=new HashSet<>();
        for(Store s:stores) {
            if(s==null || !graph.containsKey(s.pc()))
                throw new IllegalArgumentException("Store missing from CFG");
            if(!distinctPcs.add(s.pc()))
                throw new IllegalArgumentException("Duplicate store instruction");
            selected.add(s);
        }
        selected.sort(Comparator.comparingLong(Store::pc));
        boolean limited=selected.size()>MAX_SITES_PER_FUNCTION;
        if(limited)selected=selected.subList(0,MAX_SITES_PER_FUNCTION);
        boolean uncertainty=functionUncertain||gaps;
        List<Pair> pairs=new ArrayList<>();
        for(int i=0;i<selected.size();i++)for(int j=i+1;j<selected.size();j++){
            Store a=selected.get(i),b=selected.get(j);
            Reach ab=reachable(graph,a.pc(),b.pc(),visitBudget);
            Reach ba=reachable(graph,b.pc(),a.pc(),visitBudget);
            Relationship status;
            if(ab==Reach.LIMIT || ba==Reach.LIMIT) {
                status=Relationship.SEARCH_LIMIT_UNKNOWN;limited=true;
            }else if(ab==Reach.YES && ba==Reach.YES) {
                status=Relationship.BOTH_DIRECTIONS_POSSIBLE_IN_CYCLE;
            }else if(ab==Reach.YES) {
                status=Relationship.A_MAY_PRECEDE_B;
            }else if(ba==Reach.YES) {
                status=Relationship.B_MAY_PRECEDE_A;
            }else status=Relationship.NO_CONNECTING_PATH_IN_MODELED_CFG;
            pairs.add(new Pair(function,a.pc(),b.pc(),a.register(),
                b.register(),status,uncertainty));
        }
        return new Report(pairs,limited,uncertainty);
    }
    public static String markdown(List<Pair> relations,int limitedFunctions) {
        if(relations==null || limitedFunctions<0)
            throw new IllegalArgumentException("Invalid path report");
        StringBuilder out=new StringBuilder(
            "## CFG possible paths between candidate configuration writes\n\n")
            .append("- Modeled directed relationships: ").append(relations.size())
            .append("; functions exceeding site/search/global limits: ")
            .append(limitedFunctions).append(".\n")
            .append("- These describe only graph paths between static instruction ")
            .append("addresses **inside one function**, NOT whether both writes ")
            .append("are feasible, executed, ordered after RESET or visible to ")
            .append("the write-once SIMCR MM latch.\n")
            .append("- A one-way modeled path is NOT an always-before relation; ")
            .append("a missing modeled path is NOT proof that control flow or ")
            .append("an interrupt cannot reach that write. Computed jumps and ")
            .append("unknown callees remain uncertain.\n")
            .append("- Separate function sites and distinct CSBAR/CSOR/CSPAR ")
            .append("words are never combined into an active hardware map.\n\n");
        int displayed=Math.min(MAX_DISPLAYED_RELATIONS,relations.size());
        for(int i=0;i<displayed;i++){
            Pair p=relations.get(i);
            out.append("- function ").append(hex(p.function()))
               .append(": ").append(hex(p.aPc())).append(" ")
               .append(p.aRegister()).append(" / ")
               .append(hex(p.bPc())).append(" ").append(p.bRegister())
               .append("; ").append(p.relation())
               .append("; unknown call/tail branch/gap=")
               .append(p.unknownFunctionControlFlow()).append("\n");
        }
        if(displayed<relations.size())out.append("- ")
            .append(relations.size()-displayed)
            .append(" additional relations omitted by display cap.\n");
        return out.append("\n").toString();
    }
    private static String hex(long value){
        return String.format(Locale.ROOT,"0x%08X",value);
    }
}
