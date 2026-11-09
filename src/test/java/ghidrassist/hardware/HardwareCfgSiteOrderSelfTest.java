package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;

public final class HardwareCfgSiteOrderSelfTest {
    private static int checks;
    private static void check(boolean ok,String reason){
        checks++;
        if(!ok)throw new AssertionError(reason);
    }
    private static void reject(Runnable r,String reason){
        boolean threw=false;
        try{r.run();}catch(IllegalArgumentException expected){threw=true;}
        check(threw,reason);
    }
    private static HardwareCfgSiteOrder.Node n(long pc,Long... next){
        return new HardwareCfgSiteOrder.Node(pc,List.of(next));
    }
    private static void relation(List<HardwareCfgSiteOrder.Node> graph,
            long from,long to,HardwareCfgSiteOrder.Relation expected){
        check(HardwareCfgSiteOrder.inspect(0x100,graph,true,from,to)==expected,
            expected+" on bounded source CFG");
    }
    public static void main(String[] args){
        var straight=List.of(n(0x100,0x110L),n(0x110,0x120L),n(0x120));
        relation(straight,0x100,0x120,
            HardwareCfgSiteOrder.Relation.POSSIBLE_JSR_BEFORE_MOVEC);
        relation(straight,0x120,0x100,
            HardwareCfgSiteOrder.Relation.POSSIBLE_MOVEC_BEFORE_JSR);
        var cycle=List.of(n(0x100,0x110L),n(0x110,0x120L),
            n(0x120,0x110L));
        relation(cycle,0x110,0x120,
            HardwareCfgSiteOrder.Relation.POSSIBLE_BOTH_ORDERS);
        var split=List.of(n(0x100,0x110L,0x120L),
            n(0x110,0x130L),n(0x120,0x130L),n(0x130));
        relation(split,0x110,0x120,
            HardwareCfgSiteOrder.Relation.NO_OBSERVED_ORDERED_ROUTE);
        check(HardwareCfgSiteOrder.inspect(0x100,split,false,0x110,0x120)==
            HardwareCfgSiteOrder.Relation.UNKNOWN,
            "Incomplete Ghidra Listing cannot prove route absence");
        relation(List.of(n(0x100,0x110L),n(0x110),n(0x120)),
            0x110,0x120,HardwareCfgSiteOrder.Relation.UNKNOWN);
        relation(List.of(n(0x100,0x110L),n(0x110,0x140L)),
            0x100,0x110,HardwareCfgSiteOrder.Relation.UNKNOWN);
        relation(List.of(n(0x100,0x110L),n(0x110,0x110L)),
            0x100,0x130,HardwareCfgSiteOrder.Relation.UNKNOWN);
        relation(List.of(n(0x100,0x110L),n(0x100,0x110L),
            n(0x110)),0x100,0x110,HardwareCfgSiteOrder.Relation.UNKNOWN);
        check(HardwareCfgSiteOrder.inspect(0x100,null,true,0x100,0x110)==
            HardwareCfgSiteOrder.Relation.UNKNOWN,"Missing graph unknown");
        check(HardwareCfgSiteOrder.inspect(0x100,straight,true,0x100,0x100)==
            HardwareCfgSiteOrder.Relation.UNKNOWN,"Coincident PCs unknown");
        var longGraph=new ArrayList<HardwareCfgSiteOrder.Node>();
        for(int i=0;i<=HardwareCfgSiteOrder.MAX_NODES;i++)
            longGraph.add(n(0x100+2L*i));
        check(HardwareCfgSiteOrder.inspect(0x100,longGraph,true,0x100,0x102)==
            HardwareCfgSiteOrder.Relation.UNKNOWN,"Node budget fails closed");
        reject(()->n(0x101),"Odd instruction identity rejected");
        reject(()->n(0x100,0x101L),"Odd successor rejected");
        reject(()->n(0x100,0x1000000L),"24-bit successor bound");
        reject(()->HardwareCfgSiteOrder.inspect(0x1000000L,straight,
            true,0x100,0x110),"Invalid entry rejected");
        var original=new ArrayList<Long>();
        original.add(0x110L);
        var immutable=new HardwareCfgSiteOrder.Node(0x100,original);
        original.clear();
        check(immutable.successors().equals(List.of(0x110L)),
            "Graph nodes immutable against source list mutation");
        boolean blocked=false;
        try{immutable.successors().clear();}
        catch(UnsupportedOperationException expected){blocked=true;}
        check(blocked,"Node edges immutable");
        System.out.println("HardwareCfgSiteOrderSelfTest PASS: assertions="+checks);
    }
}
