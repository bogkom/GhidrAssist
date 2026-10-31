package ghidrassist.hardware;

import java.util.List;

public final class HardwareCfgStorePathsSelfTest {
    private HardwareCfgStorePathsSelfTest(){}
    private static void ok(boolean success,String text){
        if(!success)throw new AssertionError(text);
    }
    private static HardwareCfgStorePaths.Node n(long pc,long...next) {
        java.util.ArrayList<Long> successors=new java.util.ArrayList<>();
        for(long x:next)successors.add(x);
        return new HardwareCfgStorePaths.Node(pc,successors);
    }
    private static HardwareCfgStorePaths.Store s(long pc,String reg) {
        return new HardwareCfgStorePaths.Store(pc,reg);
    }
    public static void main(String[] args){
        var graph=List.of(n(0,1,2),n(1,3),n(2,3),n(3,4),n(4,3),n(5));
        var observations=List.of(s(1,"SIMCR"),s(2,"CSBAR0"),
            s(3,"CSOR0"),s(4,"TRAMBAR"));
        var r=HardwareCfgStorePaths.analyze(0x2bc0,graph,observations,false,100);
        ok(r.relations().size()==6 && !r.truncated() && !r.unknownFlow(),
            "candidate pairs bounded and complete");
        ok(r.relations().stream().anyMatch(p->p.aPc()==1 && p.bPc()==2 &&
            p.relation()==HardwareCfgStorePaths.Relationship.NO_CONNECTING_PATH_IN_MODELED_CFG),
            "disconnected branches not claimed to have executed");
        ok(r.relations().stream().anyMatch(p->p.aPc()==1 && p.bPc()==3 &&
            p.relation()==HardwareCfgStorePaths.Relationship.A_MAY_PRECEDE_B),
            "syntactic one-way possible path");
        ok(r.relations().stream().anyMatch(p->p.aPc()==3 && p.bPc()==4 &&
            p.relation()==HardwareCfgStorePaths.Relationship.BOTH_DIRECTIONS_POSSIBLE_IN_CYCLE),
            "cycle is not linear execution order");
        String md=HardwareCfgStorePaths.markdown(r.relations(),0);
        ok(md.contains("NOT an always-before relation") &&
            md.contains("NOT whether both writes") &&
            md.contains("never combined into an active hardware map"),
            "forbidden feasibility/runtime claim");
        var budget=HardwareCfgStorePaths.analyze(0x2bc0,graph,
            List.of(s(1,"SIMCR"),s(4,"TRAMBAR")),false,1);
        ok(budget.truncated() &&
            budget.relations().get(0).relation()==
            HardwareCfgStorePaths.Relationship.SEARCH_LIMIT_UNKNOWN,
            "budget prevents false path-negative conclusion");
        var gap=HardwareCfgStorePaths.analyze(0x2bc0,
            List.of(n(1,2,100),n(2)),List.of(s(1,"SIMCR"),s(2,"CSBAR0")),true,10);
        ok(gap.unknownFlow() && gap.relations().get(0).unknownFunctionControlFlow(),
            "unknown call or CFG gap remains explicit");
        var many=new java.util.ArrayList<HardwareCfgStorePaths.Node>();
        var manyStores=new java.util.ArrayList<HardwareCfgStorePaths.Store>();
        for(int i=0;i<20;i++){
            many.add(n(i));
            manyStores.add(s(i,"CSBAR0"));
        }
        var capped=HardwareCfgStorePaths.analyze(0x2bc0,many,manyStores,false,100);
        ok(capped.truncated() &&
            capped.relations().size()==66,
            "site-count cap is deterministic");
        boolean failed=false;
        try{HardwareCfgStorePaths.analyze(0,graph,
            List.of(s(1,"SIMCR"),s(1,"CSOR0")),false,100);}
        catch(IllegalArgumentException e){failed=true;}
        ok(failed,"duplicated ambiguous store rejected");
        failed=false;
        try{HardwareCfgStorePaths.analyze(0,graph,List.of(s(100,"SIMCR")),false,100);}
        catch(IllegalArgumentException e){failed=true;}
        ok(failed,"missing node rejected");
        System.out.println("HardwareCfgStorePathsSelfTest OK");
    }
}
