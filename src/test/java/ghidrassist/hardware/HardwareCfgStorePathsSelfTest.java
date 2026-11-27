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
        var r=HardwareCfgStorePaths.analyze(0,graph,observations,false,100);
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
        var budget=HardwareCfgStorePaths.analyze(0,graph,
            List.of(s(1,"SIMCR"),s(4,"TRAMBAR")),false,1);
        ok(budget.truncated() &&
            budget.relations().get(0).relation()==
            HardwareCfgStorePaths.Relationship.SEARCH_LIMIT_UNKNOWN,
            "budget prevents false path-negative conclusion");
        var gap=HardwareCfgStorePaths.analyze(0,
            List.of(n(0,1),n(1,2,100),n(2)),
            List.of(s(1,"SIMCR"),s(2,"CSBAR0")),true,10);
        ok(gap.unknownFlow() && gap.relations().get(0).unknownFunctionControlFlow(),
            "unknown call or CFG gap remains explicit");
        var many=new java.util.ArrayList<HardwareCfgStorePaths.Node>();
        var manyStores=new java.util.ArrayList<HardwareCfgStorePaths.Store>();
        for(int i=0;i<20;i++){
            many.add(i<19?n(i,i+1):n(i));
            manyStores.add(s(i,"CSBAR0"));
        }
        var capped=HardwareCfgStorePaths.analyze(0,many,manyStores,false,100);
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
        // Negative ownership witnesses: no foreign/pre-entry source,
        // dangling backward branch or disconnected STORE may be promoted
        // to an intra-function hardware write relation.
        var valid=List.of(n(10,12),n(12,14),n(14));
        var ownedStores=List.of(s(12,"SIMCR"),s(14,"CSBAR0"));
        var owned=HardwareCfgStorePaths.analyze(10,valid,ownedStores,false,100);
        ok(owned.relations().size()==1 && !owned.truncated(),
            "entry-anchored positive CFG evidence");
        var missing=HardwareCfgStorePaths.analyze(8,valid,ownedStores,false,100);
        ok(missing.truncated() && missing.unknownFlow() &&
            missing.relations().isEmpty(),"missing function entry fail closed");
        var foreign=HardwareCfgStorePaths.analyze(10,
            List.of(n(8),n(10,12),n(12,14),n(14)),
            ownedStores,false,100);
        ok(foreign.truncated() && foreign.unknownFlow() &&
            foreign.relations().isEmpty(),"pre-entry CFG node fail closed");
        var backward=HardwareCfgStorePaths.analyze(10,
            List.of(n(10,8,12),n(12,14),n(14)),
            ownedStores,false,100);
        ok(backward.truncated() && backward.unknownFlow() &&
            backward.relations().isEmpty(),"pre-entry successor fail closed");
        var orphan=HardwareCfgStorePaths.analyze(10,
            List.of(n(10,12),n(12),n(14)),
            ownedStores,false,100);
        ok(orphan.truncated() && orphan.unknownFlow() &&
            orphan.relations().isEmpty(),"unreachable STORE fail closed");
        var unsafe=new HardwareCfgStorePaths.Pair(10,12,14,
            "SIMCR\n- ACTIVE VBR|<b>", "CSBAR0" + "X".repeat(100000),
            HardwareCfgStorePaths.Relationship.A_MAY_PRECEDE_B,true);
        String escaped=HardwareCfgStorePaths.markdown(List.of(unsafe),0);
        ok(!escaped.contains("<b>") && !escaped.contains("|<b>") &&
            !escaped.contains("\n- ACTIVE VBR") &&
            escaped.contains("[U+007C]") &&
            escaped.contains("[ABBREVIATED LABEL]") &&
            escaped.length()<1400 && unsafe.bRegister().length()>100000,
            "untrusted labels cannot forge report evidence and raw witness remains");
        // GA-02/03/12: bounded source contracts, not merely bounded output.
        // A single adversarial CALL fanout cannot make every pair search
        // inspect arbitrarily many edges after the visit budget has passed.
        var oversizedEdges=new java.util.ArrayList<Long>(
            java.util.Collections.nCopies(
                HardwareCfgStorePaths.MAX_SOURCE_EDGES+1,12L));
        boolean denied=false;
        try {
            new HardwareCfgStorePaths.Node(10,oversizedEdges);
        }catch(IllegalArgumentException expected){denied=true;}
        ok(denied,"one CFG node cannot contain unbounded successor references");
        var edgeAtLimit=new HardwareCfgStorePaths.Node(
            10,java.util.Collections.nCopies(
                HardwareCfgStorePaths.MAX_SOURCE_EDGES,12L));
        ok(edgeAtLimit.successors().size()==HardwareCfgStorePaths.MAX_SOURCE_EDGES,
            "bounded maximum input adjacency remains supported");
        denied=false;
        try {
            HardwareCfgStorePaths.analyze(10,
                List.of(edgeAtLimit,n(12,14),n(14,12)),
                ownedStores,false,10);
        }catch(IllegalArgumentException expected){denied=true;}
        ok(denied,"total CFG edges reject without partial write-path publication");
        denied=false;
        try {
            HardwareCfgStorePaths.analyze(10,valid,
                java.util.Collections.nCopies(
                    HardwareCfgStorePaths.MAX_SOURCE_STORES+1,
                    s(12,"SIMCR")),false,10);
        }catch(IllegalArgumentException expected){denied=true;}
        ok(denied,"oversized store input fails before list copy or sorting");
        denied=false;
        try {
            HardwareCfgStorePaths.analyze(10,
                java.util.Collections.nCopies(
                    HardwareCfgStorePaths.MAX_SOURCE_NODES+1,n(10)),
                ownedStores,false,10);
        }catch(IllegalArgumentException expected){denied=true;}
        ok(denied,"oversized source nodes fail closed before graph construction");
        for(Runnable malformed:List.<Runnable>of(
                ()->new HardwareCfgStorePaths.Node(0x100000000L,List.of()),
                ()->new HardwareCfgStorePaths.Node(10,
                    java.util.Arrays.asList(12L,null)),
                ()->new HardwareCfgStorePaths.Node(10,
                    List.of(0x100000000L)),
                ()->new HardwareCfgStorePaths.Store(0x100000000L,"SIMCR"),
                ()->HardwareCfgStorePaths.analyze(0x100000000L,valid,
                    ownedStores,false,10))) {
            boolean invalid=false;
            try {malformed.run();}
            catch(IllegalArgumentException expected){invalid=true;}
            ok(invalid,"unsigned 32-bit source identity cannot be forged");
        }
        var safeMissing=HardwareCfgStorePaths.analyzeOrUnknown(10,
            List.of(n(12,14),n(14)),ownedStores,false,10);
        ok(safeMissing.truncated() && safeMissing.unknownFlow() &&
            safeMissing.relations().isEmpty(),
            "missing entry must not publish a path in production report adapter");
        var safeEdges=HardwareCfgStorePaths.analyzeOrUnknown(10,
            List.of(edgeAtLimit,n(12,14),n(14,12)),
            ownedStores,false,10);
        ok(safeEdges.truncated() && safeEdges.unknownFlow() &&
            safeEdges.relations().isEmpty(),
            "oversized total source edges become UNKNOWN without partial report");
        var safeStores=HardwareCfgStorePaths.analyzeOrUnknown(10,valid,
            java.util.Collections.nCopies(
                HardwareCfgStorePaths.MAX_SOURCE_STORES+1,s(12,"SIMCR")),
            false,10);
        ok(safeStores.truncated() && safeStores.unknownFlow() &&
            safeStores.relations().isEmpty(),
            "oversized STORE inventory becomes UNKNOWN, not a global failure");
        var safeValid=HardwareCfgStorePaths.analyzeOrUnknown(
            10,valid,ownedStores,false,100);
        ok(safeValid.equals(owned) &&
            safeValid.relations().size()==1,
            "valid complete source preserves exact same CFG path witness");
        // A valid high CPU32 address remains legal in the generic source
        // model. No unsupported 24-bit physical bus alias is invented.
        var high=HardwareCfgStorePaths.analyze(0xfffffff0L,
            List.of(n(0xfffffff0L,0xfffffff2L),
                    n(0xfffffff2L,0xfffffff4L),n(0xfffffff4L)),
            List.of(s(0xfffffff2L,"SIMCR"),s(0xfffffff4L,"CSBAR0")),
            true,10);
        ok(high.relations().size()==1 && high.unknownFlow() &&
            high.relations().get(0).relation()==
                HardwareCfgStorePaths.Relationship.A_MAY_PRECEDE_B,
            "bounded source graph preserves generic CPU32 high addresses");
        System.out.println("HardwareCfgStorePathsSelfTest OK");
    }
}
