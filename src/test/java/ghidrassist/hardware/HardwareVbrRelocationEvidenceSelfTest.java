package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** GA-11 static-only VBR relocation candidates, no Ghidra installation. */
public final class HardwareVbrRelocationEvidenceSelfTest {
    private HardwareVbrRelocationEvidenceSelfTest() {}
    private static int assertions;
    private static void ok(boolean cond,String message){
        assertions++;
        if(!cond)throw new AssertionError(message);
    }
    private static void reject(Runnable action,String message){
        boolean caught=false;
        try{action.run();}
        catch(IllegalArgumentException expected){caught=true;}
        ok(caught,message);
    }
    public static void main(String[] args){
        var sites=List.of(
            new HardwareVbrRelocationEvidence.Site(0x130,0x136,0x800L,false,false),
            new HardwareVbrRelocationEvidence.Site(0x220,0x228,0xC00L,true,true),
            new HardwareVbrRelocationEvidence.Site(0x300,0x306,null,false,true),
            new HardwareVbrRelocationEvidence.Site(0x350,0x356,0x801L,false,false),
            new HardwareVbrRelocationEvidence.Site(0x3A0,0x3A6,0xFFFFFCL,true,false));
        var plan=HardwareVbrRelocationEvidence.plan(
            sites,true,true,Set.of(0x100L,0x130L),3,32);
        ok(plan.observedSourceSites()==5 && plan.unknownSourceValues()==1 &&
            plan.invalidSourceValues()==2,
            "unknown, odd/misaligned and 24-bit limit must not be scanned");
        ok(plan.eligibleTableBases()==2 &&
            plan.tableBases().equals(List.of(0x800L,0xC00L)),
            "only two unique valid in-range source bases");
        ok(plan.rows().get(0).resetRelation()==
            HardwareVbrRelocationEvidence.Relation.IN_OBSERVED_RESET_CALL_SUBSET,
            "observed RESET CALL subset is a static relation, not execution");
        ok(plan.rows().get(1).resetRelation()==
            HardwareVbrRelocationEvidence.Relation.OUTSIDE_OBSERVED_RESET_CALL_SUBSET &&
            plan.rows().get(1).incompleteCfg() &&
            plan.rows().get(1).priorUnknownCall(),
            "outside subset with uncertain CFG and unknown prior CALL persists");
        ok(plan.rows().get(2).tableState()==
            HardwareVbrRelocationEvidence.TableState.UNKNOWN_SOURCE_REGISTER,
            "no guessed table for unknown MOVEC source");
        ok(plan.rows().get(3).tableState()==
            HardwareVbrRelocationEvidence.TableState.UNALIGNED_SOURCE,
            "4-byte vector word alignment gate");
        ok(plan.rows().get(4).tableState()==
            HardwareVbrRelocationEvidence.TableState.CROSSES_24BIT_LIMIT,
            "vector table crossing 24-bit CPU32 memory cannot be promoted");
        var md=plan.markdown();
        ok(md.contains("runtime VBR UNKNOWN") &&
            md.contains("STATIC SOURCE CANDIDATES ONLY") &&
            md.contains("prior") == false &&
            !md.contains("active ISR verified") &&
            md.contains("RESET callgraph incomplete"),
            "must never claim selected VBR or executed ISR");
        var trunc=HardwareVbrRelocationEvidence.plan(
            sites,true,false,Set.of(),1,1);
        ok(trunc.tableScanTruncated() && trunc.siteDisplayTruncated() &&
            trunc.tableBases().equals(List.of(0x800L)) &&
            trunc.rows().size()==1 &&
            trunc.markdown().contains("INCOMPLETE"),
            "table/row caps must be advertised");
        var unknownRoot=HardwareVbrRelocationEvidence.plan(
            sites,false,false,Set.of(0x130L),3,32);
        ok(unknownRoot.rows().stream().allMatch(r->
            r.resetRelation()==
              HardwareVbrRelocationEvidence.Relation.RESET_ROOT_UNKNOWN),
            "unknown RESET root never implies runtime VBR reachability");
        var duplicates=new ArrayList<>(sites);
        duplicates.add(sites.get(0));
        reject(()->HardwareVbrRelocationEvidence.plan(
            duplicates,true,false,Set.of(),3,32),
            "duplicate MOVEC PC is invalid");
        reject(()->new HardwareVbrRelocationEvidence.Site(
            0x130,-1,0x800L,false,false),"bad source PC");
        reject(()->new HardwareVbrRelocationEvidence.Site(
            0x130,0x136,0x1000000L,false,false),"outside MC68332 physical address");
        reject(()->HardwareVbrRelocationEvidence.plan(
            sites,true,false,Set.of(),0,32),"zero table budget");
        reject(()->HardwareVbrRelocationEvidence.plan(
            sites,true,false,Set.of(),3,33),"unbounded display");
        var tooMany=new ArrayList<HardwareVbrRelocationEvidence.Site>();
        for(int i=0;i<257;i++)
            tooMany.add(new HardwareVbrRelocationEvidence.Site(
                0x100L,0x200L+i*2L,0x800L,false,false));
        reject(()->HardwareVbrRelocationEvidence.plan(
            tooMany,true,false,Set.of(),3,32),"source input cap");
        boolean immutable=false;
        try{plan.tableBases().clear();}
        catch(UnsupportedOperationException expected){immutable=true;}
        ok(immutable,"source table bases immutable");
        System.out.println("HardwareVbrRelocationEvidenceSelfTest PASS: assertions="+assertions);
    }
}
