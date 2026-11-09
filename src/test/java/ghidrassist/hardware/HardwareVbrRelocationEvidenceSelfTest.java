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
        // Numerical table-base ordering used to exclude a RESET-linked
        // MOVEC source under the fixed three-table scan budget.
        var rankedSites=List.of(
            new HardwareVbrRelocationEvidence.Site(0x300,0x306,0x400L,false,false),
            new HardwareVbrRelocationEvidence.Site(0x180,0x184,0x600L,true,false),
            new HardwareVbrRelocationEvidence.Site(0x100,0x106,0x800L,false,false),
            new HardwareVbrRelocationEvidence.Site(0x380,0x386,0xA00L,true,true),
            new HardwareVbrRelocationEvidence.Site(0x160,0x166,0xE00L,false,false),
            new HardwareVbrRelocationEvidence.Site(0x3C0,0x3C6,0xE00L,true,true));
        var prioritized=HardwareVbrRelocationEvidence.plan(
            rankedSites,true,false,Set.of(0x100L,0x160L,0x180L),3,12);
        ok(prioritized.eligibleTableBases()==5 &&
                prioritized.tableScanTruncated() &&
                prioritized.tableBases().equals(List.of(0x800L,0xE00L,0x600L)),
            "RESET-linked complete MOVEC sources scanned before lower unrelated bases");
        ok(prioritized.markdown().contains("SOURCE-ONLY budget heuristic") &&
                prioritized.markdown().contains("NOT active-VBR probability"),
            "Static priority never asserts runtime table selection");
        var prioritizationWithoutReset=HardwareVbrRelocationEvidence.plan(
            rankedSites,false,true,Set.of(0x100L,0x160L,0x180L),2,12);
        ok(prioritizationWithoutReset.tableBases().equals(
                List.of(0x400L,0x800L)) &&
                prioritizationWithoutReset.rows().stream().allMatch(row->
                    row.resetRelation()==
                        HardwareVbrRelocationEvidence.Relation.RESET_ROOT_UNKNOWN),
            "Unknown RESET root may not privilege claimed reachable sites");
        var limitedProvenance=HardwareVbrRelocationEvidence.plan(
            rankedSites,true,true,Set.of(0x100L,0x160L,0x180L),1,1);
        ok(limitedProvenance.tableBases().equals(List.of(0x800L)) &&
                limitedProvenance.siteDisplayTruncated() &&
                limitedProvenance.tableScanTruncated() &&
                limitedProvenance.eligibleTableBases()==5,
            "Row and table caps keep total omitted source evidence explicit");
        var duplicates=new ArrayList<>(sites);
        duplicates.add(sites.get(0));
        reject(()->HardwareVbrRelocationEvidence.plan(
            duplicates,true,false,Set.of(),3,32),
            "duplicate MOVEC PC is invalid");
        reject(()->new HardwareVbrRelocationEvidence.Site(
            0x130,-1,0x800L,false,false),"bad source PC");
        reject(()->new HardwareVbrRelocationEvidence.Site(
            0x130,0x136,0x1000000L,false,false),"outside MC68332 physical address");
        reject(()->new HardwareVbrRelocationEvidence.Site(
            0x140,0x13e,0x800L,false,false),
            "MOVEC PC cannot precede its declared owning function entry");
        reject(()->new HardwareVbrRelocationEvidence.Site(
            0x131,0x136,0x800L,false,false),
            "Odd CPU32 function entry cannot own a MOVEC site");
        reject(()->new HardwareVbrRelocationEvidence.Site(
            0x130,0x137,0x800L,false,false),
            "Odd CPU32 MOVEC instruction site is not a decoded instruction");
        reject(()->new HardwareVbrRelocationEvidence.Site(
            0x1000000L,0x1000000L,0x800L,false,false),
            "MOVEC function and instruction must fit selected MC68332 range");
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
