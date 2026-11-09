package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** GA-12/18: complete bounded JSR/MOVEC pagination and stale-page refusal. */
public final class HardwareResetIndirectVbrPaginationSelfTest {
    private static int assertions;
    private static void ok(boolean yes,String label){
        assertions++;
        if(!yes)throw new AssertionError(label);
    }
    private static void rejects(Runnable operation,String label) {
        boolean rejected=false;
        try {operation.run();}catch(IllegalArgumentException expected){
            rejected=true;
        }
        ok(rejected,label);
    }
    public static void main(String[] args) {
        List<HardwareResetIndirectVbrCorrelation.Indirect> calls=new ArrayList<>();
        List<HardwareResetIndirectVbrCorrelation.Vbr> movecs=new ArrayList<>();
        for(int i=0;i<64;i++)calls.add(
            new HardwareResetIndirectVbrCorrelation.Indirect(
                0x100L,0x200L+2L*i,0x400L,true,i%2!=0));
        for(int i=0;i<32;i++)movecs.add(
            new HardwareResetIndirectVbrCorrelation.Vbr(
                0x100L,0x600L+2L*i,0x800L,i%3==0));
        // The worst-case 64 x 32 same-function inventory has 2048
        // ordered pairs. Pages are always <=32 entries.
        var visited=Set.of(0x100L);
        var first=HardwareResetIndirectVbrCorrelation.page(
            calls,movecs,visited,true,false,11,13,0,32);
        ok(first.colocatedPairs()==2048 && first.rows().size()==32 &&
            first.indirectSources()==64 && first.vbrSources()==32 &&
            first.omittedIndirect()==11 && first.omittedVbr()==13 &&
            first.pageOffset()==0 && first.pageLimit()==32 &&
            first.nextOffset()==32 && first.hasMore() &&
            first.displayTruncated(),"Exact first-page counts and omitted witnesses");
        ok(first.rows().get(0).indirectPc()==0x200L &&
            first.rows().get(0).vbrPc()==0x600L &&
            first.rows().get(31).vbrPc()==0x63eL,
            "First page preserves caller/JSR/MOVEC deterministic sort");
        ok(first.markdown().contains("page offset: 0") &&
            first.markdown().contains("next offset: 32") &&
            first.markdown().contains("has more pages: true") &&
            first.markdown().contains("INCOMPLETE SOURCE INVENTORY/DISPLAY"),
            "First-page markdown never implies complete evidence");
        List<HardwareResetIndirectVbrCorrelation.Pair> stitched=new ArrayList<>();
        int cursor=0;
        for(int p=0;p<64;p++){
            var page=HardwareResetIndirectVbrCorrelation.page(
                calls,movecs,visited,true,false,11,13,cursor,32);
            ok(page.pageOffset()==cursor && page.nextOffset()==cursor+32 &&
                page.rows().size()==32 && page.hasMore()==(p!=63) &&
                page.colocatedPairs()==2048 && page.omittedIndirect()==11 &&
                page.omittedVbr()==13,
                "Exact source count and cursor on each of 64 pages");
            stitched.addAll(page.rows());
            cursor=page.nextOffset();
        }
        ok(cursor==2048 && stitched.size()==2048 &&
            stitched.get(1024).indirectPc()==0x240L &&
            stitched.get(2047).indirectPc()==0x27eL &&
            stitched.get(2047).vbrPc()==0x63eL,
            "Complete deterministic stitching without duplicate/lost pairs");
        var beyond=HardwareResetIndirectVbrCorrelation.page(
            calls,movecs,visited,true,false,11,13,2048,32);
        ok(beyond.rows().isEmpty() && beyond.nextOffset()==2048 &&
            !beyond.hasMore() && beyond.colocatedPairs()==2048,
            "Exact-end page is empty, not an invented candidate");
        var middle=HardwareResetIndirectVbrCorrelation.page(
            calls,movecs,visited,true,true,2,3,7,9);
        ok(middle.rows().size()==9 &&
            middle.rows().get(0).indirectPc()==stitched.get(7).indirectPc() &&
            middle.rows().get(0).vbrPc()==stitched.get(7).vbrPc() &&
            middle.rows().get(8).vbrPc()==stitched.get(15).vbrPc() &&
            middle.pageOffset()==7 && middle.nextOffset()==16 &&
            middle.rows().stream().allMatch(x->x.resetGraphIncomplete()),
            "Unaligned mid-page is deterministic and preserves RESET uncertainty");
        Collections.reverse(calls);
        Collections.reverse(movecs);
        var shuffled=HardwareResetIndirectVbrCorrelation.page(
            calls,movecs,visited,true,false,11,13,1011,17);
        ok(shuffled.rows().equals(stitched.subList(1011,1028)),
            "Input order cannot change page boundary or duplicates");
        var smaller=HardwareResetIndirectVbrCorrelation.page(
            List.of(calls.get(0)),List.of(movecs.get(0)),
            visited,false,true,4,5,0,1);
        ok(smaller.rows().size()==1 &&
            smaller.rows().get(0).resetRelation()==
            HardwareResetIndirectVbrCorrelation.ResetRelation.RESET_ROOT_UNKNOWN &&
            smaller.rows().get(0).uncertain() &&
            smaller.omittedIndirect()==4 && smaller.omittedVbr()==5,
            "Unknown RESET root and inventory count retained");
        rejects(()->HardwareResetIndirectVbrCorrelation.page(
            calls,movecs,visited,true,false,0,0,-1,32),
            "Negative offset rejected");
        rejects(()->HardwareResetIndirectVbrCorrelation.page(
            calls,movecs,visited,true,false,0,0,0,33),
            "Over-cap page rejected");
        rejects(()->HardwareResetIndirectVbrCorrelation.page(
            calls,movecs,visited,true,false,0,0,2049,32),
            "Offset outside theoretical bounded inventory rejected");
        rejects(()->HardwareResetIndirectVbrCorrelation.page(
            calls,movecs,visited,true,false,-1,0,0,32),
            "Negative omission rejected");
        Object program=new Object();
        var captured=HardwareAnalysisRevision.capture(program,9,
            "68000:BE:32:CPU32","synthetic-source",true);
        var live=new AtomicReference<>(captured);
        var epoch=new AtomicBoolean(true);
        var page=HardwareResetIndirectVbrCorrelation.page(
            calls,movecs,visited,true,false,11,13,32,32);
        String text=HardwareJointSourcePublication.render(captured,
            live::get,epoch::get,page::markdown);
        ok(text.contains("page offset: 32") &&
            text.contains("next offset: 64"),"Exact revision allows page rendering");
        boolean refused=false;
        try {
            HardwareJointSourcePublication.render(captured,
                live::get,epoch::get,()->{
                    live.set(HardwareAnalysisRevision.capture(program,10,
                        "68000:BE:32:CPU32","synthetic-source",true));
                    return page.markdown();
                });
        }catch(HardwareJointSourcePublication.StaleRevision expected){
            refused=true;
        }
        ok(refused,"Changed Ghidra revision during later page rendering refuses output");
        live.set(captured);
        epoch.set(false);
        refused=false;
        try {
            HardwareJointSourcePublication.render(captured,
                live::get,epoch::get,page::markdown);
        }catch(HardwareJointSourcePublication.StaleRevision expected){
            refused=true;
        }
        ok(refused,"Explicit stage invalidate refuses old page cursor");
        System.out.println("HardwareResetIndirectVbrPaginationSelfTest PASS: assertions="+assertions);
    }
}
