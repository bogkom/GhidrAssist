package ghidrassist.hardware;

import java.util.List;
import java.util.Set;

/** GA-01/02/03/11 source-only RESET/JSR/MOVEC co-location safety. */
public final class HardwareResetIndirectVbrCorrelationSelfTest {
    private static int checks;
    private static void check(boolean condition,String reason) {
        checks++;
        if(!condition)throw new AssertionError(reason);
    }
    private static void reject(Runnable action,String reason) {
        boolean refused=false;
        try{action.run();}catch(IllegalArgumentException expected){refused=true;}
        check(refused,reason);
    }
    private static HardwareResetIndirectVbrCorrelation.Result join(
            List<HardwareResetIndirectVbrCorrelation.Indirect> jsr,
            List<HardwareResetIndirectVbrCorrelation.Vbr> vbr,
            boolean resetKnown,boolean resetIncomplete,
            int omittedJsr,int omittedVbr,int cap) {
        return HardwareResetIndirectVbrCorrelation.inspect(
            jsr,vbr,Set.of(0x100L,0x130L),resetKnown,
            resetIncomplete,omittedJsr,omittedVbr,cap);
    }
    public static void main(String[] args) {
        var j1=new HardwareResetIndirectVbrCorrelation.Indirect(
            0x130L,0x138L,0x500L,true,false);
        var j2=new HardwareResetIndirectVbrCorrelation.Indirect(
            0x130L,0x144L,0x520L,false,true);
        var j3=new HardwareResetIndirectVbrCorrelation.Indirect(
            0x300L,0x30cL,0x600L,true,true);
        var v1=new HardwareResetIndirectVbrCorrelation.Vbr(
            0x130L,0x152L,0x800L,false);
        var v2=new HardwareResetIndirectVbrCorrelation.Vbr(
            0x130L,0x160L,null,true);
        var v3=new HardwareResetIndirectVbrCorrelation.Vbr(
            0x300L,0x320L,0xc00L,false);
        var v4=new HardwareResetIndirectVbrCorrelation.Vbr(
            0x380L,0x386L,0xe00L,false);
        var r=join(List.of(j3,j2,j1),List.of(v4,v3,v2,v1),
            true,false,0,0,12);
        check(r.indirectSources()==3 && r.vbrSources()==4 &&
            r.colocatedPairs()==5 && r.rows().size()==5 &&
            !r.displayTruncated(),
            "Only five same-function pairs, no foreign MOVEC/JSR borrowing");
        check(r.rows().get(0).function()==0x130L &&
            r.rows().get(0).indirectPc()==0x138L &&
            r.rows().get(0).vbrPc()==0x152L &&
            r.rows().get(0).mayMm() &&
            !r.rows().get(0).uncertain() &&
            r.rows().get(0).resetRelation()==
                HardwareResetIndirectVbrCorrelation.ResetRelation
                    .IN_OBSERVED_RESET_CALL_SUBSET,
            "Source-proven MAY MM and VBR co-location in RESET subset");
        check(!r.rows().get(2).mayMm() &&
            r.rows().get(2).uncertain() &&
            r.rows().get(2).indirectPc()==0x144L,
            "Unknown indirect target subtree cannot become known MM WRITE");
        check(r.rows().get(4).function()==0x300L &&
            r.rows().get(4).resetRelation()==
                HardwareResetIndirectVbrCorrelation.ResetRelation
                    .OUTSIDE_OBSERVED_RESET_CALL_SUBSET &&
            r.rows().get(4).mayMm() && r.rows().get(4).uncertain(),
            "Outside observed RESET subset is not proof of nonexecution");
        String markdown=r.markdown();
        check(markdown.contains("STATIC SAME-FUNCTION SOURCE CO-LOCATION ONLY") &&
            markdown.contains("IN_OBSERVED_RESET_CALL_SUBSET") &&
            markdown.contains("OUTSIDE_OBSERVED_RESET_CALL_SUBSET") &&
            markdown.contains("UNKNOWN") &&
            markdown.contains("0x00000138") &&
            markdown.contains("0x00000152") &&
            markdown.contains("selected VBR") &&
            markdown.contains("ISR") &&
            !markdown.contains("hardware MM activated"),
            "Rendered sources explicitly distinguish MAY evidence from hardware runtime");
        var unknown=join(List.of(j1),List.of(v1),false,true,0,0,12);
        check(unknown.rows().size()==1 &&
            unknown.rows().get(0).resetRelation()==
                HardwareResetIndirectVbrCorrelation.ResetRelation
                    .RESET_ROOT_UNKNOWN &&
            unknown.rows().get(0).resetGraphIncomplete() &&
            unknown.markdown().contains("RESET root recognized: false"),
            "Unknown RESET root cannot inherit set membership");
        var incomplete=join(List.of(j1),List.of(v1),true,true,0,0,12);
        check(incomplete.rows().get(0).resetGraphIncomplete() &&
            incomplete.rows().get(0).resetRelation()==
                HardwareResetIndirectVbrCorrelation.ResetRelation
                    .IN_OBSERVED_RESET_CALL_SUBSET,
            "Partial RESET graph retains observed membership, not runtime certainty");
        var omitted=join(List.of(j1,j2),List.of(v1,v2),true,false,7,8,2);
        check(omitted.colocatedPairs()==4 &&
            omitted.displayTruncated() && omitted.omittedIndirect()==7 &&
            omitted.omittedVbr()==8 && omitted.rows().size()==2 &&
            omitted.markdown().contains("INCOMPLETE SOURCE INVENTORY/DISPLAY"),
            "Source and pair output caps preserve omitted/unknown evidence counts");
        check(join(List.of(j1),List.of(v3),true,false,0,0,10).rows().isEmpty(),
            "No source co-location must not create an indirect CALL edge");
        check(join(List.of(j1),List.of(v3),true,false,0,0,10)
            .markdown().contains("NOT proof of absent indirect MMIO or VBR"),
            "No match never becomes a negative hardware conclusion");
        check(r.equals(join(List.of(j1,j2,j3),List.of(v1,v2,v3,v4),
            true,false,0,0,12)), "Deterministic pair order independent of input ordering");
        reject(()->join(List.of(j1,j1),List.of(v1),true,false,0,0,10),
            "Same indirect instruction PC cannot be double counted");
        reject(()->join(List.of(j1),List.of(v1,v1),true,false,0,0,10),
            "Same MOVEC instruction PC cannot be double counted");
        reject(()->new HardwareResetIndirectVbrCorrelation.Indirect(
            0x130L,0x12eL,0x500L,true,false),
            "Indirect source PC before declared function entry rejected");
        reject(()->new HardwareResetIndirectVbrCorrelation.Vbr(
            0x130L,0x131L,0x800L,false),
            "Unaligned MOVEC source PC rejected");
        reject(()->new HardwareResetIndirectVbrCorrelation.Vbr(
            0x130L,0x136L,0x1000000L,false),
            "Out-of-range MC68332 VBR source rejected");
        reject(()->HardwareResetIndirectVbrCorrelation.inspect(
            List.of(j1),List.of(v1),Set.of(-1L),true,false,0,0,10),
            "Invalid RESET source entry rejected");
        reject(()->join(List.of(j1),List.of(v1),true,false,0,0,33),
            "Display cap greater than maximum rejected");
        reject(()->join(List.of(j1),List.of(v1),true,false,-1,0,10),
            "Negative omitted witness count rejected");
        boolean immutable=false;
        try{r.rows().clear();}catch(UnsupportedOperationException expected){
            immutable=true;
        }
        check(immutable,"Returned candidate rows immutable");
        System.out.println("HardwareResetIndirectVbrCorrelationSelfTest PASS: assertions="+checks);
    }
}
