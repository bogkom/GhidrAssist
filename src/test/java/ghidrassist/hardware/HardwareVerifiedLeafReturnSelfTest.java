package ghidrassist.hardware;

import java.util.List;
import java.util.Map;
import java.util.Set;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

public final class HardwareVerifiedLeafReturnSelfTest {
    private HardwareVerifiedLeafReturnSelfTest(){}
    private static void ok(boolean yes,String why){if(!yes)throw new AssertionError(why);}
    private static HardwareDataflow.Step set(long pc,String op,String reg,
            long value,Long next){
        return new HardwareDataflow.Step(pc,SET_POINTER,reg,value,0,null,0,
            List.of(next),op);
    }
    private static HardwareDataflow.Step end(long pc,String op){
        return new HardwareDataflow.Step(pc,OTHER,null,0,0,null,0,List.of(),op);
    }
    public static void main(String[] ignored){
        var leaf=List.of(set(0x130,"MOVEA.L","A0",0xfffa00L,0x136L),
            set(0x136,"MOVE.L","D0",0x40ca,0x13cL),end(0x13c,"RTS"));
        var output=HardwareVerifiedLeafReturn.summarize(0x130,14,leaf);
        ok(output.equals(Map.of("A0",0xfffa00L,"D0",0x40caL)),
            "exact straight-line leaf produces two register constants");
        var caller=List.of(
            new HardwareDataflow.Step(0x100,SET_POINTER,"A0",0x123L,
                0,null,0,List.of(0x106L),"MOVEA.L"),
            new HardwareDataflow.Step(0x106,CALL_BARRIER,null,
                0,0,null,0,List.of(0x10aL),"JSR")
                .withVerifiedCallReturns(output),
            new HardwareDataflow.Step(0x10a,STORE_INDIRECT,"A0","D0",
                0,0,null,16,List.of(),"MOVE.W D0,(A0)")
        );
        var analysed=HardwareDataflow.analyze(0x100,caller,Set.of(0xfffa00L),100);
        ok(analysed.snapshots.size()==1 &&
            analysed.snapshots.get(0).effectiveAddress==0xfffa00L &&
            analysed.snapshots.get(0).writtenWord==0x40ca &&
            analysed.snapshots.get(0).priorUnknownCall,
            "verified leaf returns unlock source only while CALL hazard remains");
        var abiClobber=HardwareDataflow.analyze(0x100,List.of(
            caller.get(0),
            caller.get(1).withSideEffects(Set.of("D0","A7")),
            caller.get(2)),Set.of(0xfffa00L),100);
        ok(abiClobber.snapshots.get(0).effectiveAddress==0xfffa00L &&
            abiClobber.snapshots.get(0).writtenWord==0x40ca,
            "proven post-call return registers survive generic ABI clobber");
        var unproved=HardwareDataflow.analyze(0x100,List.of(
            caller.get(0),new HardwareDataflow.Step(0x106,CALL_BARRIER,
                null,0,0,null,0,List.of(0x10aL),"JSR"),caller.get(2)),
            Set.of(0xfffa00L),100);
        ok(unproved.snapshots.get(0).effectiveAddress==null &&
            unproved.snapshots.get(0).writtenWord==null,
            "ordinary or unresolved CALL always invalidates incoming registers");
        var extra=List.of(leaf.get(0),
            new HardwareDataflow.Step(0x136,CALL_BARRIER,null,
                0,0,null,0,List.of(0x13cL),"JSR"),leaf.get(2));
        ok(HardwareVerifiedLeafReturn.summarize(0x130,14,extra).isEmpty(),
            "nested call cannot certify leaf returns");
        var branched=List.of(
            new HardwareDataflow.Step(0x130,SET_POINTER,"A0",0xfffa00,
                0,null,0,List.of(0x136L,0x13cL),"MOVEA.L"),
            leaf.get(1),leaf.get(2));
        ok(HardwareVerifiedLeafReturn.summarize(0x130,14,branched).isEmpty(),
            "branch rejects summary even when one path sets a constant");
        ok(HardwareVerifiedLeafReturn.summarize(0x130,14,
            List.of(leaf.get(0),leaf.get(1),end(0x13c,"RTE"))).isEmpty(),
            "RTE is not a subroutine return");
        ok(HardwareVerifiedLeafReturn.summarize(0x130,14,
            List.of(leaf.get(0),leaf.get(1).withSideEffects(Set.of("A1")),
                leaf.get(2))).isEmpty(),
            "implicit clobber excludes leaf summary");
        ok(HardwareVerifiedLeafReturn.summarize(0x130,16,leaf).isEmpty(),
            "additional undecoded bytes exclude leaf summary");
        ok(HardwareVerifiedLeafReturn.summarize(0x130,14,
            List.of(set(0x130,"MOVE.W","D0",0x40ca,0x136L),
                leaf.get(1),leaf.get(2))).isEmpty(),
            "partial-width Dn write is not a full known pointer constant");
        ok(HardwareVerifiedLeafReturn.summarize(0x130,14,
            List.of(leaf.get(0),leaf.get(1),
                end(0x13c,"RTS").withSideEffects(Set.of("A7"))))
            .equals(output),
            "expected stack pop in real RTS does not invalidate unrelated A/D outputs");
        boolean rejected=false;
        try{caller.get(0).withVerifiedCallReturns(output);}
        catch(IllegalArgumentException expected){rejected=true;}
        ok(rejected,"summary cannot be attached to non-CALL instruction");
        System.out.println("HardwareVerifiedLeafReturnSelfTest OK");
    }
}
