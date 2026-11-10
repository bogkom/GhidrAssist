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
        // CPU32 MOVEQ is exactly two bytes and sign-extends its eight-bit
        // immediate across all 32 bits of Dn. These are actual post-RTS
        // constants, not a guessed positive 0x80 or A-register assignment.
        var moveqOnly=List.of(set(0x300,"MOVEQ","D0",0x7f,0x302L),
            end(0x302,"RTS"));
        ok(HardwareVerifiedLeafReturn.summarize(0x300,4,moveqOnly)
                .equals(Map.of("D0",0x7fL)),
            "Exact two-byte MOVEQ #127,D0 and RTS can certify a constant");
        var signed=List.of(
            set(0x300,"MOVEA.L","A0",0xfffa00L,0x306L),
            set(0x306,"MOVEQ","D0",0xffff80L,0x308L),
            end(0x308,"RTS"));
        var signedReturns=HardwareVerifiedLeafReturn.summarize(
            0x300,10,signed);
        ok(signedReturns.equals(Map.of("A0",0xfffa00L,
                "D0",0xffff80L)),
            "MOVEQ #-128,D0 sign-extends into a full source register");
        var signedCall=List.of(
            new HardwareDataflow.Step(0x400,CALL_BARRIER,null,0,0,null,0,
                List.of(0x406L),"JSR")
                .withVerifiedCallReturns(signedReturns),
            new HardwareDataflow.Step(0x406,STORE_INDIRECT,"A0","D0",
                0,0,null,16,List.of(),"MOVE.W D0,(A0)"));
        var signFlow=HardwareDataflow.analyze(
            0x400,signedCall,Set.of(0xfffa00L),120);
        ok(signFlow.snapshots.size()==1 &&
                signFlow.snapshots.get(0).effectiveAddress==0xfffa00L &&
                Integer.valueOf(0xff80).equals(
                    signFlow.snapshots.get(0).writtenWord) &&
                signFlow.snapshots.get(0).priorUnknownCall,
            "Signed MOVEQ return propagates candidate word across CALL, not execution");
        ok(HardwareVerifiedLeafReturn.summarize(0x300,10,List.of(
            signed.get(0),
            set(0x306,"MOVEQ","D0",0x80,0x308L),
            signed.get(2))).isEmpty(),
            "Unextended 0x80 must not be treated as a full positive D0 source");
        ok(HardwareVerifiedLeafReturn.summarize(0x300,10,List.of(
            signed.get(0),
            set(0x306,"MOVEQ","D0",0x100,0x308L),
            signed.get(2))).isEmpty(),
            "MOVEQ with an unrepresentable 9-bit positive literal rejected");
        ok(HardwareVerifiedLeafReturn.summarize(0x300,10,List.of(
            signed.get(0),
            set(0x306,"MOVEQ","A1",0xffff80L,0x308L),
            signed.get(2))).isEmpty(),
            "MOVEQ cannot assign an address register");
        ok(HardwareVerifiedLeafReturn.summarize(0x300,12,signed).isEmpty(),
            "Unexpected extra two bytes break exact short MOVEQ body coverage");
        ok(HardwareVerifiedLeafReturn.summarize(0x300,10,List.of(
            signed.get(0),
            set(0x306,"MOVEQ","D0",0xffff80L,0x30aL),
            signed.get(2))).isEmpty(),
            "MOVEQ must have exact two-byte linear fallthrough");
        ok(HardwareVerifiedLeafReturn.summarize(0x300,10,List.of(
            signed.get(0),
            signed.get(1).withSideEffects(Set.of("D1")),
            signed.get(2))).isEmpty(),
            "Unexpected P-code output clobber disables signed MOVEQ summary");
        ok(HardwareVerifiedLeafReturn.summarize(0x300,10,List.of(
            signed.get(0),signed.get(1),end(0x308,"RTE"))).isEmpty(),
            "RTE cannot inherit input-independent MOVEQ/RTS summary");
        ok(HardwareVerifiedLeafReturn.summarize(0x300,10,List.of(
            signed.get(0),signed.get(1),end(0x308,"RTS")
                .withSideEffects(Set.of("A7")))).equals(signedReturns),
            "Real RTS stack pop remains allowed after full signed D0 proof");
        System.out.println("HardwareVerifiedLeafReturnSelfTest OK");
    }
}
