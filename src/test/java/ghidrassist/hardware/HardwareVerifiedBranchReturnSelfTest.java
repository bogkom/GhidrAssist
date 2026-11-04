package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

public final class HardwareVerifiedBranchReturnSelfTest {
    private HardwareVerifiedBranchReturnSelfTest(){}
    private static void ok(boolean value,String msg){
        if(!value)throw new AssertionError(msg);
    }
    private static HardwareDataflow.Step step(long pc,HardwareDataflow.Kind k,
            String mnemonic,String reg,long value,Long... successors){
        return new HardwareDataflow.Step(pc,k,reg,value,0,null,0,
            List.of(successors),mnemonic);
    }
    private static List<HardwareDataflow.Step> fixture(long alternateA0){
        return List.of(
            step(0x100,SET_POINTER,"MOVE.L","D0",0x40caL,0x106L),
            step(0x106,OTHER,"BNE",null,0,0x108L,0x110L),
            step(0x108,SET_POINTER,"MOVEA.L","A0",0xfffa00L,0x10eL),
            step(0x10e,OTHER,"BRA",null,0,0x116L),
            step(0x110,SET_POINTER,"MOVEA.L","A0",alternateA0,0x116L),
            step(0x116,OTHER,"RTS",null,0));
    }
    private static Map<Long,Integer> sizes(){
        return Map.of(0x100L,6,0x106L,2,0x108L,6,0x10eL,2,
            0x110L,6,0x116L,2);
    }
    public static void main(String[] args){
        var agreed=HardwareVerifiedBranchReturn.summarize(
            0x100,24,fixture(0xfffa00L),sizes());
        ok(agreed.equals(Map.of("D0",0x40caL,"A0",0xfffa00L)),
            "two genuinely divergent paths agree on unconditional register result");
        var divergent=HardwareVerifiedBranchReturn.summarize(
            0x100,24,fixture(0x7ffa00L),sizes());
        ok(divergent.equals(Map.of("D0",0x40caL)),
            "disagreeing path removes only ambiguous A0, not stable D0");
        var caller=List.of(
            step(0x200,CALL_BARRIER,"JSR",null,0,0x206L)
                .withVerifiedCallReturns(agreed),
            new HardwareDataflow.Step(0x206,STORE_INDIRECT,"A0","D0",0,0,
                null,16,List.of(),"MOVE.W D0,(A0)"));
        var analysis=HardwareDataflow.analyze(0x200,caller,
            Set.of(0xfffa00L),80);
        ok(analysis.snapshots.size()==1 &&
            analysis.snapshots.get(0).effectiveAddress==0xfffa00L &&
            Integer.valueOf(0x40ca).equals(analysis.snapshots.get(0).writtenWord) &&
            analysis.snapshots.get(0).priorUnknownCall,
            "branching leaf yields static SIMCR candidate, not runtime proof");
        var uncertain=HardwareDataflow.analyze(0x200,List.of(
            caller.get(0).withVerifiedCallReturns(divergent),caller.get(1)),
            Set.of(0xfffa00L),80);
        ok(uncertain.snapshots.get(0).effectiveAddress==null &&
            uncertain.snapshots.get(0).writtenWord!=null,
            "disagreeing branch must not invent peripheral destination");
        var back=new ArrayList<>(fixture(0xfffa00L));
        back.set(3,step(0x10e,OTHER,"BRA",null,0,0x106L));
        ok(HardwareVerifiedBranchReturn.summarize(0x100,24,back,sizes()).isEmpty(),
            "loop or possibly nonterminating function cannot be certified");
        var external=new ArrayList<>(fixture(0xfffa00L));
        external.set(1,step(0x106,OTHER,"BNE",null,0,0x108L,0x900L));
        ok(HardwareVerifiedBranchReturn.summarize(0x100,24,external,sizes()).isEmpty(),
            "branch target outside function body cannot certify return");
        var unknown=new ArrayList<>(fixture(0xfffa00L));
        unknown.set(3,step(0x10e,STORE_DIRECT,"MOVE.W",null,0xfffa00L,0x116L));
        ok(HardwareVerifiedBranchReturn.summarize(0x100,24,unknown,sizes()).isEmpty(),
            "memory-writing path invalidates input-independent leaf summary");
        var unmodeled=new ArrayList<>(fixture(0xfffa00L));
        unmodeled.set(1,step(0x106,CALL_BARRIER,"BSR",null,0,0x108L,0x110L));
        ok(HardwareVerifiedBranchReturn.summarize(0x100,24,unmodeled,sizes()).isEmpty(),
            "nested CALL cannot be treated as a conditional branch");
        var partial=new ArrayList<>(fixture(0xfffa00L));
        partial.set(4,step(0x110,SET_POINTER,"MOVEA.W","A0",0xfffa00L,0x116L));
        ok(HardwareVerifiedBranchReturn.summarize(0x100,24,partial,sizes()).isEmpty(),
            "word-width register assignment is not a full known A register");
        var implicit=new ArrayList<>(fixture(0xfffa00L));
        implicit.set(4,implicit.get(4).withSideEffects(Set.of("A1")));
        ok(HardwareVerifiedBranchReturn.summarize(0x100,24,implicit,sizes()).isEmpty(),
            "implicit A/D mutation invalidates strict branch summary");
        var faulty=new LinkedHashMap<>(sizes());
        faulty.put(0x106L,4);
        ok(HardwareVerifiedBranchReturn.summarize(
            0x100,24,fixture(0xfffa00L),faulty).isEmpty(),
            "false byte coverage of Ghidra Listing fails closed");
        var hidden=new ArrayList<>(fixture(0xfffa00L));
        hidden.set(3,step(0x10e,OTHER,"NOP",null,0,0x116L));
        ok(HardwareVerifiedBranchReturn.summarize(0x100,24,hidden,sizes()).isEmpty(),
            "non-fallthrough disguised NOP must not certify ignored instructions");
        var rts=new ArrayList<>(fixture(0xfffa00L));
        rts.set(5,step(0x116,OTHER,"RTE",null,0));
        ok(HardwareVerifiedBranchReturn.summarize(0x100,24,rts,sizes()).isEmpty(),
            "RTE is not an ordinary CALL return");
        ok(HardwareVerifiedBranchReturn.summarize(
            0x100,24,List.of(),Map.of()).isEmpty(),
            "empty or missing Listing never proves callee output");
        System.out.println("HardwareVerifiedBranchReturnSelfTest OK");
    }
}
