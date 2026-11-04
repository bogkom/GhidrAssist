package ghidrassist.hardware;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static ghidrassist.hardware.HardwareDataflow.Kind.*;

/**
 * GA-02/03: deterministic 2-hop source-only CALL A/D propagation and
 * fail-closed negative controls, independent of Ghidra and AI models.
 */
public final class HardwareTwoHopRegisterFlowSelfTest {
    private HardwareTwoHopRegisterFlowSelfTest(){}
    private static int checks;
    private static void ok(boolean yes,String reason){
        checks++;
        if(!yes)throw new AssertionError(reason);
    }
    private static void reject(Runnable operation,String reason){
        boolean denied=false;
        try{operation.run();}
        catch(IllegalArgumentException expected){denied=true;}
        ok(denied,reason);
    }
    private static HardwareDataflow.Step step(long pc,
            HardwareDataflow.Kind k,String reg,String source,long value,
            String mnemonic,Long... succ){
        return new HardwareDataflow.Step(pc,k,reg,source,value,0,null,0,
            List.of(succ),mnemonic);
    }
    private static HardwareDataflow.Step ret(long pc){
        return step(pc,OTHER,null,null,0,"RTS");
    }
    private static HardwareDataflow.Step jsr(long pc,long next){
        return step(pc,CALL_BARRIER,null,null,0,"JSR",next);
    }
    private static HardwareCallsiteRegisterFlow.Call outer(long entry,
            long bridge,long mmio,long word){
        var caller=List.of(
            step(entry,SET_POINTER,"A0",null,mmio,"MOVEA.L",entry+6),
            step(entry+6,SET_POINTER,"D0",null,word,"MOVE.L",entry+12),
            jsr(entry+12,entry+18),ret(entry+18));
        var input=HardwareDataflow.analyze(entry,caller,
            Set.of(0xfffa00L,0xfffa68L),500);
        ok(!input.truncated,"complete synthetic outer CFG");
        ok(input.knownPointersAtEntry.get(entry+12).size()==2,
            "two known A/D arguments at exact outer CALL");
        ok(!input.knownPointersAtEntry.containsKey(entry+18),
            "no stale A/D after unsummarized CALL");
        return new HardwareCallsiteRegisterFlow.Call(
            entry,entry+12,bridge,
            input.knownPointersAtEntry.get(entry+12),false);
    }
    private static HardwareTwoHopRegisterFlow.Bridge bridge(long entry){
        return new HardwareTwoHopRegisterFlow.Bridge(entry,List.of(
            step(entry,COPY_POINTER,"A1","A0",0,"MOVEA.L",entry+2),
            jsr(entry+2,entry+8),ret(entry+8)),
            entry+2,0x700L,true);
    }
    private static HardwareCallsiteRegisterFlow.Callee leaf(long pc,
            String target){
        return new HardwareCallsiteRegisterFlow.Callee(pc,List.of(
            step(pc,STORE_INDIRECT,target,"D0",0,"MOVE.W",pc+2),
            ret(pc+2)),true);
    }
    private static HardwareTwoHopRegisterFlow.Summary scan(
            List<HardwareCallsiteRegisterFlow.Call> calls,
            List<HardwareTwoHopRegisterFlow.Bridge> mids,
            List<HardwareCallsiteRegisterFlow.Callee> leaves,int limit){
        return HardwareTwoHopRegisterFlow.analyze(calls,mids,leaves,
            Set.of(0xfffa00L,0xfffa68L),limit);
    }
    public static void main(String[] args){
        long simcr=0xfffa00L,cs=0xfffa68L;
        var left=outer(0x600,0x640,simcr,0x40ca);
        var right=outer(0x680,0x640,cs,0x4848);
        var bridge=bridge(0x640);
        var leaf=leaf(0x700,"A1");
        var pair=scan(List.of(right,left),List.of(bridge),List.of(leaf),48);
        ok(pair.sampled()==2 && pair.eligibleOuter()==2 &&
            pair.possibleStores()==2 && pair.rows().size()==2,
            "two original callers produce two separate two-hop sources");
        var a=pair.rows().get(0);
        var b=pair.rows().get(1);
        ok(a.outerCaller()==0x600L && a.outerCallPc()==0x60cL &&
            a.bridgeEntry()==0x640L && a.innerCallPc()==0x642L &&
            a.leafEntry()==0x700L && a.storePc()==0x700L &&
            a.effectiveAddress()==simcr && a.writtenWord()==0x40ca &&
            a.knownEntryRegisters()==2 && a.knownInnerRegisters()==3,
            "first caller context A0/D0 copied through bridge to leaf");
        ok(b.outerCaller()==0x680L && b.outerCallPc()==0x68cL &&
            b.effectiveAddress()==cs && b.writtenWord()==0x4848,
            "second caller context cannot pollute the first");
        ok(pair.markdown().contains("SOURCE-ONLY MAY-CANDIDATES") &&
            pair.markdown().contains("NOT EXECUTION") &&
            pair.markdown().contains("A7 is NEVER propagated") &&
            pair.markdown().contains("Neither") &&
            pair.markdown().contains("Review/Apply"),
            "two-hop evidence is not runtime or reviewed Apply");
        var cold=HardwareDataflow.analyze(0x700,leaf.steps(),
            Set.of(simcr,cs),500);
        ok(cold.snapshots.size()==1 &&
            cold.snapshots.get(0).effectiveAddress==null &&
            cold.snapshots.get(0).writtenWord==null,
            "ordinary GA-12 function evidence stays input-free/unknown");
        // At a conditional bridge join incompatible A0 values MUST become
        // unknown; branch feasibility is never guessed.
        var fork=new HardwareTwoHopRegisterFlow.Bridge(0x640,List.of(
            step(0x640,OTHER,null,null,0,"BNE",0x642L,0x644L),
            step(0x642,SET_POINTER,"A0",null,simcr,"MOVEA.L",0x646L),
            step(0x644,SET_POINTER,"A0",null,cs,"MOVEA.L",0x646L),
            jsr(0x646,0x64c),ret(0x64c)),0x646,0x700L,true);
        var branch=scan(List.of(left),List.of(fork),
            List.of(leaf(0x700,"A0")),48);
        ok(branch.rows().isEmpty() && branch.possibleStores()==0 &&
            branch.unknownAliases()==1,
            "conflicting branch path A0 cannot become known MMIO address");
        // A7 changes when JSR pushes its return PC. Unconditionally strip
        // it at BOTH CALL boundaries, even when other D registers survive.
        var stack=new HardwareCallsiteRegisterFlow.Call(0x800,0x80c,0x640L,
            Map.of("A7",simcr,"D0",0x40caL),false);
        var stackBridge=new HardwareTwoHopRegisterFlow.Bridge(0x640,
            List.of(step(0x640,COPY_POINTER,"A1","A7",0,"MOVEA.L",0x642L),
                jsr(0x642,0x648),ret(0x648)),0x642,0x700L,true);
        var stackReport=scan(List.of(stack),List.of(stackBridge),
            List.of(leaf),48);
        ok(stackReport.rows().isEmpty() &&
            stackReport.unknownAliases()==1,
            "caller A7 must not be used as callee memory address");
        var innerStack=scan(List.of(left),List.of(bridge),
            List.of(leaf(0x700,"A7")),48);
        ok(innerStack.rows().isEmpty() &&
            innerStack.unknownAliases()==1,
            "intermediate A7 must not cross nested CALL either");
        var oneHopA7=HardwareCallsiteRegisterFlow.analyze(
            List.of(new HardwareCallsiteRegisterFlow.Call(0x900,0x90c,
                0x700L,Map.of("A7",simcr,"D0",0x40caL),false)),
            List.of(leaf(0x700,"A7")),Set.of(simcr),48);
        ok(oneHopA7.candidates().isEmpty() &&
            oneHopA7.unresolvedAliases()==1,
            "existing one-hop path also must reject pre-JSR A7 aliases");
        // Incomplete, out-of-body, recursive, nested and memory-altering
        // intermediate functions MUST NOT forward unverified arguments.
        var incomplete=new HardwareTwoHopRegisterFlow.Bridge(0x640,
            bridge.steps(),0x642,0x700L,false);
        ok(scan(List.of(left),List.of(incomplete),List.of(leaf),48)
            .rejectedBridge()==1,"incomplete intermediate Listing rejected");
        var nested=new HardwareTwoHopRegisterFlow.Bridge(0x640,List.of(
            jsr(0x640,0x646),jsr(0x646,0x64c),ret(0x64c)),
            0x640,0x700L,true);
        ok(scan(List.of(left),List.of(nested),List.of(leaf),48)
            .rejectedBridge()==1,"second nested CALL rejected");
        var withStore=new HardwareTwoHopRegisterFlow.Bridge(0x640,List.of(
            step(0x640,STORE_INDIRECT,"A0","D0",0,"MOVE.W",0x642L),
            jsr(0x642,0x648),ret(0x648)),0x642,0x700L,true);
        ok(scan(List.of(left),List.of(withStore),List.of(leaf),48)
            .rejectedBridge()==1,"bridge memory side effect rejected");
        var cycle=new HardwareTwoHopRegisterFlow.Bridge(0x640,List.of(
            step(0x640,OTHER,null,null,0,"BRA",0x640L),
            jsr(0x642,0x648),ret(0x648)),0x642,0x700L,true);
        ok(scan(List.of(left),List.of(cycle),List.of(leaf),48)
            .rejectedBridge()==1,"CFG cycle/inaccessible CALL cannot prove transfer");
        var indirect=new HardwareTwoHopRegisterFlow.Bridge(
            0x640,bridge.steps(),0x642,null,true);
        ok(scan(List.of(left),List.of(indirect),List.of(leaf),48)
            .unresolvedInner()==1,"unresolved nested CALL target rejected");
        ok(scan(List.of(left),List.of(bridge),List.of(),48)
            .rejectedLeaf()==1,"missing exact final function rejected");
        ok(scan(List.of(new HardwareCallsiteRegisterFlow.Call(
                0x900,0x90c,null,Map.of("A0",simcr),false)),
            List.of(bridge),List.of(leaf),48).rejectedOuter()==1,
            "outer indirect CALL cannot become two-hop source");
        ok(scan(List.of(new HardwareCallsiteRegisterFlow.Call(
                0x900,0x90c,0x640L,Map.of("A0",simcr),true)),
            List.of(bridge),List.of(leaf),48).rejectedOuter()==1,
            "incomplete outer CFG invalidates two-hop evidence");
        var cap=scan(List.of(left,right),List.of(bridge),List.of(leaf),1);
        ok(cap.possibleStores()==2 && cap.rows().size()==1 &&
            cap.displayTruncated() &&
            cap.markdown().contains("INCOMPLETE DISPLAY"),
            "bounded output cannot silently lose other source candidates");
        var swapped=scan(List.of(left,right),List.of(bridge),List.of(leaf),48);
        ok(swapped.rows().equals(pair.rows()),
            "candidate ordering deterministic regardless input iteration");
        reject(()->scan(List.of(left,left),List.of(bridge),List.of(leaf),48),
            "duplicate outer CALL PC prohibited");
        reject(()->HardwareTwoHopRegisterFlow.analyze(
            List.of(left),List.of(bridge,bridge),List.of(leaf),
            Set.of(simcr),48),"duplicate intermediate prohibited");
        reject(()->scan(List.of(left),List.of(bridge),List.of(leaf),49),
            "display cap hard validated");
        var invalid=new HardwareCallsiteRegisterFlow.Call(0x900,0x90c,
            0x640L,Map.of("A0",0xffffffL,"D0",0x40caL),false);
        var upper=scan(List.of(invalid),List.of(bridge),List.of(leaf),48);
        ok(upper.rows().isEmpty() && upper.possibleStores()==0,
            "unmapped high 24-bit alias not promoted as MC68332 MMIO");
        System.out.println("HardwareTwoHopRegisterFlowSelfTest PASS: assertions="+checks);
    }
}
