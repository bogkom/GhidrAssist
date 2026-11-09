package ghidrassist.hardware;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

/** GA-02/03/12 sampled CALL reconciliation, provenance and revision gates. */
public final class HardwareCallsiteConsensusSelfTest {
    private static int assertions;
    private static void check(boolean pass,String why){
        assertions++;
        if(!pass)throw new AssertionError(why);
    }
    private static HardwareCallsiteRegisterFlow.Call call(
            long caller,long site,long callee,Long a0,boolean incomplete) {
        return new HardwareCallsiteRegisterFlow.Call(caller,site,callee,
            a0==null?Map.of("D0",0x40caL):
                Map.of("A0",a0,"D0",0x40caL),incomplete);
    }
    private static HardwareCallsiteRegisterFlow.Callee leaf(){
        return new HardwareCallsiteRegisterFlow.Callee(0x500L,List.of(
            new HardwareDataflow.Step(0x500L,STORE_INDIRECT,"A0","D0",
                0,0,null,16,List.of(0x502L),"MOVE.W"),
            new HardwareDataflow.Step(0x502L,OTHER,null,0,0,null,0,
                List.of(),"RTS")),true);
    }
    private static HardwareCallsiteRegisterFlow.Summary analyze(
            List<HardwareCallsiteRegisterFlow.Call> calls,int maxRows) {
        return HardwareCallsiteRegisterFlow.analyze(
            calls,List.of(leaf()),Set.of(0xfffa00L,0xfffa68L),maxRows);
    }
    private static HardwareCallsiteConsensus.Finding inspect(
            List<HardwareCallsiteRegisterFlow.Call> calls,int rows) {
        return HardwareCallsiteConsensus.inspect(calls,analyze(calls,rows),
            0x500L,0x500L);
    }
    private static void rejects(Runnable test,String why){
        boolean denied=false;
        try{test.run();}catch(IllegalArgumentException expected){denied=true;}
        check(denied,why);
    }
    public static void main(String[] args){
        var a=call(0x100L,0x10cL,0x500L,0xfffa00L,false);
        var b=call(0x200L,0x20cL,0x500L,0xfffa00L,false);
        var c=call(0x300L,0x30cL,0x500L,0xfffa68L,false);
        var agreement=inspect(List.of(b,a),8);
        check(agreement.state()==HardwareCallsiteConsensus.State.SAMPLED_AGREEMENT &&
                agreement.sampledCallSites()==2 &&
                agreement.address()==0xfffa00L &&
                agreement.word()==0x40ca &&
                agreement.bits()==16 &&
                agreement.provenance().size()==2,
            "Two distinct sampled CALLs agree on source address/word/width");
        check(agreement.provenance().get(0).caller()==0x100L &&
                agreement.provenance().get(1).caller()==0x200L,
            "Independent CALL-site rows sorted deterministically");
        check(!agreement.publishableAsHardwareProof() &&
                agreement.description().contains("not runtime execution") &&
                agreement.description().contains("Review/Apply"),
            "Agreement among sampled CALLs is never runtime/global proof");
        var conflict=inspect(List.of(a,c),8);
        check(conflict.state()==HardwareCallsiteConsensus.State.SAMPLED_DIVERGENCE &&
                conflict.address()==null && conflict.word()==null &&
                conflict.bits()==0 && conflict.provenance().size()==2,
            "Different callers do not invent global callee MMIO address");
        var hidden=inspect(List.of(a,b,c),1);
        check(hidden.state()==HardwareCallsiteConsensus.State.INCOMPLETE &&
                hidden.address()==null,
            "Paginated output cannot certify sampled convergence");
        var unknown=call(0x400L,0x40cL,0x500L,null,false);
        check(inspect(List.of(a,unknown),8).state()==
                HardwareCallsiteConsensus.State.INCOMPLETE,
            "Unknown pointer in any sampled CALL invalidates consensus");
        check(inspect(List.of(a,call(0x500L,0x50cL,0x500L,
                0xfffa00L,true)),8).state()==
                HardwareCallsiteConsensus.State.INCOMPLETE,
            "Unfinished caller must not inherit known callee evidence");
        var none=HardwareCallsiteConsensus.inspect(List.of(a),
            analyze(List.of(a),8),0x700L,0x500L);
        check(none.state()==HardwareCallsiteConsensus.State.NO_SAMPLED_CALLS &&
                none.provenance().isEmpty(),
            "Unsampled callee must never be represented as negative evidence");
        var wrongStore=HardwareCallsiteConsensus.inspect(List.of(a),
            analyze(List.of(a),8),0x500L,0x502L);
        check(wrongStore.state()==HardwareCallsiteConsensus.State.INCOMPLETE,
            "No row for a requested STORE is not proof it cannot write");
        var foreign=HardwareCallsiteConsensus.inspect(List.of(b),
            analyze(List.of(a),8),0x500L,0x500L);
        check(foreign.state()==HardwareCallsiteConsensus.State.INCOMPLETE,
            "Foreign caller evidence cannot replace the supplied source");
        rejects(()->HardwareCallsiteConsensus.inspect(List.of(a,a),
            analyze(List.of(a),8),0x500L,0x500L),
            "Duplicate caller and CALL PC rejected");
        rejects(()->HardwareCallsiteConsensus.inspect(List.of(a),
            analyze(List.of(a),8),-1L,0x500L),
            "Negative target entry must fail closed");

        Object program=new Object();
        var revision=HardwareAnalysisRevision.capture(
            program,12,"68000:BE:32:CPU32","synthetic-original-sha",true);
        var same=HardwareAnalysisRevision.capture(
            program,12,"68000:BE:32:CPU32","synthetic-original-sha",true);
        var changed=HardwareAnalysisRevision.capture(
            program,13,"68000:BE:32:CPU32","synthetic-original-sha",true);
        var differentProfile=HardwareAnalysisRevision.capture(
            program,12,"68000:BE:32:CPU32","synthetic-original-sha",false);
        var cloned=HardwareAnalysisRevision.capture(
            new Object(),12,"68000:BE:32:CPU32","synthetic-original-sha",true);
        var summary=analyze(List.of(a,b),8);
        var accepted=HardwareCallsiteConsensus.inspectRevisionBound(
            revision,()->same,List.of(a,b),summary,0x500L,0x500L);
        check(accepted.state()==HardwareCallsiteConsensus.State.SAMPLED_AGREEMENT,
            "Unchanged actual revision token may return sampled source evidence");
        for(var candidate:List.of(changed,differentProfile,cloned)) {
            var denied=HardwareCallsiteConsensus.inspectRevisionBound(
                revision,()->candidate,List.of(a,b),summary,0x500L,0x500L);
            check(denied.state()==HardwareCallsiteConsensus.State.STALE_REVISION &&
                    denied.provenance().isEmpty() && denied.address()==null,
                "Edited revision, profile or foreign owner must return no sources");
        }
        AtomicInteger read=new AtomicInteger();
        var midflight=HardwareCallsiteConsensus.inspectRevisionBound(
            revision,()->read.getAndIncrement()==0?same:changed,
            List.of(a,b),summary,0x500L,0x500L);
        check(midflight.state()==HardwareCallsiteConsensus.State.STALE_REVISION &&
                midflight.provenance().isEmpty() && read.get()==2,
            "Revision edited during evaluation must discard all stale evidence");
        rejects(()->HardwareCallsiteConsensus.inspectRevisionBound(
            null,()->same,List.of(a),summary,0x500L,0x500L),
            "Missing revision snapshot rejected");
        rejects(()->HardwareCallsiteConsensus.inspectRevisionBound(
            revision,null,List.of(a),summary,0x500L,0x500L),
            "Missing revision supplier rejected");
        System.out.println("HardwareCallsiteConsensusSelfTest PASS: assertions="+
            assertions);
    }
}
