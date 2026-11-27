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
        Object reportOwner=new Object();
        var reportRevision=HardwareAnalysisRevision.capture(reportOwner,1,
            "68000:BE:32:CPU32","sha",true);
        String agreementMarkdown=HardwareCallsiteConsensus.markdown(
            List.of(a,b),analyze(List.of(a,b),8),0,24,
            reportRevision,()->reportRevision);
        check(agreementMarkdown.contains("SAMPLED_AGREEMENT") &&
                agreementMarkdown.contains("0x00FFFA00") &&
                agreementMarkdown.contains("NEVER HARDWARE PROOF"),
            "Production source report displays only sampled MAY agreement");
        String omittedMarkdown=HardwareCallsiteConsensus.markdown(
            List.of(a,b),analyze(List.of(a,b),8),1,24,
            reportRevision,()->reportRevision);
        check(omittedMarkdown.contains("INCOMPLETE SOURCE INVENTORY") &&
                omittedMarkdown.contains("INCOMPLETE") &&
                !omittedMarkdown.contains("SAMPLED_AGREEMENT"),
            "Unsampled caller budget suppresses a seemingly unanimous result");
        var singleton=inspect(List.of(a),8);
        check(singleton.state()==HardwareCallsiteConsensus.State.INCOMPLETE &&
                singleton.sampledCallSites()==1 &&
                singleton.address()==null && singleton.word()==null &&
                singleton.bits()==0 && singleton.provenance().size()==1,
            "One complete CALL is not cross-CALL agreement");
        String singletonMarkdown=HardwareCallsiteConsensus.markdown(
            List.of(a),analyze(List.of(a),8),0,24,
            reportRevision,()->reportRevision);
        check(!singletonMarkdown.contains("SAMPLED_AGREEMENT") &&
                singletonMarkdown.contains("NO_SAMPLED_CALLS"),
            "Single caller cannot enter production cross-CALL agreement report");
        var conflict=inspect(List.of(a,c),8);
        check(conflict.state()==HardwareCallsiteConsensus.State.SAMPLED_DIVERGENCE &&
                conflict.address()==null && conflict.word()==null &&
                conflict.bits()==0 && conflict.provenance().size()==2,
            "Different callers do not invent global callee MMIO address");
        String conflictMarkdown=HardwareCallsiteConsensus.markdown(
            List.of(a,c),analyze(List.of(a,c),8),0,24,
            reportRevision,()->reportRevision);
        check(conflictMarkdown.contains("SAMPLED_DIVERGENCE") &&
                conflictMarkdown.contains("UNKNOWN"),
            "Disagreeing source callers never emit one inferred MMIO address");
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
        check(HardwareCallsiteConsensus.markdown(
                List.of(a,b),summary,0,24,revision,()->changed)
                .contains("STALE_REVISION"),
            "Ghidra edit strips all address evidence from the report");
        // The full Markdown is one revision-bound publication, not a
        // collection of individually valid rows. A late edit must erase
        // even the previously rendered known MMIO address and provenance.
        AtomicInteger midReportReads=new AtomicInteger();
        String staleWhole=HardwareCallsiteConsensus.markdown(
            List.of(a,b),summary,0,24,revision,
            ()->midReportReads.incrementAndGet()<4?revision:changed);
        check(midReportReads.get()>=4 &&
                staleWhole.contains("STALE_REVISION") &&
                staleWhole.contains("ENTIRE REPORT WITHHELD") &&
                !staleWhole.contains("0x00FFFA00") &&
                !staleWhole.contains("0x00000500") &&
                !staleWhole.contains("SAMPLED_AGREEMENT"),
            "Edit after a valid row discards entire source report");
        var twoStoreLeaf=new HardwareCallsiteRegisterFlow.Callee(0x500L,List.of(
            new HardwareDataflow.Step(0x500L,STORE_INDIRECT,"A0","D0",
                0,0,null,16,List.of(0x502L),"MOVE.W"),
            new HardwareDataflow.Step(0x502L,STORE_INDIRECT,"A0","D0",
                0,0,null,16,List.of(0x504L),"MOVE.W"),
            new HardwareDataflow.Step(0x504L,OTHER,null,0,0,null,0,
                List.of(),"RTS")),true);
        var twoStoreSummary=HardwareCallsiteRegisterFlow.analyze(
            List.of(a,b),List.of(twoStoreLeaf),Set.of(0xfffa00L),8);
        String clipped=HardwareCallsiteConsensus.markdown(
            List.of(a,b),twoStoreSummary,0,1,revision,()->revision);
        check(clipped.contains("INCOMPLETE DISPLAY") &&
                clipped.contains("0x00FFFA00"),
            "Bounded display retains explicit incomplete marker if unchanged");
        AtomicInteger clippedReads=new AtomicInteger();
        String staleClipped=HardwareCallsiteConsensus.markdown(
            List.of(a,b),twoStoreSummary,0,1,revision,
            ()->clippedReads.incrementAndGet()<4?revision:changed);
        check(clippedReads.get()>=4 &&
                staleClipped.contains("STALE_REVISION") &&
                !staleClipped.contains("INCOMPLETE DISPLAY") &&
                !staleClipped.contains("0x00FFFA00") &&
                !staleClipped.contains("0x00000500"),
            "Early bounded display exit also discards stale earlier source rows");
        String immediatelyStale=HardwareCallsiteConsensus.markdown(
            List.of(a,b),summary,0,24,revision,()->changed);
        check(immediatelyStale.contains("STALE_REVISION") &&
                !immediatelyStale.contains("0x00FFFA00"),
            "Revision changed before report build cannot publish known evidence");
        rejects(()->HardwareCallsiteConsensus.markdown(
                List.of(a,b),summary,-1,24,revision,()->revision),
            "Negative omitted-call inventory rejected");
        rejects(()->HardwareCallsiteConsensus.markdown(
                List.of(a,b),summary,0,49,revision,()->revision),
            "Oversized report budget rejected");

        // GA-02/03: a public producer can fabricate the same CALL-site
        // address and word with a mismatched number of source A/D values.
        // It must never be a two-caller sampled agreement.
        var good=analyze(List.of(a,b),8);
        var firstSource=good.candidates().get(0);
        var mismatched=new HardwareCallsiteRegisterFlow.Candidate(
            firstSource.caller(),firstSource.callPc(),firstSource.callee(),
            firstSource.storePc(),firstSource.kind(),
            firstSource.address(),firstSource.writtenWord(),
            firstSource.writeBits(),firstSource.priorUnknownCall(),
            firstSource.priorUnknownStore(),1);
        var badEvidence=List.of(mismatched,good.candidates().get(1));
        var forgedSummary=new HardwareCallsiteRegisterFlow.Summary(
            good.sampledCalls(),good.directCalls(),good.contextCalls(),
            good.rejectedIncomplete(),good.rejectedMissingCallee(),
            good.rejectedNestedOrBadCfg(),good.truncatedCalls(),
            good.unresolvedAliases(),good.possibleStoreSites(),
            false,badEvidence);
        var rejectedContext=HardwareCallsiteConsensus.inspect(
            List.of(a,b),forgedSummary,0x500L,0x500L);
        check(rejectedContext.state()==HardwareCallsiteConsensus.State.INCOMPLETE &&
                rejectedContext.address()==null && rejectedContext.word()==null,
            "forged source-register count cannot become sampled MMIO agreement");
        var forgedContextCount=new HardwareCallsiteRegisterFlow.Summary(
            good.sampledCalls(),good.directCalls(),1,
            good.rejectedIncomplete(),good.rejectedMissingCallee(),
            good.rejectedNestedOrBadCfg(),good.truncatedCalls(),
            good.unresolvedAliases(),good.possibleStoreSites(),
            false,good.candidates());
        check(HardwareCallsiteConsensus.inspect(List.of(a,b),
            forgedContextCount,0x500L,0x500L).state()==
                HardwareCallsiteConsensus.State.INCOMPLETE,
            "sampled CALL context coverage must match source inventory");
        var forgedDirectCount=new HardwareCallsiteRegisterFlow.Summary(
            good.sampledCalls(),1,1,
            good.rejectedIncomplete(),good.rejectedMissingCallee(),
            good.rejectedNestedOrBadCfg(),good.truncatedCalls(),
            good.unresolvedAliases(),good.possibleStoreSites(),
            false,good.candidates());
        check(HardwareCallsiteConsensus.inspect(List.of(a,b),
            forgedDirectCount,0x500L,0x500L).state()==
                HardwareCallsiteConsensus.State.INCOMPLETE,
            "direct CALL counter cannot substitute for source inventory");
        // Source-bearing public Finding records are also used by report
        // consumers; constructor must reject an invented known conclusion.
        rejects(()->new HardwareCallsiteConsensus.Finding(
            HardwareCallsiteConsensus.State.SAMPLED_AGREEMENT,
            0x500,0x500,2,0xfffa00L,0x40ca,16,List.of()),
            "agreement without both CALL receipts is forbidden");
        rejects(()->new HardwareCallsiteConsensus.Finding(
            HardwareCallsiteConsensus.State.SAMPLED_AGREEMENT,
            0x500,0x500,2,0xfffa00L,0x40ca,16,
            List.of(good.candidates().get(0),good.candidates().get(0))),
            "replaying one caller cannot fabricate independent agreement");
        rejects(()->new HardwareCallsiteConsensus.Finding(
            HardwareCallsiteConsensus.State.SAMPLED_AGREEMENT,
            0x500,0x500,2,0xfffa00L,0x4848,16,good.candidates()),
            "public receipt must match exact word from both callers");
        var secondSource=good.candidates().get(1);
        var alternateKind=new HardwareCallsiteRegisterFlow.Candidate(
            secondSource.caller(),secondSource.callPc(),
            secondSource.callee(),secondSource.storePc(),STORE_DIRECT,
            secondSource.address(),secondSource.writtenWord(),
            secondSource.writeBits(),false,false,
            secondSource.sourceRegisterCount());
        rejects(()->new HardwareCallsiteConsensus.Finding(
            HardwareCallsiteConsensus.State.SAMPLED_AGREEMENT,
            0x500,0x500,2,0xfffa00L,0x40ca,16,
            List.of(good.candidates().get(0),alternateKind)),
            "direct/indirect write source kinds cannot forge unanimity");
        var differingKind=new HardwareCallsiteRegisterFlow.Summary(
            good.sampledCalls(),good.directCalls(),good.contextCalls(),
            good.rejectedIncomplete(),good.rejectedMissingCallee(),
            good.rejectedNestedOrBadCfg(),good.truncatedCalls(),
            good.unresolvedAliases(),good.possibleStoreSites(),
            false,List.of(good.candidates().get(0),alternateKind));
        check(HardwareCallsiteConsensus.inspect(List.of(a,b),
            differingKind,0x500L,0x500L).state()==
                HardwareCallsiteConsensus.State.SAMPLED_DIVERGENCE,
            "sampled source kinds disagree even with identical address/word");
        var withStack=new HardwareCallsiteRegisterFlow.Call(
            a.caller(),a.callPc(),a.directCallee(),
            Map.of("A0",0xfffa00L,"D0",0x40caL,"A7",0xfff7fcL),false);
        var stackSafe=HardwareCallsiteConsensus.inspect(
            List.of(withStack,b),analyze(List.of(withStack,b),8),
            0x500L,0x500L);
        check(stackSafe.state()==
                HardwareCallsiteConsensus.State.SAMPLED_AGREEMENT &&
            stackSafe.provenance().get(0).sourceRegisterCount()==2,
            "A7 is never part of the passed A/D register context");
        rejects(()->new HardwareCallsiteConsensus.Finding(
            HardwareCallsiteConsensus.State.NO_SAMPLED_CALLS,
            0x500,0x500,0,null,null,0,good.candidates()),
            "no sampled calls cannot conceal retained provenances");
        rejects(()->new HardwareCallsiteConsensus.Finding(
            HardwareCallsiteConsensus.State.STALE_REVISION,
            0x500,0x500,1,null,null,0,List.of()),
            "stale snapshot cannot advertise one current CALL");
        rejects(()->new HardwareCallsiteConsensus.Finding(
            HardwareCallsiteConsensus.State.INCOMPLETE,
            0x500,0x500,2,0xfffa00L,null,0,good.candidates()),
            "incomplete CALL evidence must suppress exact MMIO address");
        check(HardwareCallsiteConsensus.inspect(List.of(a,b),good,
            0x500,0x500).state()==
                HardwareCallsiteConsensus.State.SAMPLED_AGREEMENT,
            "fully sourced two-CALL control case still agrees");
        System.out.println("HardwareCallsiteConsensusSelfTest PASS: assertions="+
            assertions);
    }
}
