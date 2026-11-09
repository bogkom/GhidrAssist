package ghidrassist.hardware;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

/** GA-02/03/12: two-hop source agreement, missing contexts and revision race. */
public final class HardwareTwoHopConsensusSelfTest {
    private HardwareTwoHopConsensusSelfTest(){}
    private static int checks;
    private static void ok(boolean value,String why){
        checks++;
        if(!value)throw new AssertionError(why);
    }
    private static void denied(Runnable fn,String why){
        boolean failed=false;
        try{fn.run();}catch(IllegalArgumentException expected){failed=true;}
        ok(failed,why);
    }
    private static HardwareCallsiteRegisterFlow.Call caller(
            long entry,Long address,long word) {
        return new HardwareCallsiteRegisterFlow.Call(entry,entry+0xCL,0x640L,
            address==null?Map.of("D0",word):
                Map.of("A0",address,"D0",word),false);
    }
    private static HardwareTwoHopRegisterFlow.Bridge bridge(){
        return new HardwareTwoHopRegisterFlow.Bridge(0x640L,List.of(
            new HardwareDataflow.Step(0x640L,COPY_POINTER,"A1","A0",
                0,0,null,0,List.of(0x642L),"MOVEA.L"),
            new HardwareDataflow.Step(0x642L,CALL_BARRIER,null,
                0,0,null,0,List.of(0x648L),"JSR"),
            new HardwareDataflow.Step(0x648L,OTHER,null,
                0,0,null,0,List.of(),"RTS")),0x642L,0x700L,true);
    }
    private static HardwareCallsiteRegisterFlow.Callee leaf(){
        return new HardwareCallsiteRegisterFlow.Callee(0x700L,List.of(
            new HardwareDataflow.Step(0x700L,STORE_INDIRECT,"A1","D0",
                0,0,null,16,List.of(0x702L),"MOVE.W"),
            new HardwareDataflow.Step(0x702L,OTHER,null,
                0,0,null,0,List.of(),"RTS")),true);
    }
    private static HardwareTwoHopRegisterFlow.Summary analyze(
            List<HardwareCallsiteRegisterFlow.Call> calls,int limit){
        return HardwareTwoHopRegisterFlow.analyze(calls,List.of(bridge()),
            List.of(leaf()),Set.of(0xfffa00L,0xfffa68L),limit);
    }
    private static HardwareTwoHopConsensus.Finding inspect(
            List<HardwareCallsiteRegisterFlow.Call> calls,int limit){
        return HardwareTwoHopConsensus.inspect(calls,analyze(calls,limit),
            0x700L,0x700L);
    }
    public static void main(String[] args){
        long simcr=0xfffa00L,cs=0xfffa68L;
        var a=caller(0x100L,simcr,0x40caL);
        var b=caller(0x200L,simcr,0x40caL);
        var c=caller(0x300L,cs,0x4848L);
        var agreement=inspect(List.of(b,a),16);
        ok(agreement.state()==HardwareTwoHopConsensus.State.SAMPLED_AGREEMENT &&
                agreement.sampledOuterCalls()==2 &&
                agreement.address()==simcr &&
                agreement.word()==0x40ca &&
                agreement.bits()==16 &&
                agreement.provenance().size()==2,
            "Two independent outer direct CALLs agree after one bridge");
        ok(agreement.provenance().get(0).outerCaller()==0x100L &&
                agreement.provenance().get(0).bridgeEntry()==0x640L &&
                agreement.provenance().get(0).innerCallPc()==0x642L &&
                agreement.provenance().get(0).leafEntry()==0x700L &&
                agreement.provenance().get(0).storePc()==0x700L &&
                agreement.provenance().get(1).outerCaller()==0x200L,
            "Independent outer, bridge, nested and leaf PCs retained");
        ok(!agreement.publishableAsHardwareProof(),
            "Sampled two-hop agreement is never runtime MMIO proof");
        var singleton=inspect(List.of(a),16);
        ok(singleton.state()==HardwareTwoHopConsensus.State.INCOMPLETE &&
                singleton.sampledOuterCalls()==1 &&
                singleton.address()==null && singleton.word()==null &&
                singleton.bits()==0 && singleton.provenance().size()==1 &&
                !singleton.publishableAsHardwareProof(),
            "One complete two-hop source is not an agreement among callers");
        var singletonScoped=HardwareTwoHopConsensus.inspectScoped(
            List.of(a),analyze(List.of(a),16),0x640L,0x700L,0x700L);
        ok(singletonScoped.state()==HardwareTwoHopConsensus.State.INCOMPLETE &&
                singletonScoped.sampledOuterCalls()==1 &&
                singletonScoped.address()==null &&
                singletonScoped.provenance().size()==1,
            "Single outer CALL cannot certify even an exact bridge/leaf/STORE cohort");
        var divergence=inspect(List.of(a,c),16);
        ok(divergence.state()==HardwareTwoHopConsensus.State.SAMPLED_DIVERGENCE &&
                divergence.address()==null && divergence.word()==null &&
                divergence.provenance().size()==2,
            "Different callers do not produce a globally proven MMIO address");
        var missing=caller(0x400L,null,0x40caL);
        ok(inspect(List.of(a,missing),16).state()==
                HardwareTwoHopConsensus.State.INCOMPLETE,
            "Unknown A0 in the outer caller poisons apparent agreement");
        var partial=new HardwareCallsiteRegisterFlow.Call(
            0x500L,0x50cL,0x640L,Map.of("A0",simcr,"D0",0x40caL),true);
        ok(inspect(List.of(a,partial),16).state()==
                HardwareTwoHopConsensus.State.INCOMPLETE,
            "Unfinished outer caller cannot be promoted to agreement");
        ok(inspect(List.of(a,b,c),1).state()==
                HardwareTwoHopConsensus.State.INCOMPLETE,
            "Display pagination cannot certify complete source contexts");
        ok(HardwareTwoHopConsensus.inspect(List.of(),analyze(List.of(),16),
                0x700L,0x700L).state()==
                HardwareTwoHopConsensus.State.NO_SAMPLED_CALLS,
            "No sampled outer source is explicitly unknown");
        ok(HardwareTwoHopConsensus.inspect(List.of(a),analyze(List.of(a),16),
                0x700L,0x702L).state()==
                HardwareTwoHopConsensus.State.INCOMPLETE,
            "Unobserved requested STORE cannot be declared absent");
        ok(HardwareTwoHopConsensus.inspect(List.of(b),analyze(List.of(a),16),
                0x700L,0x700L).state()==
                HardwareTwoHopConsensus.State.INCOMPLETE,
            "Foreign outer caller evidence cannot satisfy this inventory");
        denied(()->HardwareTwoHopConsensus.inspect(List.of(a,a),
                analyze(List.of(a),16),0x700L,0x700L),
            "Duplicate outer CALL PC is rejected");
        denied(()->HardwareTwoHopConsensus.inspect(List.of(a),
                analyze(List.of(a),16),-1L,0x700L),
            "Negative leaf entry rejected");

        Object program=new Object();
        var rev=HardwareAnalysisRevision.capture(program,8,
            "68000:BE:32:CPU32","synthetic-sha",true);
        var equal=HardwareAnalysisRevision.capture(program,8,
            "68000:BE:32:CPU32","synthetic-sha",true);
        var changed=HardwareAnalysisRevision.capture(program,9,
            "68000:BE:32:CPU32","synthetic-sha",true);
        var wrongProfile=HardwareAnalysisRevision.capture(program,8,
            "68000:BE:32:CPU32","synthetic-sha",false);
        var wrongOwner=HardwareAnalysisRevision.capture(new Object(),8,
            "68000:BE:32:CPU32","synthetic-sha",true);
        var summary=analyze(List.of(a,b),16);
        var valid=HardwareTwoHopConsensus.inspectRevisionBound(rev,()->equal,
            List.of(a,b),summary,0x700L,0x700L);
        ok(valid.state()==HardwareTwoHopConsensus.State.SAMPLED_AGREEMENT,
            "Matching source owner and revision permits sampled result");
        for(var bad:List.of(changed,wrongProfile,wrongOwner)) {
            var rejected=HardwareTwoHopConsensus.inspectRevisionBound(
                rev,()->bad,List.of(a,b),summary,0x700L,0x700L);
            ok(rejected.state()==HardwareTwoHopConsensus.State.STALE_REVISION &&
                    rejected.address()==null && rejected.provenance().isEmpty(),
                "Edited Ghidra Program, profile or owner discards provenance");
        }
        AtomicInteger reads=new AtomicInteger();
        var raced=HardwareTwoHopConsensus.inspectRevisionBound(
            rev,()->reads.getAndIncrement()==0?equal:changed,
            List.of(a,b),summary,0x700L,0x700L);
        ok(raced.state()==HardwareTwoHopConsensus.State.STALE_REVISION &&
                raced.provenance().isEmpty() && reads.get()==2,
            "Revision changed between source gates suppresses all evidence");
        String agreedMarkdown=HardwareTwoHopConsensus.markdown(
            List.of(a,b),summary,0,16,rev,()->equal);
        ok(agreedMarkdown.contains("SAMPLED_AGREEMENT") &&
                agreedMarkdown.contains("0x00FFFA00") &&
                agreedMarkdown.contains("NOT HARDWARE PROOF"),
            "Report labels sampled agreement as source-only");
        String omission=HardwareTwoHopConsensus.markdown(
            List.of(a,b),summary,1,16,rev,()->equal);
        ok(omission.contains("INCOMPLETE INPUT") &&
                !omission.contains("SAMPLED_AGREEMENT"),
            "Unseen outer CALLs prevent apparent unanimous consensus");
        String stale=HardwareTwoHopConsensus.markdown(
            List.of(a,b),summary,0,16,rev,()->changed);
        ok(stale.contains("STALE_REVISION") &&
                !stale.contains("0x00FFFA00"),
            "Stale revision strips even sampled source addresses");
        String different=HardwareTwoHopConsensus.markdown(
            List.of(a,c),analyze(List.of(a,c),16),0,16,rev,()->equal);
        ok(different.contains("SAMPLED_DIVERGENCE") &&
                different.contains("UNKNOWN"),
            "Conflicting leaf source candidates reported without false address");
        denied(()->HardwareTwoHopConsensus.markdown(List.of(a),summary,
                -1,16,rev,()->equal),
            "Negative omitted outer count rejected");
        denied(()->HardwareTwoHopConsensus.markdown(List.of(a),summary,
                0,HardwareTwoHopConsensus.MAX_REPORT_ROWS+1,rev,()->equal),
            "Unbounded report rows rejected");
        // Fully decoded fork/merge in the first bridge. Two identical
        // predecessor assignments to A1 establish an agreed inner CALL
        // register; neither branch is assumed to execute.
        var forkBridge=new HardwareTwoHopRegisterFlow.Bridge(0x640L,List.of(
            new HardwareDataflow.Step(0x640L,OTHER,null,0,0,null,0,
                List.of(0x642L,0x648L),"BNE"),
            new HardwareDataflow.Step(0x642L,COPY_POINTER,"A1","A0",
                0,0,null,0,List.of(0x644L),"MOVEA.L"),
            new HardwareDataflow.Step(0x644L,OTHER,null,0,0,null,0,
                List.of(0x64cL),"BRA"),
            new HardwareDataflow.Step(0x648L,COPY_POINTER,"A1","A0",
                0,0,null,0,List.of(0x64cL),"MOVEA.L"),
            new HardwareDataflow.Step(0x64cL,CALL_BARRIER,null,
                0,0,null,0,List.of(0x652L),"JSR"),
            new HardwareDataflow.Step(0x652L,OTHER,null,
                0,0,null,0,List.of(),"RTS")),0x64cL,0x700L,true);
        var multiStoreLeaf=new HardwareCallsiteRegisterFlow.Callee(
            0x700L,List.of(
                new HardwareDataflow.Step(0x700L,STORE_INDIRECT,"A1","D0",
                    0,0,null,16,List.of(0x702L),"MOVE.W"),
                new HardwareDataflow.Step(0x702L,STORE_INDIRECT,"A1","D0",
                    0,0,null,16,List.of(0x704L),"MOVE.W"),
                new HardwareDataflow.Step(0x704L,OTHER,null,
                    0,0,null,0,List.of(),"RTS")),true);
        // Second independently decoded bridge calls a DIFFERENT leaf.
        var secondBridge=new HardwareTwoHopRegisterFlow.Bridge(
            0x740L,List.of(
                new HardwareDataflow.Step(0x740L,COPY_POINTER,"A1","A0",
                    0,0,null,0,List.of(0x742L),"MOVEA.L"),
                new HardwareDataflow.Step(0x742L,CALL_BARRIER,null,
                    0,0,null,0,List.of(0x748L),"JSR"),
                new HardwareDataflow.Step(0x748L,OTHER,null,
                    0,0,null,0,List.of(),"RTS")),0x742L,0x780L,true);
        var secondLeaf=new HardwareCallsiteRegisterFlow.Callee(
            0x780L,List.of(
                new HardwareDataflow.Step(0x780L,STORE_INDIRECT,"A1","D0",
                    0,0,null,16,List.of(0x782L),"MOVE.W"),
                new HardwareDataflow.Step(0x782L,OTHER,null,
                    0,0,null,0,List.of(),"RTS")),true);
        var outerC=new HardwareCallsiteRegisterFlow.Call(
            0x900L,0x90cL,0x740L,Map.of("A0",cs,"D0",0x4848L),false);
        var outerD=new HardwareCallsiteRegisterFlow.Call(
            0x980L,0x98cL,0x740L,Map.of("A0",cs,"D0",0x4848L),false);
        var allOuter=List.of(outerD,b,a,outerC);
        var multiple=HardwareTwoHopRegisterFlow.analyze(allOuter,
            List.of(secondBridge,forkBridge),
            List.of(multiStoreLeaf,secondLeaf),Set.of(simcr,cs),48);
        ok(multiple.sampled()==4 && multiple.possibleStores()==6 &&
                multiple.rows().size()==6 &&
                multiple.unknownAliases()==0 && !multiple.displayTruncated(),
            "Convergent fork and two separate leaf functions yield six sources");
        for(long store:new long[]{0x700L,0x702L}) {
            var hit=HardwareTwoHopConsensus.inspectScoped(
                allOuter,multiple,0x640L,0x700L,store);
            ok(hit.state()==HardwareTwoHopConsensus.State.SAMPLED_AGREEMENT &&
                    hit.sampledOuterCalls()==2 && hit.address()==simcr &&
                    hit.provenance().size()==2 &&
                    hit.provenance().stream().allMatch(r->
                        r.bridgeEntry()==0x640L && r.leafEntry()==0x700L &&
                        r.storePc()==store && r.innerCallPc()==0x64cL),
                "Every independent STORE site retains correct convergent CALL provenance");
        }
        var unevenOuter=List.of(a,outerC,outerD);
        var uneven=HardwareTwoHopRegisterFlow.analyze(unevenOuter,
            List.of(forkBridge,secondBridge),
            List.of(multiStoreLeaf,secondLeaf),Set.of(simcr,cs),48);
        var loneBridge=HardwareTwoHopConsensus.inspectScoped(
            unevenOuter,uneven,0x640L,0x700L,0x700L);
        var pairedBridge=HardwareTwoHopConsensus.inspectScoped(
            unevenOuter,uneven,0x740L,0x780L,0x780L);
        ok(loneBridge.state()==HardwareTwoHopConsensus.State.INCOMPLETE &&
                loneBridge.sampledOuterCalls()==1 &&
                loneBridge.provenance().size()==1 &&
                loneBridge.address()==null &&
                pairedBridge.state()==HardwareTwoHopConsensus.State.SAMPLED_AGREEMENT &&
                pairedBridge.sampledOuterCalls()==2 &&
                pairedBridge.address()==cs,
            "Separate bridges cannot lend callers to a singleton cohort");
        String unevenMarkdown=HardwareTwoHopConsensus.markdown(
            unevenOuter,uneven,0,24,rev,()->equal);
        ok(unevenMarkdown.contains(
                "| 0x00000640 | 0x00000700 | 0x00000700 | 1 | INCOMPLETE") &&
                unevenMarkdown.contains(
                "| 0x00000740 | 0x00000780 | 0x00000780 | 2 | SAMPLED_AGREEMENT") &&
                unevenMarkdown.contains("SOURCE-ONLY MAY-CANDIDATES"),
            "Production two-hop report keeps singleton unknown and independent pair");
        var otherLeaf=HardwareTwoHopConsensus.inspectScoped(
            allOuter,multiple,0x740L,0x780L,0x780L);
        ok(otherLeaf.state()==HardwareTwoHopConsensus.State.SAMPLED_AGREEMENT &&
                otherLeaf.sampledOuterCalls()==2 && otherLeaf.address()==cs &&
                otherLeaf.provenance().stream().allMatch(r->
                    r.bridgeEntry()==0x740L && r.leafEntry()==0x780L),
            "Other leaf's callers cannot be mistaken for missing source of first leaf");
        var multiMarkdown=HardwareTwoHopConsensus.markdown(
            allOuter,multiple,0,24,rev,()->equal);
        ok(multiMarkdown.contains(
                "| 0x00000640 | 0x00000700 | 0x00000700 | 2 | SAMPLED_AGREEMENT") &&
                multiMarkdown.contains(
                "| 0x00000640 | 0x00000700 | 0x00000702 | 2 | SAMPLED_AGREEMENT") &&
                multiMarkdown.contains(
                "| 0x00000740 | 0x00000780 | 0x00000780 | 2 | SAMPLED_AGREEMENT"),
            "Bounded production table displays three disjoint cohorts");
        var omitted=HardwareTwoHopConsensus.markdown(
            allOuter,multiple,1,24,rev,()->equal);
        ok(omitted.contains("INCOMPLETE INPUT") &&
                !omitted.contains("SAMPLED_AGREEMENT"),
            "Unseen global CALL inventory still blocks every local agreement");
        var truncated=HardwareTwoHopRegisterFlow.analyze(allOuter,
            List.of(forkBridge,secondBridge),
            List.of(multiStoreLeaf,secondLeaf),Set.of(simcr,cs),3);
        ok(truncated.displayTruncated() &&
                HardwareTwoHopConsensus.inspectScoped(allOuter,truncated,
                    0x640L,0x700L,0x700L).state()==
                    HardwareTwoHopConsensus.State.INCOMPLETE,
            "Truncated source pagination cannot imply local convergence");

        // A mid-render Listing revision invalidates the ENTIRE report,
        // including rows completed before the edit was observed.
        AtomicInteger reportReads=new AtomicInteger();
        var discardedReport=HardwareTwoHopConsensus.markdown(
            allOuter,multiple,0,24,rev,
            ()->reportReads.getAndIncrement()<3?equal:changed);
        ok(discardedReport.contains("STALE_REVISION") &&
                !discardedReport.contains("SAMPLED_AGREEMENT") &&
                !discardedReport.contains("0x00FFFA00") &&
                !discardedReport.contains("0x00FFFA68"),
            "Ghidra edit during multi-row report discards prior valid rows");
        // One bridge's callers are not exchangeable with another bridge's
        // leaf, even when both may reach the same tracked MCU registers.
        var missingForeign=HardwareTwoHopConsensus.inspectScoped(
            allOuter,multiple,0x640L,0x780L,0x780L);
        ok(missingForeign.state()==HardwareTwoHopConsensus.State.INCOMPLETE ||
                missingForeign.state()==HardwareTwoHopConsensus.State.NO_SAMPLED_CALLS,
            "Foreign leaf rows never become cross-bridge agreement");
        var missingBridge=HardwareTwoHopConsensus.inspectScoped(
            allOuter,multiple,0x7f0L,0x780L,0x780L);
        ok(missingBridge.state()==HardwareTwoHopConsensus.State.NO_SAMPLED_CALLS,
            "Unobserved bridge is not interpreted as globally absent effect");

        // One branch assigns a DIFFERENT A1, so no exact effective
        // address survives the fixed-point join at inner JSR.
        var divergentBranch=new HardwareTwoHopRegisterFlow.Bridge(
            0x640L,List.of(
                new HardwareDataflow.Step(0x640L,OTHER,null,
                    0,0,null,0,List.of(0x642L,0x648L),"BNE"),
                new HardwareDataflow.Step(0x642L,COPY_POINTER,"A1","A0",
                    0,0,null,0,List.of(0x644L),"MOVEA.L"),
                new HardwareDataflow.Step(0x644L,OTHER,null,
                    0,0,null,0,List.of(0x64cL),"BRA"),
                new HardwareDataflow.Step(0x648L,SET_POINTER,"A1",
                    cs,0,null,0,List.of(0x64cL),"MOVEA.L"),
                new HardwareDataflow.Step(0x64cL,CALL_BARRIER,null,
                    0,0,null,0,List.of(0x652L),"JSR"),
                new HardwareDataflow.Step(0x652L,OTHER,null,
                    0,0,null,0,List.of(),"RTS")),0x64cL,0x700L,true);
        var conflictScan=HardwareTwoHopRegisterFlow.analyze(
            List.of(a,b),List.of(divergentBranch),
            List.of(multiStoreLeaf),Set.of(simcr,cs),48);
        ok(conflictScan.unknownAliases()>0 &&
                HardwareTwoHopConsensus.inspectScoped(List.of(a,b),
                    conflictScan,0x640L,0x700L,0x700L).state()==
                    HardwareTwoHopConsensus.State.INCOMPLETE,
            "Conflicting bridge branch A1 never fabricates known MMIO source");
        AtomicInteger secondGate=new AtomicInteger();
        var staleScoped=HardwareTwoHopConsensus.inspectScopedRevisionBound(
            rev,()->secondGate.getAndIncrement()==0?equal:changed,
            allOuter,multiple,0x640L,0x700L,0x700L);
        ok(staleScoped.state()==HardwareTwoHopConsensus.State.STALE_REVISION &&
                staleScoped.address()==null &&
                staleScoped.provenance().isEmpty() && secondGate.get()==2,
            "Mid-scan actual revision transition drops all scoped branch evidence");

        System.out.println("HardwareTwoHopConsensusSelfTest PASS: checks="+checks);
    }
}
