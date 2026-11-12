package ghidrassist.hardware;

import java.util.List;
import java.util.Map;
import java.util.Set;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

/** GA-02/03 one-hop static-source CALL argument/alias safety, no Ghidra. */
public final class HardwareCallsiteRegisterFlowSelfTest {
    private static int assertions;
    private static void ok(boolean value,String message){
        assertions++;
        if(!value)throw new AssertionError(message);
    }
    private static void rejects(Runnable action,String message){
        boolean bad=false;
        try{action.run();}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,message);
    }
    private static HardwareDataflow.Step set(long pc,String reg,long value,long next){
        return new HardwareDataflow.Step(pc,SET_POINTER,reg,value,0,null,0,
            List.of(next),"MOVE.L");
    }
    private static HardwareDataflow.Step ret(long pc){
        return new HardwareDataflow.Step(pc,OTHER,null,0,0,null,0,
            List.of(),"RTS");
    }
    private static List<HardwareDataflow.Step> callee(long entry){
        return List.of(
            new HardwareDataflow.Step(entry,STORE_INDIRECT,"A0","D0",
                0,0,null,16,List.of(entry+2),"MOVE.W"),
            ret(entry+2));
    }
    private static HardwareCallsiteRegisterFlow.Call call(long entry,long target,
            long pointer,long value){
        var steps=List.of(
            set(entry,"A0",pointer,entry+6),
            set(entry+6,"D0",value,entry+12),
            new HardwareDataflow.Step(entry+12,CALL_BARRIER,null,
                0,0,null,0,List.of(entry+18),"JSR"),
            ret(entry+18));
        var cold=HardwareDataflow.analyze(entry,steps,
            Set.of(0xfffa00L,0xfffa68L),500);
        ok(!cold.truncated,"Caller CFG must complete");
        var agreed=cold.knownPointersAtEntry.get(entry+12);
        ok(agreed!=null && agreed.size()==2 &&
            agreed.get("A0")==pointer && agreed.get("D0")==value,
            "Caller values must be known at CALL only when predecessors agree");
        ok(!cold.knownPointersAtEntry.containsKey(entry+18),
            "Caller constants cannot survive unsummarized CALL");
        return new HardwareCallsiteRegisterFlow.Call(
            entry,entry+12,target,agreed,false);
    }
    public static void main(String[] args){
        long simcr=0xfffa00L,cs=0xfffa68L;
        var callee=new HardwareCallsiteRegisterFlow.Callee(
            0x640,callee(0x640),true);
        var left=call(0x600,0x640,simcr,0x40ca);
        var right=call(0x680,0x640,cs,0x4848);
        var results=HardwareCallsiteRegisterFlow.analyze(
            List.of(right,left),List.of(callee),Set.of(simcr,cs),64);
        ok(results.sampledCalls()==2 && results.directCalls()==2 &&
            results.contextCalls()==2 && results.possibleStoreSites()==2 &&
            results.candidates().size()==2,
            "Two distinct direct CALL contexts yield two source candidates");
        var a=results.candidates().get(0);
        var b=results.candidates().get(1);
        ok(a.caller()==0x600L && a.callPc()==0x60cL &&
            a.callee()==0x640 && a.storePc()==0x640 &&
            a.address()==simcr && a.writtenWord()==0x40ca &&
            a.sourceRegisterCount()==2,
            "First caller transfers A0 and D0 to callee STORE");
        ok(b.caller()==0x680L && b.callPc()==0x68cL &&
            b.address()==cs && b.writtenWord()==0x4848,
            "Second caller cannot inherit or overwrite first caller arguments");
        ok(results.markdown().contains("SOURCE-ONLY MAY-CANDIDATES") &&
            results.markdown().contains("No argument convention/actual") &&
            results.markdown().contains("No result is published"),
            "Report must not infer executed MMIO or Review/Apply proof");
        var coldCallee=HardwareDataflow.analyze(0x640,callee.steps(),
            Set.of(simcr,cs),500);
        ok(coldCallee.snapshots.size()==1 &&
            coldCallee.snapshots.get(0).effectiveAddress==null &&
            coldCallee.snapshots.get(0).writtenWord==null,
            "Ordinary function analysis unchanged: no injected caller state");
        var conditional=List.of(
            new HardwareDataflow.Step(0x700,OTHER,null,0,0,null,0,
                List.of(0x710L,0x720L),"BNE"),
            set(0x710,"A0",simcr,0x730),
            set(0x720,"A0",cs,0x730),
            set(0x730,"D0",0x40caL,0x736),
            new HardwareDataflow.Step(0x736,CALL_BARRIER,null,0,0,null,0,
                List.of(0x73cL),"JSR"),
            ret(0x73c));
        var fork=HardwareDataflow.analyze(0x700,conditional,
            Set.of(simcr,cs),500);
        var atCall=fork.knownPointersAtEntry.get(0x736L);
        ok(atCall!=null && atCall.size()==1 &&
            atCall.get("D0")==0x40caL && !atCall.containsKey("A0"),
            "Disagreeing branch A0 must not invent a common argument");
        var disagree=new HardwareCallsiteRegisterFlow.Call(
            0x700,0x736,0x640L,atCall,false);
        var unknown=HardwareCallsiteRegisterFlow.analyze(
            List.of(disagree),List.of(callee),Set.of(simcr,cs),8);
        ok(unknown.possibleStoreSites()==0 &&
            unknown.unresolvedAliases()==1 &&
            unknown.candidates().isEmpty(),
            "Unagreed pointer across CFG branches resolves no MMIO alias");
        var noTarget=new HardwareCallsiteRegisterFlow.Call(
            0x780,0x784,null,Map.of("A0",simcr,"D0",0x40caL),false);
        var incomplete=new HardwareCallsiteRegisterFlow.Call(
            0x800,0x804,0x640L,Map.of("A0",simcr),true);
        var missing=HardwareCallsiteRegisterFlow.analyze(
            List.of(noTarget,incomplete),List.of(callee),Set.of(simcr),8);
        ok(missing.rejectedMissingCallee()==1 &&
            missing.rejectedIncomplete()==1 &&
            missing.candidates().isEmpty(),
            "Unresolved direct CALL and truncated caller remain UNKNOWN");
        var nested=new HardwareCallsiteRegisterFlow.Callee(
            0x640,List.of(
                new HardwareDataflow.Step(0x640,CALL_BARRIER,null,0,0,null,0,
                    List.of(0x646L),"JSR"),
                new HardwareDataflow.Step(0x646,STORE_INDIRECT,"A0","D0",
                    0,0,null,16,List.of(0x648L),"MOVE.W"),
                ret(0x648)),true);
        var bad=HardwareCallsiteRegisterFlow.analyze(
            List.of(left),List.of(nested),Set.of(simcr),8);
        ok(bad.rejectedNestedOrBadCfg()==1 && bad.candidates().isEmpty(),
            "Nested CALL must not become a transitive verified write");
        var split=HardwareCallsiteRegisterFlow.analyze(
            List.of(left,right),List.of(callee),Set.of(simcr,cs),1);
        ok(split.possibleStoreSites()==2 && split.candidates().size()==1 &&
            split.omittedRows() && split.markdown().contains("INCOMPLETE DISPLAY"),
            "Output cap never becomes completed proof of no other writes");
        var noRegisters=new HardwareCallsiteRegisterFlow.Call(
            0x900,0x904,0x640L,Map.of(),false);
        var noEvidence=HardwareCallsiteRegisterFlow.analyze(
            List.of(noRegisters),List.of(callee),Set.of(simcr),8);
        ok(noEvidence.contextCalls()==0 && noEvidence.candidates().isEmpty(),
            "No agreed argument registers -> no derived MMIO address");
        rejects(()->new HardwareCallsiteRegisterFlow.Call(
            0x900,0x904,0x640L,Map.of("SP",simcr),false),
            "Non A/D register injection rejected");
        rejects(()->new HardwareCallsiteRegisterFlow.Call(
            0x900,0x904,0x640L,Map.of("A0",0x1000000L),false),
            "Out-of-range MCU24 argument rejected");
        rejects(()->HardwareCallsiteRegisterFlow.analyze(
            List.of(left,left),List.of(callee),Set.of(simcr),8),
            "Duplicate CALL PC must be rejected");
        rejects(()->HardwareDataflow.analyzeWithEntryRegisters(
            0x640,callee.steps(),Set.of(simcr),500,Map.of("A9",simcr)),
            "Contextual CFG only accepts A0-A7/D0-D7");
        ok(results.candidates().stream().allMatch(r->
            !r.priorUnknownCall() && !r.priorUnknownStore()),
            "No fabricated unknown-effects conclusions in clean source");
        // The CALL source budgets covered call PCs/steps, but not the
        // candidate address collection or number of decoded callees.
        // An incomplete null/foreign-address set must not be silently
        // interpreted as the exhaustive set of MC68332 MMIO registers.
        rejects(()->HardwareCallsiteRegisterFlow.analyze(
            List.of(left),List.of(callee),
            java.util.Arrays.asList(simcr,(Long)null),8),
            "unknown tracked MMIO address must reject one-hop evidence");
        rejects(()->HardwareCallsiteRegisterFlow.analyze(
            List.of(left),List.of(callee),Set.of(0x1000000L),8),
            "foreign 25-bit MMIO address rejected for MC68332");
        rejects(()->HardwareCallsiteRegisterFlow.analyze(
            List.of(left),List.of(callee),Set.of(-1L),8),
            "negative tracked MMIO address cannot be reinterpreted");
        rejects(()->HardwareCallsiteRegisterFlow.analyze(
            List.of(left),java.util.Collections.nCopies(
                HardwareCallsiteRegisterFlow.MAX_CALL_SITES+1,callee),
            Set.of(simcr),8),
            "unbounded callee descriptors rejected before graph allocation");
        var exactBudget=new java.util.ArrayList<Long>();
        exactBudget.add(simcr); exactBudget.add(cs);
        for(long address=0;address<
                HardwareCallsiteRegisterFlow.MAX_TRACKED_ADDRESSES-2;
                address++)exactBudget.add(address);
        var atLimit=HardwareCallsiteRegisterFlow.analyze(
            List.of(left),List.of(callee),exactBudget,8);
        ok(atLimit.possibleStoreSites()==1 &&
            atLimit.candidates().get(0).address()==simcr,
            "exact 4096 valid target budget preserves source candidate");
        exactBudget.add(0x1000L);
        rejects(()->HardwareCallsiteRegisterFlow.analyze(
            List.of(left),List.of(callee),exactBudget,8),
            "4097 tracked addresses reject without truncation");
        ok(results.candidates().size()==2 &&
            results.candidates().get(0).address()==simcr,
            "invalid external inputs never mutate previously returned rows");
        // A byte count missing from p-code at a known A0 start address
        // cannot prove the write misses SIMCR. The start is not a tracked
        // register, but an unknown-sized write may span the MM low byte.
        var unmodeledWidth=new HardwareCallsiteRegisterFlow.Callee(
            0x640,List.of(new HardwareDataflow.Step(
                0x640,STORE_INDIRECT,"A0","D0",0,0,null,0,
                List.of(0x642L),"MOVE.UNKNOWN"),ret(0x642)),true);
        var nearMm=new HardwareCallsiteRegisterFlow.Call(
            0xa00,0xa0c,0x640L,
            Map.of("A0",0xfff9feL,"D0",0x40caL),false);
        var unknownWidth=HardwareCallsiteRegisterFlow.analyze(
            List.of(nearMm),List.of(unmodeledWidth),Set.of(simcr),8);
        ok(unknownWidth.unresolvedAliases()==1 &&
            unknownWidth.possibleStoreSites()==0 &&
            unknownWidth.candidates().isEmpty() &&
            unknownWidth.markdown().contains("unknown STORE aliases: 1"),
            "unknown-width contextual STORE outside tracked start stays UNKNOWN");
        var impossibleWidth=new HardwareCallsiteRegisterFlow.Callee(
            0x640,List.of(new HardwareDataflow.Step(
                0x640,STORE_INDIRECT,"A0","D0",0,0,null,64,
                List.of(0x642L),"MOVE.UNMODELED"),ret(0x642)),true);
        var unknown64=HardwareCallsiteRegisterFlow.analyze(
            List.of(nearMm),List.of(impossibleWidth),Set.of(simcr),8);
        ok(unknown64.unresolvedAliases()==1 &&
            unknown64.candidates().isEmpty(),
            "unmodeled 64-bit p-code STORE cannot become a negative MMIO claim");
        var spanningLong=new HardwareCallsiteRegisterFlow.Callee(
            0x640,List.of(new HardwareDataflow.Step(
                0x640,STORE_INDIRECT,"A0","D0",0,0,null,32,
                List.of(0x642L),"MOVE.L"),ret(0x642)),true);
        var longWrite=HardwareCallsiteRegisterFlow.analyze(
            List.of(nearMm),List.of(spanningLong),Set.of(simcr),8);
        ok(longWrite.unresolvedAliases()==0 &&
            longWrite.possibleStoreSites()==1 &&
            longWrite.candidates().size()==1 &&
            longWrite.candidates().get(0).address()==0xfff9feL &&
            longWrite.candidates().get(0).writeBits()==32 &&
            longWrite.candidates().get(0).writtenWord()==null,
            "known 32-bit STORE spanning SIMCR MM byte is a possible source");
        var narrowByte=new HardwareCallsiteRegisterFlow.Callee(
            0x640,List.of(new HardwareDataflow.Step(
                0x640,STORE_INDIRECT,"A0","D0",0,0,null,8,
                List.of(0x642L),"MOVE.B"),ret(0x642)),true);
        var byteWrite=HardwareCallsiteRegisterFlow.analyze(
            List.of(nearMm),List.of(narrowByte),Set.of(simcr),8);
        ok(byteWrite.unresolvedAliases()==0 &&
            byteWrite.possibleStoreSites()==0 &&
            byteWrite.candidates().isEmpty(),
            "known 8-bit STORE not spanning MM remains excluded");
        // A known MOVE.L at CSBAR-2 includes the tracked CSBAR base
        // even though its starting address is not in the MMIO catalog.
        // This source is a MAY-alias, never an observed CSBAR value.
        var beforeCs=new HardwareCallsiteRegisterFlow.Call(
            0xb00,0xb0c,0x640L,
            Map.of("A0",0xfffa66L,"D0",0x1234L),false);
        var crossingCs=HardwareCallsiteRegisterFlow.analyze(
            List.of(beforeCs),List.of(spanningLong),Set.of(cs),8);
        ok(crossingCs.possibleStoreSites()==1 &&
            crossingCs.unresolvedAliases()==0 &&
            crossingCs.candidates().size()==1 &&
            crossingCs.candidates().get(0).address()==0xfffa66L &&
            crossingCs.candidates().get(0).writeBits()==32 &&
            crossingCs.candidates().get(0).writtenWord()==null,
            "one-hop long STORE before tracked CSBAR base is a possible alias");
        var beforeCsByte=HardwareCallsiteRegisterFlow.analyze(
            List.of(beforeCs),List.of(narrowByte),Set.of(cs),8);
        ok(beforeCsByte.possibleStoreSites()==0 &&
            beforeCsByte.candidates().isEmpty(),
            "byte STORE before CSBAR with no overlap remains excluded");
        var unrelatedTracked=HardwareCallsiteRegisterFlow.analyze(
            List.of(beforeCs),List.of(spanningLong),Set.of(simcr),8);
        ok(unrelatedTracked.possibleStoreSites()==0 &&
            unrelatedTracked.candidates().isEmpty(),
            "known-width spanning STORE cannot hit a distant tracked register");
        // The CPU32 external address bus wraps after 0xFFFFFF. The third
        // byte of a MOVE.L starting 0xFFFFFE touches tracked 0x000000.
        var atBusEnd=new HardwareCallsiteRegisterFlow.Call(
            0xb40,0xb4c,0x640L,
            Map.of("A0",0xfffffeL,"D0",0x1234L),false);
        var wrappedTracked=HardwareCallsiteRegisterFlow.analyze(
            List.of(atBusEnd),List.of(spanningLong),Set.of(0L),8);
        ok(wrappedTracked.possibleStoreSites()==1 &&
            wrappedTracked.candidates().size()==1 &&
            wrappedTracked.candidates().get(0).address()==0xfffffeL,
            "known 32-bit STORE wraps to tracked MCU24 address zero");
        ok(!HardwareDataflow.mayTouchTrackedAddress(0xfffffeL,8,Set.of(0L)) &&
            HardwareDataflow.mayTouchTrackedAddress(0xfffffeL,32,Set.of(0L)) &&
            !HardwareDataflow.mayTouchTrackedAddress(0xfffffeL,0,Set.of(0L)),
            "byte overlap uses known widths only and never invents unknown width");

        // Public source records must not mint CALL/STORE evidence from
        // unaligned or foreign-width instruction coordinates.
        rejects(()->new HardwareCallsiteRegisterFlow.Call(
            0x100,0x103,0x640L,Map.of(),false),
            "odd CALL PC cannot be represented as verified CPU32 source");
        rejects(()->new HardwareCallsiteRegisterFlow.Call(
            0x1000000L,0x1000002L,0x640L,Map.of(),false),
            "25-bit caller source cannot enter the MC68332 lane");
        rejects(()->new HardwareCallsiteRegisterFlow.Call(
            0x100,0x104,0x641L,Map.of(),false),
            "odd direct callee is not an exact CPU32 function entry");
        rejects(()->new HardwareCallsiteRegisterFlow.Callee(
            0x641,callee(0x640),true),
            "odd callee entry cannot authenticate another body");
        rejects(()->new HardwareCallsiteRegisterFlow.Callee(
            0x640,List.of(new HardwareDataflow.Step(
                0x1000000L,OTHER,null,0,0,null,0,List.of(),"RTS")),false),
            "foreign-width callee instruction cannot enter source inventory");
        rejects(()->new HardwareCallsiteRegisterFlow.Callee(
            0x640,List.of(new HardwareDataflow.Step(
                0x640,OTHER,null,0,0,null,0,List.of(0x643L),"NOP")),false),
            "odd CFG successor cannot be published as an instruction PC");
        rejects(()->new HardwareCallsiteRegisterFlow.Candidate(
            0x600,0x60c,0x640,0x640,OTHER,simcr,0x40ca,16,
            false,false,2),
            "non-STORE operation cannot be constructed as MMIO candidate");
        rejects(()->new HardwareCallsiteRegisterFlow.Candidate(
            0x600,0x60c,0x640,0x641,STORE_INDIRECT,simcr,0x40ca,16,
            false,false,2),
            "odd STORE PC cannot be constructed as source evidence");
        rejects(()->new HardwareCallsiteRegisterFlow.Summary(
            1,1,0,0,0,0,0,0,0,false,List.of(a)),
            "summary cannot claim fewer possible stores than retained rows");
        rejects(()->new HardwareCallsiteRegisterFlow.Summary(
            -1,0,0,0,0,0,0,0,0,false,List.of()),
            "negative public source counters cannot be published");

        System.out.println("HardwareCallsiteRegisterFlowSelfTest PASS: assertions="+assertions);
    }
}
