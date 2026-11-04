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
        System.out.println("HardwareCallsiteRegisterFlowSelfTest PASS: assertions="+assertions);
    }
}
