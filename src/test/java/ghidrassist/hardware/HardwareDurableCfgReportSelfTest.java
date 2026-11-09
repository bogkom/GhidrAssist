package ghidrassist.hardware;

import java.util.*;
import static ghidrassist.hardware.HardwareDurableCfgReport.*;

public final class HardwareDurableCfgReportSelfTest {
    private HardwareDurableCfgReportSelfTest(){}
    private static void ok(boolean b,String message){
        if(!b)throw new AssertionError(message);
    }
    public static void main(String[] args)throws Exception{
        var original=new Snapshot("## bounded CFG\nsynthetic only",
            "fn,pc,register\n0x100,0x102,SIMCR\n",
            2,1,0,1,42,false,true,true,false,
            7L,8L,
            List.of(new Site(0x100,0x102,"SIMCR",0xfffa00L,
                true,16,0x40ca,0,1,true,false,false),
                new Site(0x130,0x134,"UNRESOLVED_ALIAS",-1L,
                true,0,null,0,2,true,true,true)),
            List.of(new Role(0x100,"FUN_100","A0","SIM",
                1,2,3,"PATH_UNCERTAIN","")),
            List.of(0x100L,0x130L));
        byte[] data=encode(original);
        ok(decode(data).orElseThrow().equals(original),
            "full report fields survive roundtrip without Java object deserialization");
        byte[] damaged=data.clone();
        damaged[2]^=0x30;
        ok(decode(damaged).isEmpty(),"schema change rejects snapshot");
        ok(decode(Arrays.copyOf(data,data.length-2)).isEmpty(),
            "truncation rejects partially read roles/reset entries");
        byte[] extra=Arrays.copyOf(data,data.length+1);
        ok(decode(extra).isEmpty(),"extra trailing fields rejected");
        ok(decode(new byte[0]).isEmpty(),"missing snapshot rejected");
        ok(decode(new byte[8]).isEmpty(),"untrusted tiny binary rejected");
        boolean failed=false;
        try{new Snapshot("x","x",-1,0,0,0,0,false,false,false,
            false,0,0,List.of(),List.of(),List.of());}
        catch(IllegalArgumentException e){failed=true;}
        ok(failed,"negative counters rejected");
        var none=new Snapshot("## no sites","",0,0,0,0,0,
            true,false,true,false,0,0,List.of(),List.of(),List.of());
        ok(decode(encode(none)).orElseThrow().equals(none),
            "empty lists and incomplete markers preserved");
        // GA-12: even schema-valid, checksum-protected payloads are NOT
        // eligible as "completed" checkpoints when evidence was omitted.
        var complete=new Snapshot("## complete real synthetic CFG", "fn,pc\n",
            2,0,0,0,2,false,true,false,true,0,0,
            List.of(),List.of(),List.of(0x100L));
        ok(eligibleForCompletedRestore(complete) &&
            eligibleForCompletedRestore(decode(encode(complete)).orElseThrow()),
            "completed source set is eligible after strict binary roundtrip");
        var omitted=new Snapshot(complete.markdown(),complete.csv(),
            complete.functions(),complete.indirect(),complete.vbr(),
            complete.unresolved(),complete.visited(),false,true,false,true,
            1,0,complete.sites(),complete.roles(),complete.resetFunctions());
        ok(decode(encode(omitted)).isPresent() &&
            !eligibleForCompletedRestore(omitted) &&
            !eligibleForCompletedRestore(decode(encode(omitted)).orElseThrow()),
            "valid checksum with missing CFG sites must not restore as complete");
        var omittedPointers=new Snapshot(complete.markdown(),complete.csv(),
            complete.functions(),complete.indirect(),complete.vbr(),
            complete.unresolved(),complete.visited(),false,true,false,true,
            0,1,complete.sites(),complete.roles(),complete.resetFunctions());
        ok(!eligibleForCompletedRestore(omittedPointers),
            "omitted pointer provenance cannot be certified completed");
        var stopped=new Snapshot(complete.markdown(),complete.csv(),
            complete.functions(),complete.indirect(),complete.vbr(),
            complete.unresolved(),complete.visited(),true,true,false,true,
            0,0,complete.sites(),complete.roles(),complete.resetFunctions());
        ok(!eligibleForCompletedRestore(stopped) &&
            !eligibleForCompletedRestore(original) &&
            !eligibleForCompletedRestore(none),
            "partial analysis and interrupted checkpoint never restored complete");
        ok(!eligibleForCompletedRestore(null),
            "null checkpoint is not evidence");
        // V2 persists only bounded immutable typed source witnesses, not
        // a Markdown-parsed approximation or an Apply/GUI authorization.
        var sources=new HardwareResetIndirectVbrCorrelation.SourceInventory(
            List.of(new HardwareResetIndirectVbrCorrelation.Indirect(
                0x130L,0x138L,0x180L,true,false),
                new HardwareResetIndirectVbrCorrelation.Indirect(
                0x200L,0x206L,0x180L,true,false)),
            List.of(new HardwareResetIndirectVbrCorrelation.Vbr(
                0x130L,0x144L,null,true),
                new HardwareResetIndirectVbrCorrelation.Vbr(
                0x200L,0x208L,null,true)),
            Set.of(0x100L,0x130L),true,false,1,2);
        var typed=new Snapshot(complete.markdown(),complete.csv(),
            complete.functions(),complete.indirect(),complete.vbr(),
            complete.unresolved(),complete.visited(),
            complete.limited(),complete.resetRecognized(),
            complete.resetIncomplete(),complete.cfgReviewComplete(),
            complete.cfgOmitted(),complete.pointersOmitted(),
            complete.sites(),complete.roles(),complete.resetFunctions(),sources);
        var decoded=decode(encode(typed)).orElseThrow();
        ok(decoded.equals(typed) &&
            decoded.sourceInventory()!=null &&
            decoded.sourceInventory().page(0,1).colocatedPairs()==2 &&
            decoded.sourceInventory().page(1,1).rows().size()==1 &&
            decoded.sourceInventory().page(2,1).rows().isEmpty() &&
            decoded.sourceInventory().omittedIndirect()==1 &&
            decoded.sourceInventory().omittedVbr()==2,
            "V2 typed JSR/MOVEC full source inventory survives binary roundtrip");
        ok(eligibleForCompletedRestore(decoded),
            "V2 complete CFG keeps strict original restore eligibility");
        byte[] v2=encode(complete); // No optional source inventory.
        byte[] v1=Arrays.copyOf(v2,v2.length-1);
        byte[] schema=SCHEMA.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        v1[4+schema.length-1]=(byte)'1';
        var old=decode(v1).orElseThrow();
        ok(old.sourceInventory()==null && old.markdown().equals(complete.markdown()) &&
            eligibleForCompletedRestore(old),
            "Legacy GA12-CFG-REPORT-1 decodes as CFG only without fabricated JSR sources");
        ok(decode(Arrays.copyOf(encode(typed),encode(typed).length-1)).isEmpty(),
            "Truncated V2 typed sources must never decode as complete");
        byte[] corrupt=encode(typed);
        corrupt[4+schema.length-1]='3';
        ok(decode(corrupt).isEmpty(),
            "Unknown future report schema must fail closed");
        byte[] v1Extra=Arrays.copyOf(v1,v1.length+1);
        ok(decode(v1Extra).isEmpty(),"V1 extra fields refused");
        System.out.println("HardwareDurableCfgReportSelfTest OK");
    }
}
