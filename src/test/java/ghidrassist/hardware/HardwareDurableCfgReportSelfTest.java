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
        System.out.println("HardwareDurableCfgReportSelfTest OK");
    }
}
