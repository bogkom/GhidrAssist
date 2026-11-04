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
        System.out.println("HardwareDurableCfgReportSelfTest OK");
    }
}
