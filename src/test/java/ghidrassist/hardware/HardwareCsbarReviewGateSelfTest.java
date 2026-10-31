package ghidrassist.hardware;

import java.util.List;
public final class HardwareCsbarReviewGateSelfTest {
    private HardwareCsbarReviewGateSelfTest(){}
    private static void ok(boolean x,String reason){if(!x)throw new AssertionError(reason);}
    private static HardwareCsbarReviewGate.Source ref(String fn,String reg,long addr,
            boolean write,Integer value){
        return new HardwareCsbarReviewGate.Source(fn,reg,addr,write,value);
    }
    public static void main(String[] args){
        var input=List.of(
            ref("reset","CSBAR0",0xfffa4c,true,0xf803),
            ref("later","CSBAR0",0xfffa4c,true,0xf803),
            ref("conditional","CSBAR1",0xfffa50,true,0xf803),
            ref("alternative","CSBAR1",0xfffa50,true,0xff88),
            ref("reset","CSBAR7",0xfffa68,true,null),
            ref("reset","CSBAR10",0xfffa74,true,0xff88),
            ref("reset","CSBARBT",0xfffa48,true,0xf803),
            ref("wrong-MM","CSBAR0",0x7ffa4c,true,0x1234),
            ref("wrong-MM","CSBAR2",0x7ffa54,true,0x1234),
            ref("register-ref","CSOR0",0xfffa4e,true,0x7c30),
            ref("read-only","CSBAR6",0xfffa64,false,null));
        var result=HardwareCsbarReviewGate.reviewCandidates(input);
        ok(result.candidates().size()==3 &&
            result.candidates().stream().anyMatch(x->x.register().equals("CSBAR0") &&
                x.word()==0xf803 && x.independentSiteCount()==2) &&
            result.candidates().stream().anyMatch(x->x.register().equals("CSBARBT")) &&
            result.candidates().stream().anyMatch(x->x.register().equals("CSBAR10")),
            "only unambiguous exact MM1 source candidates");
        ok(result.conflictedRegisters()==1 &&
            result.unknownWriteRegisters()==1 &&
            result.excludedWrongWindow()==3,
            "conflicting, unknown and MM0 sources fail closed");
        ok(result.candidates().stream().noneMatch(x->
            x.register().equals("CSBAR1") || x.register().equals("CSBAR7")),
            "no lexical last-write-wins with CSBAR in Review");
        ok(result.explanation().contains("manual review") &&
            result.explanation().contains("do NOT establish"),
            "approval gate never certifies physical configuration");
        boolean immutable=false;
        try{result.candidates().clear();}
        catch(UnsupportedOperationException expected){immutable=true;}
        ok(immutable,"candidate output immutable");
        boolean failed=false;
        try{HardwareCsbarReviewGate.reviewCandidates(null);}
        catch(IllegalArgumentException expected){failed=true;}
        ok(failed,"missing source is not successful empty review");
        System.out.println("HardwareCsbarReviewGateSelfTest OK");
    }
}
