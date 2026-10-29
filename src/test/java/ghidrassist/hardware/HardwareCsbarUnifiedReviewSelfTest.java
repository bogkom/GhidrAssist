package ghidrassist.hardware;

import java.util.List;

public final class HardwareCsbarUnifiedReviewSelfTest {
    private static void check(boolean yes,String reason){
        if(!yes)throw new AssertionError(reason);
    }
    private static HardwareStartupEvidenceMerge.Observation observation(
            long pc,long addr,String register,
            HardwareStartupEvidenceMerge.Source source,
            boolean write,int bits,Integer word,boolean unknown){
        return new HardwareStartupEvidenceMerge.Observation(
            0x2bc0,pc,addr,register,source,write,bits,word,unknown);
    }
    public static void main(String[] args){
        var listing=HardwareStartupEvidenceMerge.Source.LISTING_REFERENCE;
        var cfg=HardwareStartupEvidenceMerge.Source.CFG_PCODE;
        var source=List.of(
            observation(0x2bca,0xfffa4c,"CSBAR0",listing,true,16,0xf803,false),
            observation(0x2bca,0xfffa4c,"CSBAR0",cfg,true,16,0xf803,false),
            observation(0x2bd0,0xfffa50,"CSBAR1",listing,true,16,0xff00,false),
            observation(0x2bd4,0xfffa50,"CSBAR1",cfg,true,16,0x1234,false),
            observation(0x2bd8,0xfffa54,"CSBAR2",cfg,true,8,null,false),
            observation(0x2bdc,0x7ffa58,"CSBAR3",cfg,true,16,0xf803,false),
            observation(0x2be0,0xfffa60,"CSBAR5",cfg,true,16,0xf803,true));
        var reconciled=HardwareStartupEvidenceMerge.reconcile(source);
        var result=HardwareCsbarUnifiedReview.inspect(true,reconciled);
        check(result.candidates().size()==1 &&
            result.candidates().get(0).register().equals("CSBAR0") &&
            result.candidates().get(0).word()==0xf803 &&
            result.candidates().get(0).independentSiteCount()==1,
            "only exact duplicate sources and safe candidate survive");
        check(result.uncertainSites()>=2,
            "partial-width and unknown-call sites are unsafe");
        check(result.summary().contains("actual chip-select assertion UNKNOWN"),
            "no assertion of active hardware selection");
        var alias=HardwareStartupEvidenceMerge.reconcile(
            new java.util.ArrayList<>() {{
                addAll(source);
                add(observation(0x2be4,-1,"UNRESOLVED_ALIAS",
                    cfg,true,0,null,true));
            }});
        var blocked=HardwareCsbarUnifiedReview.inspect(true,alias);
        check(blocked.candidates().isEmpty() &&
            blocked.unresolvedAliasWrites()==1,
            "unknown target can alias any CSBAR, block whole proposal set");
        check(HardwareCsbarUnifiedReview.inspect(false,reconciled)
            .candidates().isEmpty(),"generic CPU32 cannot propose MC68332 CSBAR");
        check(HardwareCsbarUnifiedReview.inspect(true,
            HardwareStartupEvidenceMerge.reconcile(List.of(
                observation(0x2be8,0xfffa4c,"CSBAR0",cfg,true,0,null,true))))
            .candidates().isEmpty(),
            "unknown-width source must poison register");
        var readOnly=HardwareCsbarUnifiedReview.inspect(true,
            HardwareStartupEvidenceMerge.reconcile(List.of(
                observation(0x2bea,0xfffa4c,"CSBAR0",listing,false,0,null,false))));
        check(readOnly.candidates().isEmpty(),"read is not evidence of CSBAR initialization");
        boolean immutable=false;
        try{result.candidates().clear();}
        catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"cannot mutate reviewed results");
        System.out.println("HardwareCsbarUnifiedReviewSelfTest OK");
    }
}
