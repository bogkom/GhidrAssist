package ghidrassist.hardware;

import java.util.List;

public final class HardwarePointerRoleReviewSelfTest {
    private static void check(boolean b,String s){if(!b)throw new AssertionError(s);}
    private static HardwarePointerRoleReview.Site hit(long pc,String target,boolean uncertain){
        return new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",pc,
            "A0","SIM",1,target,uncertain);
    }
    public static void main(String[] args){
        var sites=List.of(hit(0x2bd0,"CSBAR0",false),
            hit(0x2bca,"SIMCR",false),hit(0x2bca,"SIMCR",false));
        var hints=HardwarePointerRoleReview.propose(true,sites,false);
        check(hints.size()==1 && hints.get(0).sites()==2 &&
            hints.get(0).registers()==2,"deduplicate sources and targets");
        check(hints.get(0).status()==HardwarePointerRoleReview.Status.REVIEW_ONLY &&
            hints.get(0).hint().equals("p_hw_sim_mm1_candidate"),"only hint, not symbol");
        check(HardwarePointerRoleReview.csvRows(hints).contains("NEVER_AUTO_APPLY"),
            "CSV cannot silently become Apply item");
        check(HardwarePointerRoleReview.report(hints).contains("No pointer/variable rename"),
            "no invented HighVariable identity");
        check(HardwarePointerRoleReview.propose(false,sites,false).get(0).status()
            ==HardwarePointerRoleReview.Status.FAMILY_UNCERTAIN,"CPU32 no device hints");
        check(HardwarePointerRoleReview.propose(true,sites,true).get(0).status()
            ==HardwarePointerRoleReview.Status.PATH_UNCERTAIN,"truncation must block");
        check(HardwarePointerRoleReview.propose(true,
            List.of(hit(0x2bca,"SIMCR",false),hit(0x2bcc,"CSBAR0",true)),false)
            .get(0).status()==HardwarePointerRoleReview.Status.PATH_UNCERTAIN,
            "unknown-call/STORE barrier blocks");
        check(HardwarePointerRoleReview.propose(true,
            List.of(hit(0x2bca,"SIMCR",false),hit(0x2bcc,"SIMCR",false)),false)
            .get(0).status()==HardwarePointerRoleReview.Status.WEAK_EVIDENCE,
            "repeated same-target access weak");
        check(HardwarePointerRoleReview.propose(true,
            List.of(hit(0x2bca,"SIMCR",false)),false).isEmpty(),"single site omitted");
        boolean immutable=false;
        try{hints.clear();}catch(UnsupportedOperationException ex){immutable=true;}
        check(immutable,"result immutable");
        System.out.println("HardwarePointerRoleReviewSelfTest OK");
    }
}
