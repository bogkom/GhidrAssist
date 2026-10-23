package ghidrassist.hardware;

import java.util.List;
import java.util.Map;

/** Conservative preview checks: never tests application of names. */
public final class HardwareNamingReviewSelfTest {
    static void ok(boolean v,String reason) {
        if(!v)throw new AssertionError(reason);
    }
    public static void main(String[] args){
        Map<Long,String> names=Map.of(0xfffa00L,"SIMCR",0xfffa68L,"CSBAR7",
            0xfffa6aL,"CSOR7",0xfffa04L,"SYNCR");
        Map<Long,String> existing=Map.of(0xfffa04L,"SYNCR",0xfffa00L,"DAT_00fffa00");
        Map<Long,Integer> counts=Map.of(0xfffa00L,3,0xfffa68L,3,0xfffa6aL,1,0xfffa04L,6);
        var family=HardwareNamingReview.propose(false,"MC68332",names,existing,counts,List.of());
        ok(family.stream().allMatch(x->x.proposed.isEmpty()&&
            x.status==HardwareNamingReview.Status.FAMILY_UNCERTAIN),
            "generic CPU32 cannot propose MC68332 labels");
        var manual=HardwareNamingReview.propose(true,"MC68332",names,existing,counts,
            List.of("CSBAR7","SYNCR"));
        ok(manual.stream().filter(x->x.register.equals("SIMCR")).findFirst()
            .orElseThrow().status==HardwareNamingReview.Status.REVIEW_REQUIRED,
            "provisional manual profile permits preview only");
        ok(manual.stream().filter(x->x.register.equals("CSBAR7")).findFirst()
            .orElseThrow().status==HardwareNamingReview.Status.NAME_COLLISION,
            "collisions must be blocked");
        ok(manual.stream().filter(x->x.register.equals("CSOR7")).findFirst()
            .orElseThrow().status==HardwareNamingReview.Status.EVIDENCE_TOO_WEAK,
            "single candidate is not enough to propose");
        ok(manual.stream().filter(x->x.register.equals("SYNCR")).findFirst()
            .orElseThrow().status==HardwareNamingReview.Status.ALREADY_NAMED,
            "respect user symbols");
        String csv=HardwareNamingReview.toCsv(manual);
        ok(csv.contains("REVIEW_REQUIRED") && !csv.contains("setName("),
            "review-only CSV");
        System.out.println("HardwareNamingReviewSelfTest OK");
    }
}
