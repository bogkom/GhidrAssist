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
        // Legacy seven-column REGISTER review CSV is also opened in
        // Excel/Calc; quoting does not neutralize formulas in symbol names.
        var unsafe=HardwareNamingReview.propose(true,"\u2060=SUM(1,2)",
            Map.of(0xfffa00L,"=HYPERLINK(1)"),
            Map.of(0xfffa00L,"\u200D+1+1"),
            Map.of(0xfffa00L,4),List.of());
        String guarded=HardwareNamingReview.toCsv(unsafe);
        ok(guarded.contains("\"'\u200D+1+1\"") &&
            guarded.contains("\"'=HYPERLINK(1)\"") &&
            guarded.contains("\"'\u2060=SUM(1,2)\""),
            "review CSV escapes hidden Unicode/formula prefixes in all fields");
        ok(HardwareNamingReview.cell("  -3").equals("\"'  -3\"") &&
            HardwareNamingReview.cell("ordinary_name").equals("\"ordinary_name\""),
            "blank-leading formula rejected but harmless names unchanged");
        String supplementary=new String(Character.toChars(0xE0001));
        ok(HardwareNamingReview.cell(supplementary+"@SUM(1,2)")
            .equals("\"'"+supplementary+"@SUM(1,2)\""),
            "supplementary Unicode format prefix cannot hide a formula");
        int clip=HardwareNamingReview.MAX_CSV_CELL_CHARS-
            " [SOURCE_TRUNCATED]".length();
        String splitPair="A".repeat(clip-1)+"\uD83D\uDE00"+"Z".repeat(100);
        String clipped=HardwareNamingReview.cell(splitPair);
        ok(clipped.contains("SOURCE_TRUNCATED") &&
            clipped.length()<=HardwareNamingReview.MAX_CSV_CELL_CHARS+2 &&
            !clipped.contains("\uD83D") && !clipped.contains("\uDE00"),
            "bounded CSV text must not split a supplementary code point");
        System.out.println("HardwareNamingReviewSelfTest OK");
    }
}
