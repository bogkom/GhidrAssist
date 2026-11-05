package ghidrassist.hardware;

import java.util.List;
import java.util.ArrayList;

public final class HardwareFunctionNamingReviewSelfTest {
    private static void ok(boolean v,String why){if(!v)throw new AssertionError(why);}
    private static HardwareFunctionNamingReview.Observation obs(long function,
            long pc,String register,boolean write,String name) {
        return new HardwareFunctionNamingReview.Observation(
            function,name,pc,register,write);
    }
    public static void main(String[] args) {
        var writes=List.of(
            obs(0x1000,0x1000,"CSPAR1",true,"FUN_00001000"),
            obs(0x1000,0x1002,"CSBAR7",true,"FUN_00001000"),
            obs(0x1000,0x1004,"CSOR7",true,"FUN_00001000"),
            obs(0x1000,0x1004,"CSOR7",true,"FUN_00001000"),
            obs(0x1000,0x1006,"SIMCR",false,"FUN_00001000")
        );
        var proposals=HardwareFunctionNamingReview.propose(true,writes,List.of());
        ok(proposals.size()==1,"one function from distinct write sites");
        var p=proposals.get(0);
        ok(p.status==HardwareNamingReview.Status.REVIEW_REQUIRED &&
            p.role.equals("CONFIGURE_CHIP_SELECTS") &&
            p.writeSites==3 && p.proposedName.contains("00001000"),
            "role needs evidence of pin/base/option writes");
        ok(!p.registers.contains("SIMCR"),"reads do not count as writes");
        var family=HardwareFunctionNamingReview.propose(false,writes,List.of());
        ok(family.get(0).proposedName.isEmpty() &&
            family.get(0).status==HardwareNamingReview.Status.FAMILY_UNCERTAIN,
            "CPU32 cannot generate MCU-specific function names");
        var collision=HardwareFunctionNamingReview.propose(true,writes,
            List.of(p.proposedName));
        ok(collision.get(0).status==HardwareNamingReview.Status.NAME_COLLISION,
            "global symbol collision rejected");
        var already=List.of(
            obs(0x1000,0x1000,"CSPAR1",true,"user_name"),
            obs(0x1000,0x1002,"CSBAR7",true,"user_name"),
            obs(0x1000,0x1004,"CSOR7",true,"user_name"));
        ok(HardwareFunctionNamingReview.propose(true,already,List.of()).get(0)
            .status==HardwareNamingReview.Status.ALREADY_NAMED,
            "preserve existing function names");
        var weak=List.of(
            obs(0x2000,0x2000,"SIMCR",true,"FUN_00002000"),
            obs(0x2000,0x2002,"SYNCR",true,"FUN_00002000"));
        ok(HardwareFunctionNamingReview.propose(true,weak,List.of()).get(0)
            .status==HardwareNamingReview.Status.EVIDENCE_TOO_WEAK,
            "two write sites are insufficient");
        String csv=HardwareFunctionNamingReview.toCsvRows(proposals);
        ok(csv.contains("FUNCTION_ROLE:CONFIGURE_CHIP_SELECTS") &&
            csv.contains("REVIEW_REQUIRED") && !csv.contains("setName("),
            "single existing CSV schema and no renaming");
        // Function-role proposals share the seven-column register CSV.
        // Existing names can be user-defined or imported and must not
        // be treated as harmless spreadsheet text simply because quoted.
        var hostileNames=List.of(
            obs(0x3000,0x3000,"CSPAR1",true,"\u2060=HYPERLINK(1)"),
            obs(0x3000,0x3002,"CSBAR7",true,"\u2060=HYPERLINK(1)"),
            obs(0x3000,0x3004,"CSOR7",true,"\u2060=HYPERLINK(1)"));
        var hostile=HardwareFunctionNamingReview.propose(
            true,hostileNames,List.of());
        ok(hostile.size()==1 &&
            hostile.get(0).status==HardwareNamingReview.Status.ALREADY_NAMED,
            "untrusted manual/imported names must never auto-rename");
        String safe=HardwareFunctionNamingReview.toCsvRows(hostile);
        ok(safe.contains("\"'\u2060=HYPERLINK(1)\"") &&
            safe.contains("\"ALREADY_NAMED\"") &&
            safe.lines().count()==1,
            "function review CSV neutralizes format-hidden formula prefix");
        String giantName="=SUM(1,2)"+"Z".repeat(10000);
        var giant=HardwareFunctionNamingReview.propose(true,List.of(
            obs(0x4000,0x4000,"CSPAR1",true,giantName),
            obs(0x4000,0x4002,"CSBAR7",true,giantName),
            obs(0x4000,0x4004,"CSOR7",true,giantName)),List.of());
        String capped=HardwareFunctionNamingReview.toCsvRows(giant);
        ok(capped.contains("\"'=SUM(1,2)") &&
            capped.contains("SOURCE_TRUNCATED") &&
            capped.length()<1700,
            "oversized function symbol cannot produce an unbounded CSV cell");
        ok(HardwareFunctionNamingReview.toCsvRows(proposals).equals(csv),
            "normal register/function review rows remain byte-identical");
        // Third legacy naming export must not emit unlimited review rows.
        String atCap=HardwareFunctionNamingReview.toCsvRows(
            java.util.Collections.nCopies(
                HardwareFunctionNamingReview.MAX_CSV_ROWS,p));
        ok(atCap.lines().count()==HardwareFunctionNamingReview.MAX_CSV_ROWS &&
            !atCap.contains("INCOMPLETE_EXPORT_NEVER_AUTO_APPLY") &&
            !atCap.contains("OMITTED_ROWS="),
            "exactly 5000 valid rows are exported without false incompleteness");
        String omitted=HardwareFunctionNamingReview.toCsvRows(
            java.util.Collections.nCopies(
                HardwareFunctionNamingReview.MAX_CSV_ROWS+3,p));
        String last=omitted.lines().reduce((a,b)->b).orElse("");
        ok(omitted.lines().count()==HardwareFunctionNamingReview.MAX_CSV_ROWS+1 &&
            omitted.contains("OMITTED_ROWS=3") &&
            last.contains("INCOMPLETE_EXPORT_NEVER_AUTO_APPLY") &&
            last.split(",",-1).length==7 &&
            omitted.length()<2_500_000,
            "additional proposals capped with one seven-column incomplete row");
        boolean invalidCsv=false;
        try { HardwareFunctionNamingReview.toCsvRows(null); }
        catch(IllegalArgumentException expected){invalidCsv=true;}
        ok(invalidCsv,"null function CSV input rejected");
        invalidCsv=false;
        try { HardwareFunctionNamingReview.toCsvRows(
            java.util.Arrays.asList((HardwareFunctionNamingReview.Proposal)null)); }
        catch(IllegalArgumentException expected){invalidCsv=true;}
        ok(invalidCsv,"null row never treated as complete review evidence");
        // Contradictory function names at the same entry reflect stale or
        // mixed source snapshots, never a review-ready rename. Input order
        // must not decide which name wins.
        var conflicting=List.of(
            obs(0x5500,0x5500,"CSPAR1",true,"FUN_00005500"),
            obs(0x5500,0x5502,"CSBAR7",true,"user_changed_name"),
            obs(0x5500,0x5504,"CSOR7",true,"FUN_00005500"));
        var mixed=HardwareFunctionNamingReview.propose(true,conflicting,List.of());
        ok(mixed.size()==1 &&
            mixed.get(0).status==HardwareNamingReview.Status.EVIDENCE_TOO_WEAK &&
            mixed.get(0).proposedName.isEmpty() &&
            mixed.get(0).currentName.equals("[CONFLICTING_SOURCE_NAMES]") &&
            mixed.get(0).writeSites==3,
            "different names for same Ghidra function fail closed");
        var reversed=new java.util.ArrayList<>(conflicting);
        java.util.Collections.reverse(reversed);
        var mixedReversed=HardwareFunctionNamingReview.propose(
            true,reversed,List.of());
        ok(mixedReversed.get(0).status==HardwareNamingReview.Status.EVIDENCE_TOO_WEAK &&
            mixedReversed.get(0).currentName.equals("[CONFLICTING_SOURCE_NAMES]") &&
            mixedReversed.get(0).proposedName.isEmpty(),
            "conflicting source-name rejection is iteration-order independent");
        ok(HardwareFunctionNamingReview.toCsvRows(mixed).contains(
                "CONFLICTING_SOURCE_NAMES") &&
            !HardwareFunctionNamingReview.toCsvRows(mixed).contains(
                "REVIEW_REQUIRED"),
            "CSV preserves conflict marker but never exports an approved candidate");
        ok(HardwareFunctionNamingReview.propose(false,conflicting,List.of())
            .get(0).status==HardwareNamingReview.Status.FAMILY_UNCERTAIN,
            "generic CPU32 cannot promote even conflicting MC68332 evidence");
        System.out.println("HardwareFunctionNamingReviewSelfTest OK");
    }
}
