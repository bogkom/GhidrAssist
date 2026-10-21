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
        System.out.println("HardwareFunctionNamingReviewSelfTest OK");
    }
}
