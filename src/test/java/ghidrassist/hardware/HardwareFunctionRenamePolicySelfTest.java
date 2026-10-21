package ghidrassist.hardware;

import java.util.List;

public final class HardwareFunctionRenamePolicySelfTest {
    private static void ok(boolean v,String why){if(!v)throw new AssertionError(why);}
    private static HardwareFunctionNamingReview.Observation write(long pc,String reg){
        return new HardwareFunctionNamingReview.Observation(0x1200L,
            "FUN_00001200",pc,reg,true);
    }
    public static void main(String[] args) {
        var p=HardwareFunctionNamingReview.propose(true,List.of(
            write(0x1200,"CSPAR0"),write(0x1202,"CSBAR0"),
            write(0x1204,"CSOR0")),List.of()).get(0);
        ok(HardwareFunctionRenamePolicy.check(p,p.currentName,List.of()) ==
            HardwareFunctionRenamePolicy.Decision.READY,"valid reviewed function");
        ok(HardwareFunctionRenamePolicy.check(p,"custom_user_name",List.of()) ==
            HardwareFunctionRenamePolicy.Decision.NAME_CHANGED,"stale/user name rejected");
        ok(HardwareFunctionRenamePolicy.check(p,p.currentName,
            List.of(p.proposedName.toLowerCase(java.util.Locale.ROOT))) ==
            HardwareFunctionRenamePolicy.Decision.NAME_COLLISION,
            "case-insensitive collision rejected");
        var family=HardwareFunctionNamingReview.propose(false,List.of(
            write(0x1200,"CSPAR0"),write(0x1202,"CSBAR0"),
            write(0x1204,"CSOR0")),List.of()).get(0);
        ok(HardwareFunctionRenamePolicy.check(family,family.currentName,List.of()) ==
            HardwareFunctionRenamePolicy.Decision.WEAK_OR_UNREVIEWED,
            "generic CPU32 cannot apply a model-specific rename");
        ok(HardwareFunctionRenamePolicy.check(null,"FUN_00001200",List.of()) ==
            HardwareFunctionRenamePolicy.Decision.INVALID,"null proposal");
        System.out.println("HardwareFunctionRenamePolicySelfTest OK");
    }
}
