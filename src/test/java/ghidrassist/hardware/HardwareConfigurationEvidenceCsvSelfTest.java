package ghidrassist.hardware;
import java.util.List;

public final class HardwareConfigurationEvidenceCsvSelfTest {
    private static void check(boolean yes,String why){if(!yes)throw new AssertionError(why);}
    public static void main(String[] args){
        var report=HardwareCfgWriteAudit.inspect(true,List.of(
            new HardwareCfgWriteAudit.Site(0x2bc0,0x2bca,"SIMCR",0xfffa00,
                false,16,0x40ca,0,0,false,false,false),
            new HardwareCfgWriteAudit.Site(0x2bc0,0x2bcc,"CSBAR0",0xfffa4c,
                true,8,0x55,0,1,true,false,false),
            new HardwareCfgWriteAudit.Site(0x2bc0,0x2bce,"=INJECT",0xfffa4e,
                true,16,0x1234,0,0,false,false,false)));
        var relation=new HardwareCfgStorePaths.Pair(0x2bc0,0x2bca,0x2bcc,
            "SIMCR","CSBAR0",HardwareCfgStorePaths.Relationship.A_MAY_PRECEDE_B,true);
        String csv=HardwareConfigurationEvidenceCsv.serialize(report,List.of(relation),true);
        check(csv.startsWith(HardwareConfigurationEvidenceCsv.HEADER),
            "stable independent header");
        check(csv.contains("\"STORE\",\"0x00002BC0\",\"0x00002BCA\",\"SIMCR\"") &&
            csv.contains("\"0x40CA\"") && csv.contains("\"1 (STATIC_LITERAL_ONLY)\""),
            "source site with conditional MM literal only");
        check(csv.contains("\"CSBAR0\"") &&
            csv.contains("\"UNKNOWN\",\"POSSIBLE_MATCH_ON_SOME_CFG_PATHS\""),
            "byte width cannot be a word literal");
        check(csv.contains("\"'=INJECT\""),"spreadsheet formula escaped");
        check(csv.contains("\"CFG_PATH\"") && csv.contains("\"A_MAY_PRECEDE_B\"") &&
            csv.contains("NEVER_AUTO_APPLY"),"paths never rename or mutate");
        String generic=HardwareConfigurationEvidenceCsv.serialize(report,
            List.of(relation),false);
        check(!generic.contains("\"SIMCR\"") && !generic.contains("\"CSBAR0\"") &&
            generic.contains("UNVERIFIED_MCU_REGISTER") &&
            !generic.contains("STATIC_LITERAL_ONLY"),
            "generic CPU32 suppresses device register and MM names");
        check(HardwareConfigurationEvidenceCsv.serialize(
            HardwareCfgWriteAudit.inspect(false,List.of()),List.of(),false)
            .equals(HardwareConfigurationEvidenceCsv.HEADER),
            "empty result cannot fabricate evidence");
        boolean fail=false;
        try{HardwareConfigurationEvidenceCsv.serialize(null,List.of(),true);}
        catch(IllegalArgumentException expected){fail=true;}
        check(fail,"missing data must fail");
        System.out.println("HardwareConfigurationEvidenceCsvSelfTest OK");
    }
}
