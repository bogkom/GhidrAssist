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
            csv.contains("\"UNKNOWN\",\"UNKNOWN_DUE_TO_BARRIER_OR_LIMIT\""),
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
        var listing=HardwareStartupEvidenceMerge.Source.LISTING_REFERENCE;
        var cfg=HardwareStartupEvidenceMerge.Source.CFG_PCODE;
        var merged=HardwareStartupEvidenceMerge.reconcile(List.of(
            new HardwareStartupEvidenceMerge.Observation(0x2bc0,0x2bca,
                0xfffa00,"SIMCR",listing,true,16,0x40ca,false),
            new HardwareStartupEvidenceMerge.Observation(0x2bc0,0x2bca,
                0xfffa00,"SIMCR",cfg,true,16,0x40ca,false),
            new HardwareStartupEvidenceMerge.Observation(0x2bc0,0x2bcc,
                0xfffa4c,"CSBAR0",cfg,true,8,null,true),
            new HardwareStartupEvidenceMerge.Observation(0x2bc0,0x2bdf,
                -1,"UNRESOLVED_ALIAS",cfg,true,0,null,true)));
        String unified=HardwareConfigurationEvidenceCsv.withUnifiedSources(
            csv,merged,true);
        check(unified.contains("\"MERGED_SITE\"") &&
            unified.contains("\"LISTING_REF+CFG_PCODE\"") &&
            unified.contains("\"UNBOUND_ALIAS_SUMMARY\"") &&
            unified.contains("POSSIBLE_ANY_MMIO_NEVER_AUTO_APPLY"),
            "normalized view, source identity and unknown alias preserved");
        check(unified.contains("RECONCILED_READ_ONLY_NEVER_AUTO_APPLY") &&
            unified.contains("UNBOUND_ALIAS_COUNT=1"),
            "merged sources cannot become Apply requests");
        String safeGeneric=HardwareConfigurationEvidenceCsv.withUnifiedSources(
            generic,merged,false);
        check(!safeGeneric.contains("\"SIMCR\"") &&
            !safeGeneric.contains("\"CSBAR0\""),
            "generic CPU32 cannot reveal device labels in merged view");
        var unknownWidthReport=HardwareCfgWriteAudit.inspect(true,List.of(
            new HardwareCfgWriteAudit.Site(0x2bc0,0x2bd8,
                "UNRESOLVED_ALIAS",-1,true,0,null,0,0,false,true,true)));
        String unknownWidthCsv=HardwareConfigurationEvidenceCsv.serialize(
            unknownWidthReport,List.of(),true);
        check(unknownWidthCsv.contains("\"INDIRECT\",\"UNKNOWN\",\"UNKNOWN\",\"UNKNOWN_DUE_TO_BARRIER_OR_LIMIT\"") &&
            unknownWidthCsv.contains("NEVER_AUTO_APPLY"),
            "unmodeled width printed UNKNOWN, never assumed word data");
        boolean rejectedMerged=false;
        try{HardwareConfigurationEvidenceCsv.withUnifiedSources(
            "non-CSV",merged,true);}
        catch(IllegalArgumentException expected){rejectedMerged=true;}
        check(rejectedMerged,"invalid raw CSV must fail closed");
        System.out.println("HardwareConfigurationEvidenceCsvSelfTest OK");
    }
}
