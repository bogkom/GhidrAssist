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
        // The merger must reject forged rows, not merely trust a matching
        // header prefix. A valid source-only CSV remains accepted above.
        for(String forged : List.of(
                HardwareConfigurationEvidenceCsv.HEADER+"not,a,quoted,row\n",
                HardwareConfigurationEvidenceCsv.HEADER+"\"STORE\",\"broken\"\n",
                HardwareConfigurationEvidenceCsv.HEADER+"\"STORE\",\"open\n",
                HardwareConfigurationEvidenceCsv.HEADER+"\"STORE\",\"x\"",
                HardwareConfigurationEvidenceCsv.HEADER+"\"STORE\",\"x\";\n",
                HardwareConfigurationEvidenceCsv.HEADER+"\"STORE\",\"embedded\rcontrol\"\n")) {
            boolean refused=false;
            try{HardwareConfigurationEvidenceCsv.withUnifiedSources(forged,merged,true);}
            catch(IllegalArgumentException expected){refused=true;}
            check(refused,"untrusted CSV row must fail closed");
        }
        // A syntactically valid quoted field can still be an unbounded
        // imported source payload. Reject both plain and quote-escaped
        // oversized cells before building the unified view.
        String[] oversizedCells={"X".repeat(
            HardwareConfigurationEvidenceCsv.MAX_CSV_CELL_CHARS+2),
            "\"".repeat(HardwareConfigurationEvidenceCsv.MAX_CSV_CELL_CHARS+2)};
        for(String oversizedCell:oversizedCells){
            String quoted="\""+oversizedCell.replace("\"","\"\"")+"\"";
            String forged=HardwareConfigurationEvidenceCsv.HEADER+quoted+
                ",\"\"".repeat(13)+"\n";
            boolean refused=false;
            try{HardwareConfigurationEvidenceCsv.withUnifiedSources(forged,merged,true);}
            catch(IllegalArgumentException expected){refused=true;}
            check(refused,"oversized quoted CSV source cell rejected");
        }
        // Quoted, 14-column records are not automatically trustworthy:
        // the upstream source must never impersonate the merged view or
        // append more source rows after its sole terminal omission marker.
        String emptyTail=",\"\"".repeat(13)+"\n";
        for(String forgedKind : List.of("MERGED_SITE",
                "UNBOUND_ALIAS_SUMMARY","OMITTED_MERGED_SITES",
                "UNRECOGNIZED","'=HYPERLINK(1)")) {
            String forged=HardwareConfigurationEvidenceCsv.HEADER+
                "\""+forgedKind+"\""+emptyTail;
            boolean refused=false;
            try{HardwareConfigurationEvidenceCsv.withUnifiedSources(forged,merged,true);}
            catch(IllegalArgumentException expected){refused=true;}
            check(refused,"forged source record type must be rejected");
        }
        // Quoted source fields may still carry executable spreadsheet formulas.
        for(String injected : List.of("=1+1", " +SUM(1)", "\u2060@SUM(1)", "\t=2")) {
            String forged=HardwareConfigurationEvidenceCsv.HEADER+
                "\"STORE\",\""+injected+"\""+",\"\"".repeat(12)+"\n";
            boolean refused=false;
            try{HardwareConfigurationEvidenceCsv.withUnifiedSources(forged,merged,true);}
            catch(IllegalArgumentException expected){refused=true;}
            check(refused,"formula-bearing imported source field rejected");
        }
        String omission="\"OMITTED_ROWS\""+emptyTail;
        String store="\"STORE\""+emptyTail;
        String path="\"CFG_PATH\""+emptyTail;
        for(String forged : List.of(
                omission+omission, omission+store, omission+path,
                path+store, store+omission+store, store+path+store)) {
            boolean refused=false;
            try{HardwareConfigurationEvidenceCsv.withUnifiedSources(
                HardwareConfigurationEvidenceCsv.HEADER+forged,merged,true);}
            catch(IllegalArgumentException expected){refused=true;}
            check(refused,"source ordering and terminal omission marker enforced");
        }
        check(HardwareConfigurationEvidenceCsv.withUnifiedSources(
            HardwareConfigurationEvidenceCsv.HEADER+store+path+omission,
            HardwareStartupEvidenceMerge.reconcile(List.of()),true)
            .contains("\"OMITTED_ROWS\""),
            "canonical source order remains accepted");
        String oversizedRaw=HardwareConfigurationEvidenceCsv.HEADER+
            store.repeat(HardwareConfigurationEvidenceCsv.MAX_ROWS+1);
        boolean overBudget=false;
        try{HardwareConfigurationEvidenceCsv.withUnifiedSources(oversizedRaw,merged,true);}
        catch(IllegalArgumentException expected){overBudget=true;}
        check(overBudget,"raw CSV source row budget must be enforced");


        // The total cap includes omission markers, not just evidence rows.
        String nearCap=HardwareConfigurationEvidenceCsv.HEADER+
            store.repeat(HardwareConfigurationEvidenceCsv.MAX_ROWS-1);
        String capped=HardwareConfigurationEvidenceCsv.withUnifiedSources(
            nearCap,merged,true);
        check(capped.split("\\n",-1).length-2==
            HardwareConfigurationEvidenceCsv.MAX_ROWS,
            "merged export including omission marker stays within total row cap");
        check(capped.contains("\"OMITTED_MERGED_SITES\""),
            "truncated merged view retains an explicit incomplete marker");
        boolean noMarkerRoom=false;
        try{HardwareConfigurationEvidenceCsv.withUnifiedSources(
            HardwareConfigurationEvidenceCsv.HEADER+
            store.repeat(HardwareConfigurationEvidenceCsv.MAX_ROWS),
            merged,true);}
        catch(IllegalArgumentException expected){noMarkerRoom=true;}
        check(noMarkerRoom,"full source CSV refuses unreportable merged omissions");
        var cappedStores=HardwareCfgWriteAudit.inspect(true,
            java.util.stream.IntStream.range(0,HardwareConfigurationEvidenceCsv.MAX_ROWS+2)
                .mapToObj(i->new HardwareCfgWriteAudit.Site(0x100,0x100+i*2,
                    "SIMCR",0xfffa00,false,16,0x40ca,0,0,false,false,false))
                .toList());
        String cappedSerialized=HardwareConfigurationEvidenceCsv.serialize(
            cappedStores,List.of(),true);
        check(cappedSerialized.split("\\n",-1).length-2==
            HardwareConfigurationEvidenceCsv.MAX_ROWS &&
            cappedSerialized.contains("\"OMITTED_ROWS\""),
            "serializer reserves a row for its own omission marker");

        // Exactly MAX_ROWS detail records must remain complete: an
        // omission marker is reserved only when there is actual overflow.
        var exactStores=HardwareCfgWriteAudit.inspect(true,
            java.util.stream.IntStream.range(0,HardwareConfigurationEvidenceCsv.MAX_ROWS)
                .mapToObj(i->new HardwareCfgWriteAudit.Site(0x100,0x100+i*2,
                    "SIMCR",0xfffa00,false,16,0x40ca,0,0,false,false,false))
                .toList());
        String exactCsv=HardwareConfigurationEvidenceCsv.serialize(
            exactStores,List.of(),true);
        check(exactCsv.split("\\n",-1).length-2==
            HardwareConfigurationEvidenceCsv.MAX_ROWS &&
            !exactCsv.contains("\"OMITTED_ROWS\""),
            "exactly 5000 evidence rows remain complete without a false omission");
        String noExtra=HardwareConfigurationEvidenceCsv.withUnifiedSources(
            HardwareConfigurationEvidenceCsv.HEADER+
            store.repeat(HardwareConfigurationEvidenceCsv.MAX_ROWS),
            HardwareStartupEvidenceMerge.reconcile(List.of()),true);
        check(noExtra.split("\\n",-1).length-2==
            HardwareConfigurationEvidenceCsv.MAX_ROWS &&
            !noExtra.contains("\"OMITTED_MERGED_SITES\""),
            "full source CSV is valid when no merged evidence is appended");

        // Source Ghidra labels are untrusted. Unicode format controls
        // and whitespace can hide executable spreadsheet formulas despite
        // RFC-style quoted CSV cells. Keep the original prefix visible but
        // force a literal apostrophe before potential formula evaluation.
        var unicodeSites=HardwareCfgWriteAudit.inspect(true,List.of(
            new HardwareCfgWriteAudit.Site(0x500,0x500,
                "\u2060=HYPERLINK(1)",0xfffa00,false,16,0x40ca,
                0,0,false,false,false),
            new HardwareCfgWriteAudit.Site(0x500,0x502,
                " \u200d\u200e+5+5",0xfffa04,false,16,0x100,
                0,0,false,false,false),
            new HardwareCfgWriteAudit.Site(0x500,0x504,
                "\uFEFF@SUM(1,2)",0xfffa08,false,16,0x22,
                0,0,false,false,false)));
        String unicodeCsv=HardwareConfigurationEvidenceCsv.serialize(
            unicodeSites,List.of(),true);
        check(unicodeCsv.contains("\"'\u2060=HYPERLINK(1)\"") &&
            unicodeCsv.contains("\"' \u200d\u200e+5+5\"") &&
            unicodeCsv.contains("\"'\uFEFF@SUM(1,2)\""),
            "Unicode format-hidden spreadsheet formulas are neutralized");
        // Large input is clipped before replace/quote expansion, with a
        // visible loss marker and without cutting a surrogate pair.
        int edge=HardwareConfigurationEvidenceCsv.MAX_CSV_CELL_CHARS-
            " [SOURCE_TRUNCATED]".length()-1;
        String hugeLabel="R".repeat(edge)+"\uD83D\uDE80"+"Q".repeat(100_000);
        var hugeSite=HardwareCfgWriteAudit.inspect(true,List.of(
            new HardwareCfgWriteAudit.Site(0x500,0x506,
                hugeLabel,0xfffa0c,false,16,0x33,
                0,0,false,false,false)));
        String hugeCsv=HardwareConfigurationEvidenceCsv.serialize(
            hugeSite,List.of(),true);
        check(hugeCsv.contains("SOURCE_TRUNCATED") &&
            hugeCsv.length()<2500 &&
            !hugeCsv.contains("\uD83D [SOURCE_TRUNCATED]") &&
            !hugeCsv.contains("\uD83D\uDE80"),
            "giant register cells bounded without a half-surrogate");
        check(!HardwareConfigurationEvidenceCsv.serialize(
                unicodeSites,List.of(),false).contains("HYPERLINK"),
            "generic CPU32 must continue suppressing MCU-specific register evidence");
        System.out.println("HardwareConfigurationEvidenceCsvSelfTest OK");
    }
}
