package ghidrassist.hardware;

public final class HardwareProfileManifestComparisonSelfTest {
    private HardwareProfileManifestComparisonSelfTest() {}
    private static void ok(boolean value,String reason) {
        if(!value)throw new AssertionError(reason);
    }
    private static final String SAMPLE="""
        GHIDRASSIST_PROFILE\t1
        DOCUMENT\tMC68332\tMC68332UM\thttps://www.nxp.com/manual.pdf\tUNKNOWN\tUNKNOWN
        MODULE\tSIM\t0x0A00\t0x0080\tPDF page 3
        MODULE\tQSM\t0x0C00\t0x0200\tPDF page 4
        REGISTER\tSIM\tSIMCR\t0x0A00\t16\tPDF page 3
        REGISTER\tSIM\tSYPCR\t0x0A21\t8\tPDF page 3
        REGISTER\tQSM\tQSMCR\t0x0C00\t16\tPDF page 4
        FIELD\tSIMCR\tMM\t0x0040\tPDF page 3
        FIELD\tSIMCR\tSUPV\t0x0080\tPDF page 3
        """;
    private static void rejected(Runnable action,String reason){
        boolean bad=false;
        try{action.run();}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,reason);
    }
    public static void main(String[] args){
        var a=HardwareProfileManifestPreview.parse(SAMPLE);
        var identical=HardwareProfileManifestComparison.compare(a,a);
        ok(identical.equalDefinitions()==7 &&
            identical.changedDefinitions()==0 &&
            identical.changedPageLabels()==0 &&
            identical.overlappingDifferentNames()==0 &&
            !identical.matchingClaimedPdfDigest(),
            "identical unverified metadata is not verified PDF checksum");
        String alt=SAMPLE
            .replace("MC68332UM\t","MC68332TS\t")
            .replace("REGISTER\tSIM\tSYPCR\t0x0A21\t8",
                     "REGISTER\tSIM\tSYPCR\t0x0A22\t8")
            .replace("REGISTER\tSIM\tSIMCR\t0x0A00\t16\tPDF page 3",
                     "REGISTER\tSIM\tSIMCR\t0x0A00\t16\tPDF page 5")
            .replace("FIELD\tSIMCR\tMM\t0x0040",
                     "FIELD\tSIMCR\tMM\t0x0020")
            .replace("REGISTER\tQSM\tQSMCR\t0x0C00\t16\tPDF page 4\n","")
            .concat("REGISTER\tSIM\tALIAS\t0x0A21\t8\tPDF page 5\n");
        // The second manifest can describe another register at the exact
        // offset where the left one names SYPCR: this is a possible alias.
        var b=HardwareProfileManifestPreview.parse(alt);
        var diff=HardwareProfileManifestComparison.compare(a,b);
        ok(diff.changedDefinitions()==2 && diff.changedPageLabels()==1 &&
            diff.leftOnly()==1 && diff.rightOnly()==1 &&
            diff.overlappingDifferentNames()==1,
            "precise structural, folio, omission and cross-name differences");
        ok(diff.render().contains("UNVERIFIED CLAIMS ONLY") &&
            diff.render().contains("NOT verified hardware contradictions") &&
            diff.render().contains("NO symbols, memory blocks"),
            "no promotion to known hardware or Apply");
        rejected(()->HardwareProfileManifestComparison.compare(a,
            HardwareProfileManifestPreview.parse(alt.replace("MC68332\t","MC68340\t"))),
            "different claimed MCU labels must not be compared as same device");
        rejected(()->HardwareProfileManifestComparison.compare(a,null),
            "null comparison rejected");
        String claimed="a".repeat(64);
        var sameClaim=HardwareProfileManifestComparison.compare(
            HardwareProfileManifestPreview.parse(SAMPLE.replace(
                "UNKNOWN\tUNKNOWN","UNKNOWN\t"+claimed)),
            HardwareProfileManifestPreview.parse(SAMPLE.replace(
                "UNKNOWN\tUNKNOWN","UNKNOWN\t"+claimed.toUpperCase())));
        ok(sameClaim.matchingClaimedPdfDigest() &&
            sameClaim.render().contains("NOT independent byte verification"),
            "equal claimed PDF digests are not independent evidence");
        // Even a large discrepancy should retain exact counts but limit
        // the UI report to 100 source-derived findings.
        StringBuilder left=new StringBuilder(
            "GHIDRASSIST_PROFILE\t1\nDOCUMENT\tMC68332\tA\thttps://example.org/a.pdf\tUNKNOWN\tUNKNOWN\n");
        StringBuilder right=new StringBuilder(
            "GHIDRASSIST_PROFILE\t1\nDOCUMENT\tMC68332\tB\thttps://example.org/b.pdf\tUNKNOWN\tUNKNOWN\n");
        for(int i=0;i<120;i++){
            String m="M"+i;
            String base=String.format(java.util.Locale.ROOT,"0x%04X",i*16);
            String row="MODULE\t"+m+"\t"+base+"\t0x0010\tPDF page 3\n";
            left.append(row);right.append(row);
            left.append("REGISTER\t").append(m).append("\tL").append(i)
                .append("\t").append(base).append("\t8\tPDF page 3\n");
            right.append("REGISTER\t").append(m).append("\tR").append(i)
                .append("\t").append(base).append("\t8\tPDF page 3\n");
        }
        var capped=HardwareProfileManifestComparison.compare(
            HardwareProfileManifestPreview.parse(left.toString()),
            HardwareProfileManifestPreview.parse(right.toString()));
        ok(capped.overlappingDifferentNames()==120 &&
            capped.leftOnly()==120 && capped.rightOnly()==120 &&
            capped.omittedFindings()>0 &&
            capped.findings().size()==HardwareProfileManifestComparison.MAX_DISPLAY_FINDINGS &&
            capped.render().contains("ADDITIONAL_UNDISPLAYED_FINDINGS") &&
            capped.render().length()<19000,
            "large manifest comparison bounded without losing discrepancy counts");
        boolean immutable=false;
        try{capped.findings().clear();}
        catch(UnsupportedOperationException expected){immutable=true;}
        ok(immutable,"immutable comparison data");
        System.out.println("HardwareProfileManifestComparisonSelfTest OK");
    }
}
