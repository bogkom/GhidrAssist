package ghidrassist.hardware;

public final class HardwareProfileManifestPreviewSelfTest {
    private HardwareProfileManifestPreviewSelfTest(){}
    private static void check(boolean condition,String reason){
        if(!condition)throw new AssertionError(reason);
    }
    private static final String SAMPLE="""
        GHIDRASSIST_PROFILE\t1
        DOCUMENT\tMC68332\tMC68332UM\thttps://www.nxp.com/docs/en/user-guide/MC68332UM.pdf\tUNKNOWN\tUNKNOWN
        MODULE\tSIM\t0x0A00\t0x0080\tD-1 PDF page 215
        MODULE\tQSM\t0x0C00\t0x0200\tUNKNOWN
        REGISTER\tSIM\tSIMCR\t0x0A00\t16\tD-6 PDF page 220
        REGISTER\tSIM\tSYPCR\t0x0A21\t8\tUNKNOWN
        REGISTER\tQSM\tQSMCR\t0x0C00\t16\tUNKNOWN
        FIELD\tSIMCR\tMM\t0x0040\tD-6 PDF page 220
        FIELD\tSIMCR\tSUPV\t0x0080\tUNKNOWN
        """;
    private static void bad(String text,String reason){
        boolean failed=false;
        try{HardwareProfileManifestPreview.parse(text);}
        catch(IllegalArgumentException e){failed=true;}
        check(failed,reason);
    }
    public static void main(String[] args){
        var result=HardwareProfileManifestPreview.parse(SAMPLE);
        check(result.source().device().equals("MC68332") &&
            result.modules().size()==2 && result.registers().size()==3 &&
            result.fields().size()==2,"valid structure read without Ghidra APIs");
        check(result.ambiguousPages()==4,"physical-page gaps counted");
        check(result.report().contains("NOT IMPORTED into Ghidra") &&
            result.report().contains("Claimed edition: UNKNOWN") &&
            result.report().contains("No MCU identification"),
            "reports may not promote provided metadata to verified facts");
        check(result.registers().get(0).offset()==0xA00 &&
            result.fields().get(0).mask()==0x40,"hex and bitfields preserved");
        bad(SAMPLE.replace("GHIDRASSIST_PROFILE\t1","GHIDRASSIST_PROFILE\t2"),
            "reject unsupported future schema");
        bad(SAMPLE.replace("https://www.nxp.com","http://www.nxp.com"),
            "reject untrusted HTTP manual references");
        bad(SAMPLE.replace("UNKNOWN\tUNKNOWN","UNKNOWN\t1234"),
            "reject malformed claimed PDF checksum");
        bad(SAMPLE.replace("MODULE\tQSM\t0x0C00","MODULE\tQSM\t0x0A40"),
            "reject overlapping module apertures");
        bad(SAMPLE.replace("REGISTER\tSIM\tSYPCR\t0x0A21\t8",
                           "REGISTER\tSIM\tSYPCR\t0x0A01\t8"),
            "reject overlapping register ranges");
        bad(SAMPLE.replace("REGISTER\tSIM\tSIMCR\t0x0A00\t16",
                           "REGISTER\tSIM\tSIMCR\t0x0A01\t16"),
            "reject odd word alignment");
        bad(SAMPLE.replace("FIELD\tSIMCR\tSUPV\t0x0080",
                           "FIELD\tSIMCR\tSUPV\t0x0040"),
            "reject overlapping bitfields");
        String wide=SAMPLE.replace("REGISTER\tSIM\tSIMCR\t0x0A00\t16",
                "REGISTER\tSIM\tSIMCR\t0x0A00\t32")
            .replace("REGISTER\tSIM\tSYPCR\t0x0A21\t8",
                     "REGISTER\tSIM\tSYPCR\t0x0A24\t8")
            .replace("FIELD\tSIMCR\tMM\t0x0040",
                     "FIELD\tSIMCR\tMM\t0x80000000");
        var widest=HardwareProfileManifestPreview.parse(wide);
        check(widest.fields().get(0).mask()==0x80000000L,
            "full-width 32-bit masks must be unsigned and supported");
        bad(SAMPLE.replace("FIELD\tSIMCR\tMM\t0x0040",
                           "FIELD\tSIMCR\tMM\t0x10000"),
            "reject bitfield outside register width");
        bad(SAMPLE.replace("FIELD\tSIMCR\tMM\t0x0040",
                           "FIELD\tUNKNOWN\tMM\t0x0040"),
            "reject unsupported field register");
        bad(SAMPLE.replace("REGISTER\tSIM\tSYPCR","REGISTER\tOTHER\tSYPCR"),
            "reject unknown module");
        bad(SAMPLE + "COMPUTER\tSHOULD_NOT_RUN\tcmd\n",
            "no arbitrary record execution");
        bad(SAMPLE.repeat(130),"reject duplicated definitions/unbounded input");
        bad("","reject blank file");
        var report=result.report();
        check(report.length()<1500,"preview output is bounded");
        boolean immutable=false;
        try{result.modules().clear();}
        catch(UnsupportedOperationException e){immutable=true;}
        check(immutable,"preview immutable");
        // A second module differing only in case must never silently
        // overwrite a normalized key in the comparison view.
        bad(SAMPLE.replace("MODULE\\tQSM\\t0x0C00\\t0x0200",
                "MODULE\\tsim\\t0x0C00\\t0x0200"),
            "case-insensitive duplicate module names must be rejected");
        var mixedCase=HardwareProfileManifestPreview.parse(
            SAMPLE.replace("REGISTER\\tSIM\\tSIMCR",
                "REGISTER\\tsim\\tSIMCR"));
        check(mixedCase.registers().get(0).module().equals("SIM"),
            "register resolves explicitly declared module regardless of case");
        for(String unsupported:new String[]{"PDF page","PDF page UNKNOWN",
                "PDF pages 2-3 AMBIGUOUS","PDF page 0",
                "Appendix D page to be verified","PDF page abc"}){
            var changed=HardwareProfileManifestPreview.parse(
                SAMPLE.replace("D-6 PDF page 220",unsupported));
            check(changed.ambiguousPages()==6,
                "unknown source page must remain counted as ambiguous: "+unsupported);
        }
        var explicit=HardwareProfileManifestPreview.parse(
            SAMPLE.replace("D-6 PDF page 220","D-6 PDF pages 220-221"));
        check(explicit.ambiguousPages()==4,
            "numeric source page range is a claim, not unverified gap");
        System.out.println("HardwareProfileManifestPreviewSelfTest OK");
    }
}
