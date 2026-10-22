package ghidrassist.hardware;

public final class ManualDocumentScopeSelfTest {
    private static void ok(boolean b,String message){if(!b)throw new AssertionError(message);}
    public static void main(String[] args) {
        var m332=ManualDocumentScope.fromFilename("MC68332UM.pdf");
        ok(m332.documentId().equals("MC68332UM") &&
            m332.applicableModels().equals("MC68332"),"MC68332 scope");
        var combined=ManualDocumentScope.fromFilename("/manuals/MC68336376UM.PDF");
        var split=ManualDocumentScope.fromFilename("MC68336376UMD.pdf");
        ok(combined.editionPart().equals("FULL_MANUAL") &&
            split.editionPart().equals("SPLIT_D") &&
            !combined.documentId().equals(split.documentId()),
            "full book and separately paginated Appendix D must be distinct");
        ok(split.applicableModels().equals("MC68336+MC68376"),
            "split appendix applies to both with model-specific exceptions");
        ok(ManualDocumentScope.fromFilename("MC68336376UM13.pdf")
                .editionPart().equals("SPLIT_13"),"TouCAN chapter");
        ok(ManualDocumentScope.fromFilename("MC68331UM.pdf")
                .applicableModels().equals("MC68331"),"different device");
        ok(ManualDocumentScope.fromFilename("apdreg.pdf")
                .documentId().equals("UNKNOWN"),"legacy arbitrary filename never inferred");
        ok(ManualDocumentScope.fromFilename("MC68332UM_revX.pdf")
                .documentId().equals("UNKNOWN"),"revision-renamed filename not blindly verified");
        ok(m332.evidence(215).contains("pdf_page=215") &&
            m332.evidence(215).contains("NOT PROCESSOR PROOF"),
            "page and status provenance");
        boolean bad=false;
        try{m332.evidence(0);}catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"invalid PDF pages rejected");
        var own331=ManualDocumentScope.fromFilename("MC331_SIM.pdf");
        ok(own331.applicableModels().equals("MC68331") &&
           own331.confidence().contains("LOCAL_FILENAME_ALIAS"),
           "user's MC331 module prefix is a declaration, not verified identity");
        ok(ManualDocumentScope.fromFilename("MC68332_05_SIM.pdf")
            .applicableModels().equals("MC68332"),
            "unique MC68332 chapter alias is recognized");
        var own336=ManualDocumentScope.fromFilename("MC68336_68376_05_SIM.pdf");
        ok(own336.applicableModels().equals("MC68336+MC68376") &&
           own336.editionPart().startsWith("SPLIT_05"),
           "readable locally renamed 336/376 section 5");
        var legacyCan=ManualDocumentScope.fromFilename("MC68336_13_TouCAN.pdf");
        ok(legacyCan.documentId().equals("MC68336376UM13") &&
           legacyCan.applicableModels().equals("MC68376") &&
           legacyCan.confidence().contains("LOCAL_FILENAME_ALIAS"),
           "short local TouCAN chapter name remains an unverified alias");
        var ownCan=ManualDocumentScope.fromFilename("MC68336_68376_13_TOUCAN.pdf");
        ok(ownCan.applicableModels().equals("MC68376"),
           "TouCAN chapter only describes MC68376 peripheral");
        var unk=ManualDocumentScope.fromFilename("c5sim.pdf");
        ok(unk.documentId().equals("UNKNOWN"),
           "archive basename c5sim is not a unique MCU identifier");
        String h332="MC68332 SYSTEM INTEGRATION MODULE MOTOROLA\\n"+
            "USER’S MANUAL Rev 0.1 5-1\\n";
        String h336="MC68336/376 SYSTEM INTEGRATION MODULE MOTOROLA\\n"+
            "USER’S MANUAL Rev. 15 Oct 2000 5-1\\n";
        var same332=ManualDocumentScope.fromDocumentEvidence("c5sim.pdf",h332);
        var same336=ManualDocumentScope.fromDocumentEvidence("c5sim.pdf",h336);
        ok(same332.applicableModels().equals("MC68332") &&
           same336.applicableModels().equals("MC68336+MC68376") &&
           same332.confidence().contains("ARCHIVE_FILENAME_NOT_UNIQUE"),
           "the identical c5sim basename is resolved by actual PDF heading");
        ok(ManualDocumentScope.fromDocumentEvidence("c8qadc.pdf",h336)
             .applicableModels().equals("MC68336+MC68376"),
           "QADC chapter with correct header");
        ok(ManualDocumentScope.fromDocumentEvidence("c8qadc.pdf",h332)
             .documentId().equals("UNKNOWN"),
           "incompatible module/header cannot become an official module map");
        ok(ManualDocumentScope.fromDocumentEvidence(
             "MC68336_68376_05_SIM.pdf",h332).documentId().equals("UNKNOWN"),
           "contradictory PDF header overrides false confidence from a renamed file");
        ok(ManualDocumentScope.fromDocumentEvidence("MC331_SIM.pdf",h336)
             .confidence().equals("FILENAME_HEADER_MODEL_CONFLICT"),
           "custom MC331 label conflicting with actual document is rejected");
        ok(ManualDocumentScope.fromDocumentEvidence("apdreg.pdf",
            "MC68336/376 REGISTER SUMMARY MOTOROLA\\nUSER’S MANUAL Rev 1 D-1")
            .editionPart().equals("SPLIT_D"),
            "vendor apdreg basename resolves via verified Appendix D header");
        ok(ManualDocumentScope.fromDocumentEvidence("apdreg.pdf","")
             .documentId().equals("UNKNOWN"),
            "apdreg without source header is ambiguous across manuals");
        ok(ManualDocumentScope.fromDocumentEvidence("c5sim.pdf","")
             .documentId().equals("UNKNOWN"),
           "unrecognized raw filename stays unknown without a vendor header");
        ok(ManualDocumentScope.fromFilename("MC68375_SIM.pdf")
             .confidence().contains("NO_PRIMARY_MANUAL_VERIFIED"),
           "68375 is a documentary candidate, not inherited 68376 profile");
        System.out.println("ManualDocumentScopeSelfTest OK");
    }
}
