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
        System.out.println("ManualDocumentScopeSelfTest OK");
    }
}
