package ghidrassist.hardware;

public final class ManualPrintedPageSelfTest {
    private static void ok(boolean b,String msg){if(!b)throw new AssertionError(msg);}
    public static void main(String[] args) {
        var a=ManualPrintedPage.fromText(
            "MC68336/376 REGISTER SUMMARY MOTOROLA\n"+
            "USER’S MANUAL Rev. 15 Oct 2000 D-1\n"+
            "APPENDIX D REGISTER SUMMARY\nTable D-1 Module Address Map\n");
        ok(a.label().equals("D-1") &&
            a.confidence().equals("PDF_TEXT_HEADER_CANDIDATE"),
            "standalone Appendix D with date/revision");
        var b=ManualPrintedPage.fromText(
            "MC68336/376 SYSTEM INTEGRATION MODULE MOTOROLA\n"+
            "USER’S MANUAL Rev. 15 Oct 2000 5-1\nSection 5\n");
        ok(b.label().equals("5-1"),"separately paginated section 5");
        var c=ManualPrintedPage.fromText(
            "Table D-1 Module Address Map\nSIM 128 $YFFA00");
        ok(c.label().equals("UNKNOWN"),"table numbering is NOT printed page");
        var d=ManualPrintedPage.fromText(
            "MC68332 USER'S MANUAL\nD-1\nREGISTER SUMMARY\n"+
            "D.1 CPU\n");
        ok(d.label().equals("D-1"),"header label on adjacent line");
        var e=ManualPrintedPage.fromText(
            "USER'S MANUAL D-1 and 5-1\nTABLE D-1\n");
        ok(e.label().equals("UNKNOWN") && e.confidence().equals("AMBIGUOUS_HEADER"),
            "ambiguous page must not be guessed");
        ok(ManualPrintedPage.fromText("").label().equals("UNKNOWN"),
            "blank PDF page no printed label");
        var footer=ManualPrintedPage.fromText(
            "Table D-1 Module Address Map\nSIM 128 $YFFA00\nQSM 512 $YFFC00\n"+
            "MC68332 REGISTER SUMMARY\nUSER’S MANUAL    |    D-1\n"+
            "For More Information On This Product");
        ok(footer.label().equals("D-1"),"MC68332 bottom-of-page folio");
        var toucan=ManualPrintedPage.fromText(
            "Table 13-9 Interrupt Sources and Vector Addresses\n"+
            "MC68336/376 CAN 2.0B CONTROLLER MODULE MOTOROLA\n"+
            "USER’S MANUAL Rev. 15 Oct 2000 13-20");
        ok(toucan.label().equals("13-20"),"TouCAN bottom folio");
        System.out.println("ManualPrintedPageSelfTest OK");
    }
}
