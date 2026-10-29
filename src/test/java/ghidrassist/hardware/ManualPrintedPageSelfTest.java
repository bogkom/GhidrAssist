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
        var tableBelowHeader=ManualPrintedPage.fromText(
            "MC68332 REFERENCE\nUSER'S MANUAL\n"+
            "Table D-1 Module Address Map\nSIM 128 $YFFA00");
        ok(tableBelowHeader.label().equals("UNKNOWN"),
            "Table D-1 adjacent to header is not a physical folio");
        var figureAboveHeader=ManualPrintedPage.fromText(
            "Figure 5-20 Example QSPI\nUSER'S MANUAL\nRegister Summary");
        ok(figureAboveHeader.label().equals("UNKNOWN"),
            "Figure 5-20 immediately before header is not a folio");
        var inlineTable=ManualPrintedPage.fromText(
            "MC68332 USER'S MANUAL Table D-1\nRegister Summary");
        ok(inlineTable.label().equals("UNKNOWN"),
            "table reference inside manual header is not a folio");
        var pageAndTable=ManualPrintedPage.fromText(
            "MC68332 USER'S MANUAL D-3\nTable D-1 Module Address Map\n");
        ok(pageAndTable.label().equals("D-3"),
            "real header folio is retained while adjacent table is ignored");
        var standalone=ManualPrintedPage.fromText(
            "MC68332 USER'S MANUAL\nPAGE: D-7\nSection 7");
        ok(standalone.label().equals("D-7"),
            "standalone explicit page label adjacent to header is allowed");
        var conflictingHeaders=ManualPrintedPage.fromText(
            "USER'S MANUAL D-1\nMC68332 TEXT\n"+
            "USER'S MANUAL D-2\n");
        ok(conflictingHeaders.label().equals("UNKNOWN") &&
            conflictingHeaders.confidence().equals("AMBIGUOUS_HEADER"),
            "conflicting vendor headers must fail closed");
        var matchingHeaders=ManualPrintedPage.fromText(
            "USER'S MANUAL D-1\nMC68332 TEXT\n"+
            "USER'S MANUAL D-1\n");
        ok(matchingHeaders.label().equals("D-1"),
            "matching duplicate headers preserve only candidate status");
        var contradictoryAdjacent=ManualPrintedPage.fromText(
            "D-1\nUSER'S MANUAL D-2\n");
        ok(contradictoryAdjacent.label().equals("UNKNOWN") &&
            contradictoryAdjacent.confidence().equals("AMBIGUOUS_HEADER"),
            "header and adjacent standalone folios disagree");
        var sameAdjacent=ManualPrintedPage.fromText(
            "D-1\nUSER'S MANUAL D-1\n");
        ok(sameAdjacent.label().equals("D-1"),
            "same header and adjacent folio are not falsely ambiguous");
        var oversized=ManualPrintedPage.fromText(
            "MC68332 USER'S MANUAL D-1\n"+
            "X".repeat(ManualPrintedPage.MAX_PAGE_TEXT_CHARS));
        ok(oversized.label().equals("UNKNOWN") &&
            oversized.confidence().equals("PDF_TEXT_TOO_LARGE"),
            "oversized PDF text cannot yield falsely certain printed folio");
        var extremeLines=ManualPrintedPage.fromText(
            "MC68332 USER'S MANUAL D-1\n" + "\n".repeat(
                ManualPrintedPage.MAX_PAGE_TEXT_CHARS));
        ok(extremeLines.label().equals("UNKNOWN") &&
            extremeLines.confidence().equals("PDF_TEXT_TOO_LARGE"),
            "excessive lines cannot force unconstrained split allocations");
        var normal=ManualPrintedPage.fromText("USER'S MANUAL D-4\n");
        ok(normal.label().equals("D-4"),
            "ordinary folio candidate preserved under text budget");
        System.out.println("ManualPrintedPageSelfTest OK");
    }
}
