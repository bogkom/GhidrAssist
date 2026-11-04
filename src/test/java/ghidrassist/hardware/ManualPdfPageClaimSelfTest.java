package ghidrassist.hardware;

/** No Ghidra, PDF downloads, user files or model calls. */
public final class ManualPdfPageClaimSelfTest {
    private static int assertions;
    private static void check(boolean value,String message){
        assertions++;
        if(!value)throw new AssertionError(message);
    }
    public static void main(String[] args) {
        for(String good:new String[]{
                "D-1 (PDF page 215)",
                "SIMCR D-6 PDF pages 219-220",
                "PDF pages 219–220",
                "PDF page 1",
                "PDF page 215.",
                "PDF page 215, Table D-1",
                "PDF page 215; Table D-1",
                "Appendix D, PDF page 100000"}) {
            check(ManualPdfPageClaim.hasSingleConsistentClaim(good),
                "numeric bounded claim must be accepted as a claim: "+good);
        }
        for(String bad:new String[]{
                null,"","D-6","PDF page 0","PDF page ?",
                "PDF page 220-0","PDF page 220-219",
                "PDF pages 220–219","PDF page 999999",
                "PDF page 1000000","PDF page 215-999999",
                "PDF page 215-abc","PDF page 215--216",
                "PDF page 215a","PDF page 215.5",
                "PDF page 215/216","PDF page 215 / 216",
                "PDF page 215 - abc","PDF pages 219-220x",
                "PDF pages 219-220.5","PDF pages 219-220 / 221",
                "PDF page nonsense, PDF page 215",
                "PDF page 215; PDF page nonsense",
                "PDF pages 219-220 PDF page 221",
                "PDF page 215; PDF page 215",
                "PDF page UNKNOWN","PDF pages 219-220 AMBIGUOUS",
                "PDF page 215 unverified edition",
                "PDF page 215 maybe another source",
                "PDF page 215 not checked",
                "PDF pages 219 - ?",
                "Folio D-6 (page 220)"}) {
            check(!ManualPdfPageClaim.hasSingleConsistentClaim(bad),
                "malformed or ambiguous claim must not be promoted: "+bad);
        }
        check(!ManualPdfPageClaim.hasSingleConsistentClaim(
                "PDF page 215"+" ".repeat(257)),
            "unbounded PDF label denied");
        System.out.println("ManualPdfPageClaimSelfTest PASS: assertions="+assertions);
    }
}
