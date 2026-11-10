package ghidrassist.core;

import java.util.List;

/** GA-06/10/16: deterministic exact-page, exact-index-provenance regression. */
public final class RAGIndexedPdfPageEvidenceSelfTest {
    private RAGIndexedPdfPageEvidenceSelfTest() {}
    private static int checks;
    private static void ok(boolean b,String why) {
        checks++;
        if(!b)throw new AssertionError(why);
    }
    private static void refuse(Runnable action,String reason) {
        boolean rejected=false;
        try {action.run();}
        catch(IllegalArgumentException expected){rejected=true;}
        ok(rejected,reason);
    }
    private static RAGIndexedPdfPageEvidence.Chunk chunk(int page,int chunk,
            String text,String sha,String path,String lib,String type) {
        return new RAGIndexedPdfPageEvidence.Chunk(
            page,chunk,text,sha,path,type,lib);
    }
    public static void main(String[] args) {
        var first=chunk(219,1,"SIMCR SHEN", "0123", "/manual.pdf","hardware","pdf");
        var second=chunk(219,2,"MM EXOFF","0123","/manual.pdf","hardware","pdf");
        var page=RAGIndexedPdfPageEvidence.join(
            219,List.of(second,first));
        ok(page.physicalPage()==219 &&
            page.text().equals("SIMCR SHEN\n\nMM EXOFF") &&
            page.chunks()==2 && "0123".equals(page.indexedSha256()) &&
            "hardware".equals(page.libraryId()),
            "Correct same-index sources joined in numeric chunk order");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(219,2,"MM","deadbeef",
                "/manual.pdf","hardware","pdf"))),
            "Conflicting original PDF digest never silently stitched");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(219,2,"MM","0123",
                "/another.pdf","hardware","pdf"))),
            "Filename index collision cannot borrow a different source path");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(219,2,"MM","0123",
                "/manual.pdf","other","pdf"))),
            "Active-library scope is single-snapshot consistent");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(219,2,"MM","0123",
                "/manual.pdf","hardware","text"))),
            "Non-PDF same-filename row cannot gain physical PDF semantics");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(220,2,"MM","0123",
                "/manual.pdf","hardware","pdf"))),
            "Neighboring physical folio cannot be included");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(219,1,"another","0123",
                "/manual.pdf","hardware","pdf"))),
            "Duplicate chunk IDs cannot overwrite source evidence");
        refuse(()->RAGIndexedPdfPageEvidence.join(219,List.of()),
            "Empty PDF source pages never become a positive citation");
        refuse(()->RAGIndexedPdfPageEvidence.join(0,List.of(first)),
            "Physical PDF folios are strictly one-based");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(chunk(219,1,"A".repeat(
                RAGIndexedPdfPageEvidence.MAX_PAGE_CHARACTERS),
                "0123","/manual.pdf","hardware","pdf"),second)),
            "Oversized multi-chunk page remains unpublishable");
        var legacy=RAGIndexedPdfPageEvidence.join(219,List.of(
            chunk(219,0,"legacy PDF text",null,"/manual.pdf",null,"pdf")));
        ok(legacy.indexedSha256()==null && legacy.libraryId()==null,
            "Legacy missing SHA/library fields remain explicitly unknown");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,java.util.Arrays.asList(first,null)),
            "Missing indexed chunk cannot trigger unchecked comparator null");
        refuse(()->new RAGIndexedPdfPageEvidence.Chunk(
            219,-1,"bad",null,null,"pdf",null),
            "Negative chunk identity rejected");
        refuse(()->new RAGIndexedPdfPageEvidence.Chunk(
            219,0,null,null,null,"pdf",null),
            "Null indexed page text rejected");
        System.out.println("RAGIndexedPdfPageEvidenceSelfTest PASS: checks="+checks);
    }
}
