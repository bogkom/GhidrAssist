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
        var first=chunk(219,1,"SIMCR SHEN", "a".repeat(64), "/manual.pdf","hardware","pdf");
        var second=chunk(219,2,"MM EXOFF","a".repeat(64),"/manual.pdf","hardware","pdf");
        var page=RAGIndexedPdfPageEvidence.join(
            219,List.of(second,first));
        ok(page.physicalPage()==219 &&
            page.text().equals("SIMCR SHEN\n\nMM EXOFF") &&
            page.chunks()==2 && "a".repeat(64).equals(page.indexedSha256()) &&
            "hardware".equals(page.libraryId()),
            "Correct same-index sources joined in numeric chunk order");
        var hit=new SearchResult("manual.pdf","SIMCR",0.95,1,
            "/manual.pdf","pdf",219,false,"a".repeat(64),"hardware");
        RAGIndexedPdfPageEvidence.requireSameSource(page,hit);
        checks++;
        refuse(()->RAGIndexedPdfPageEvidence.requireSameSource(page,
            new SearchResult("manual.pdf","SIMCR",0.95,1,
                "/manual.pdf","pdf",219,false,"3456","hardware")),
            "Stale search-result SHA cannot borrow a new indexed page");
        refuse(()->RAGIndexedPdfPageEvidence.requireSameSource(page,
            new SearchResult("manual.pdf","SIMCR",0.95,1,
                "/manual.pdf","pdf",219,false,"a".repeat(64),"other")),
            "Moving source to another library invalidates former result");
        refuse(()->RAGIndexedPdfPageEvidence.requireSameSource(page,
            new SearchResult("manual.pdf","SIMCR",0.95,1,
                "/new-location.pdf","pdf",219,false,"a".repeat(64),"hardware")),
            "Same digest at another location is not the selected source");
        refuse(()->RAGIndexedPdfPageEvidence.requireSameSource(page,
            new SearchResult("manual.pdf","SIMCR",0.95,1,
                "/manual.pdf","pdf",220,false,"a".repeat(64),"hardware")),
            "Reindexed physical PDF page mismatch requires new selection");
        refuse(()->RAGIndexedPdfPageEvidence.requireSameSource(page,
            new SearchResult("manual.pdf","SIMCR",0.95,1,
                "/manual.pdf","pdf",219,false,"a".repeat(64))),
            "Legacy hit without library claim cannot inherit current page");
        var group=java.util.Map.of(
            219,new RAGIndexedPdfPageEvidence.Page(219,"SIMCR",
                "a".repeat(64),"/manual.pdf","hardware",1),
            220,new RAGIndexedPdfPageEvidence.Page(220,"SYNCR",
                "a".repeat(64),"/manual.pdf","hardware",1),
            221,new RAGIndexedPdfPageEvidence.Page(221,"STEXT",
                "a".repeat(64),"/manual.pdf","hardware",1));
        RAGIndexedPdfPageEvidence.requireOneIndexedDocument(group);
        checks++;
        var changed=new java.util.HashMap<>(group);
        changed.put(221,new RAGIndexedPdfPageEvidence.Page(221,"STEXT",
            "b".repeat(64),"/manual.pdf","hardware",1));
        refuse(()->RAGIndexedPdfPageEvidence.requireOneIndexedDocument(changed),
            "Different indexed SHA between D-5/D-6/D-7 refused");
        changed.put(221,new RAGIndexedPdfPageEvidence.Page(221,"STEXT",
            "a".repeat(64),"/other.pdf","hardware",1));
        refuse(()->RAGIndexedPdfPageEvidence.requireOneIndexedDocument(changed),
            "Other local path cannot borrow indexed source identity");
        changed.put(221,new RAGIndexedPdfPageEvidence.Page(221,"STEXT",
            "a".repeat(64),"/manual.pdf","other",1));
        refuse(()->RAGIndexedPdfPageEvidence.requireOneIndexedDocument(changed),
            "Cross-library indexed source group refused");
        changed.put(221,new RAGIndexedPdfPageEvidence.Page(221,"STEXT",
            null,"/manual.pdf","hardware",1));
        refuse(()->RAGIndexedPdfPageEvidence.requireOneIndexedDocument(changed),
            "Legacy page missing SHA cannot gain publisher-page evidence");
        changed.put(221,new RAGIndexedPdfPageEvidence.Page(220,"STEXT",
            "a".repeat(64),"/manual.pdf","hardware",1));
        refuse(()->RAGIndexedPdfPageEvidence.requireOneIndexedDocument(changed),
            "Wrong physical folio/key mismatch rejected");
        refuse(()->RAGIndexedPdfPageEvidence.requireOneIndexedDocument(
            java.util.Map.of(219,new RAGIndexedPdfPageEvidence.Page(
                219,"SIMCR","short","/manual.pdf","hardware",1))),
            "Short bogus hash is not real source evidence");
        refuse(()->RAGIndexedPdfPageEvidence.requireOneIndexedDocument(
            java.util.Map.of()),
            "Empty reviewed source group is not complete");

        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(219,2,"MM","deadbeef",
                "/manual.pdf","hardware","pdf"))),
            "Conflicting original PDF digest never silently stitched");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(219,2,"MM","a".repeat(64),
                "/another.pdf","hardware","pdf"))),
            "Filename index collision cannot borrow a different source path");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(219,2,"MM","a".repeat(64),
                "/manual.pdf","other","pdf"))),
            "Active-library scope is single-snapshot consistent");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(219,2,"MM","a".repeat(64),
                "/manual.pdf","hardware","text"))),
            "Non-PDF same-filename row cannot gain physical PDF semantics");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(220,2,"MM","a".repeat(64),
                "/manual.pdf","hardware","pdf"))),
            "Neighboring physical folio cannot be included");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(first,chunk(219,1,"another","a".repeat(64),
                "/manual.pdf","hardware","pdf"))),
            "Duplicate chunk IDs cannot overwrite source evidence");
        refuse(()->RAGIndexedPdfPageEvidence.join(219,List.of()),
            "Empty PDF source pages never become a positive citation");
        refuse(()->RAGIndexedPdfPageEvidence.join(0,List.of(first)),
            "Physical PDF folios are strictly one-based");
        refuse(()->RAGIndexedPdfPageEvidence.join(
            219,List.of(chunk(219,1,"A".repeat(
                RAGIndexedPdfPageEvidence.MAX_PAGE_CHARACTERS),
                "a".repeat(64),"/manual.pdf","hardware","pdf"),second)),
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
        // A matching pair of *absent* legacy metadata fields was formerly
        // accepted by Objects.equals(null,null), and a short digest could
        // masquerade as a proof of indexed PDF identity. Neither is enough
        // for a safe RAG document-open selection.
        var legacyPage=new RAGIndexedPdfPageEvidence.Page(
            219,"old indexed source",null,"/manual.pdf",null,1);
        refuse(()->RAGIndexedPdfPageEvidence.requireSameSource(
            legacyPage,new SearchResult("manual.pdf","excerpt",0.7,1,
                "/manual.pdf","pdf",219,false,null)),
            "matching missing source fields do not authenticate legacy PDF hit");
        var shortPage=new RAGIndexedPdfPageEvidence.Page(
            219,"old indexed source","abcd","/manual.pdf","hardware",1);
        refuse(()->RAGIndexedPdfPageEvidence.requireSameSource(
            shortPage,new SearchResult("manual.pdf","excerpt",0.7,1,
                "/manual.pdf","pdf",219,false,"abcd","hardware")),
            "matching short hashes cannot authenticate indexed document");
        var blankPath=new RAGIndexedPdfPageEvidence.Page(
            219,"old indexed source","a".repeat(64),"","hardware",1);
        refuse(()->RAGIndexedPdfPageEvidence.requireSameSource(
            blankPath,new SearchResult("manual.pdf","excerpt",0.7,1,
                "","pdf",219,false,"a".repeat(64),"hardware")),
            "matching blank paths cannot authenticate selected document");
        var spoofedPath=new RAGIndexedPdfPageEvidence.Page(
            219,"source text","a".repeat(64),"/manual\\nFAKE.pdf","hardware",1);
        refuse(()->RAGIndexedPdfPageEvidence.requireSameSource(
            spoofedPath,new SearchResult("manual.pdf","excerpt",0.7,1,
                "/manual\\nFAKE.pdf","pdf",219,false,
                "a".repeat(64),"hardware")),
            "control characters cannot spoof provenance in PDF path");
        refuse(()->RAGIndexedPdfPageEvidence.requireOneIndexedDocument(
            java.util.Map.of(219,spoofedPath)),
            "the same provenance safety bound guards page-group citations");
        var noLibrary=new RAGIndexedPdfPageEvidence.Page(
            219,"source text","a".repeat(64),"/manual.pdf",null,1);
        refuse(()->RAGIndexedPdfPageEvidence.requireSameSource(
            noLibrary,new SearchResult("manual.pdf","excerpt",0.7,1,
                "/manual.pdf","pdf",219,false,"a".repeat(64))),
            "missing library IDs cannot match as a confirmed source");
        var longLibrary=new RAGIndexedPdfPageEvidence.Page(
            219,"source text","a".repeat(64),"/manual.pdf","x".repeat(257),1);
        refuse(()->RAGIndexedPdfPageEvidence.requireSameSource(
            longLibrary,new SearchResult("manual.pdf","excerpt",0.7,1,
                "/manual.pdf","pdf",219,false,
                "a".repeat(64),"x".repeat(257))),
            "overlong RAG source metadata cannot be trusted in a selected hit");
        System.out.println("RAGIndexedPdfPageEvidenceSelfTest PASS: checks="+checks);
    }
}
