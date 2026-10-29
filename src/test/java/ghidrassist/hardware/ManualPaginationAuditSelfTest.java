package ghidrassist.hardware;

public final class ManualPaginationAuditSelfTest {
    private static void check(boolean b,String s){if(!b)throw new AssertionError(s);}
    private static ManualPaginationAudit.Status compare(int before,String old,
            int after,String now){
        return ManualPaginationAudit.compare(before,old,after,now).status();
    }
    public static void main(String[] args){
        var seq=ManualPaginationAudit.compare(215,"D-1",216,"D-2");
        check(seq.status()==ManualPaginationAudit.Status.SEQUENTIAL_CANDIDATE &&
            seq.evidence().contains("UNVERIFIED_HEADER_CANDIDATE") &&
            seq.evidence().contains("printed_page_prior_pdf=215"),
            "adjacent printed folio is still only a candidate");
        check(compare(215,"D-1",218,"D-4")==
            ManualPaginationAudit.Status.PHYSICAL_GAP_CONSISTENT_CANDIDATE,
            "physical and printed page gaps agree");
        check(compare(215,"D-1",218,"D-2")==
            ManualPaginationAudit.Status.SEQUENCE_CONFLICT_CANDIDATE,
            "candidate inconsistent with actual PDF page distance");
        check(compare(215,"D-1",216,"D-1")==
            ManualPaginationAudit.Status.DUPLICATE_FOLIO,
            "duplicate printed folio not silently promoted");
        check(compare(215,"D-10",216,"D-9")==
            ManualPaginationAudit.Status.SEQUENCE_CONFLICT_CANDIDATE,
            "backward numbering is uncertain");
        check(compare(215,"D-99",216,"5-1")==
            ManualPaginationAudit.Status.SECTION_CHANGED,
            "chapter transition not guessed continuous");
        check(compare(0,null,1,"D-1")==
            ManualPaginationAudit.Status.NO_PREVIOUS_FOLIO,
            "first page cannot have neighbor evidence");
        check(compare(215,"D-1",216,"UNKNOWN")==
            ManualPaginationAudit.Status.UNREADABLE_FOLIO,
            "unknown page never inferred from predecessor");
        check(compare(215,"Table D-1",216,"D-2")==
            ManualPaginationAudit.Status.NO_PREVIOUS_FOLIO,
            "body table number not considered a printed page");
        boolean bad=false;
        try{compare(216,"D-2",215,"D-1");}
        catch(IllegalArgumentException e){bad=true;}
        check(bad,"physical PDF order must be increasing");
        System.out.println("ManualPaginationAuditSelfTest OK");
    }
}
