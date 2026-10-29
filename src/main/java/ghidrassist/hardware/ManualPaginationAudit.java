package ghidrassist.hardware;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Audit only the relationship between two independently observed printed
 * folio CANDIDATES and their physical PDF page numbers. Never infer or
 * change a PDF page number from a printed folio.
 */
public final class ManualPaginationAudit {
    private ManualPaginationAudit(){}
    private static final Pattern FOLIO=Pattern.compile(
        "(?i)^([A-D]|[1-9][0-9]?)\\-([1-9][0-9]{0,2})$");

    public enum Status {
        NO_PREVIOUS_FOLIO, UNREADABLE_FOLIO, SECTION_CHANGED,
        SEQUENTIAL_CANDIDATE, PHYSICAL_GAP_CONSISTENT_CANDIDATE,
        DUPLICATE_FOLIO, SEQUENCE_CONFLICT_CANDIDATE
    }
    public record Result(Status status,String previous,String current,
                         int previousPdfPage,int currentPdfPage) {
        public String evidence() {
            return "printed_page_sequence_status="+status+
                " printed_page_sequence_evidence=UNVERIFIED_HEADER_CANDIDATE"+
                " printed_page_prior_pdf="+
                (previousPdfPage>0?previousPdfPage:"UNKNOWN");
        }
    }
    private record Folio(String section,int page) {}
    private static Folio parse(String label) {
        if(label==null)return null;
        Matcher m=FOLIO.matcher(label.trim().toUpperCase(Locale.ROOT));
        if(!m.matches())return null;
        try {return new Folio(m.group(1),Integer.parseInt(m.group(2)));}
        catch(NumberFormatException e){return null;}
    }
    public static Result compare(int previousPhysical,String previousPrinted,
                                 int currentPhysical,String currentPrinted) {
        if(currentPhysical<1 || previousPhysical<0 ||
                (previousPhysical>0 && previousPhysical>=currentPhysical))
            throw new IllegalArgumentException("Non-increasing physical PDF page numbers");
        Folio now=parse(currentPrinted);
        Folio prev=parse(previousPrinted);
        Status status;
        if(now==null)status=Status.UNREADABLE_FOLIO;
        else if(previousPhysical==0 || prev==null)status=Status.NO_PREVIOUS_FOLIO;
        else if(!prev.section().equals(now.section()))status=Status.SECTION_CHANGED;
        else {
            long phys=(long)currentPhysical-previousPhysical;
            long printed=(long)now.page()-prev.page();
            status=printed==0?Status.DUPLICATE_FOLIO:
                printed<0 || printed!=phys ? Status.SEQUENCE_CONFLICT_CANDIDATE:
                phys==1?Status.SEQUENTIAL_CANDIDATE:
                Status.PHYSICAL_GAP_CONSISTENT_CANDIDATE;
        }
        return new Result(status,previousPrinted,currentPrinted,
            previousPhysical,currentPhysical);
    }
}
