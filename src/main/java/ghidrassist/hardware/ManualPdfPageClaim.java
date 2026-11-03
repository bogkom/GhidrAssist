package ghidrassist.hardware;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * GA-06/10/16: recognizes one STRUCTURALLY CONSISTENT numeric physical-PDF
 * page claim in an untrusted label. It does NOT fetch or authenticate PDF
 * bytes, the edition, the printed folio or the claimed source contents.
 */
public final class ManualPdfPageClaim {
    private ManualPdfPageClaim() {}

    private static final Pattern CLAIM=Pattern.compile(
        "\\bPDF\\s+PAGES?\\s+([1-9][0-9]{0,5})"+
        "(?:\\s*[-–]\\s*([1-9][0-9]{0,5}))?(?![0-9–-])",
        Pattern.CASE_INSENSITIVE);

    /**
     * A unique, ascending, bounded physical page number/range claim is
     * *eligible for display as a claim*, not verified provenance.
     */
    public static boolean hasSingleConsistentClaim(String text) {
        if(text==null || text.isBlank() || text.length()>256 ||
                text.indexOf('?')>=0)return false;
        String upper=text.toUpperCase(Locale.ROOT);
        for(String unknown:new String[]{
                "UNKNOWN","UNVERIFIED","AMBIGUOUS",
                "TO BE VERIFIED","TO BE CHECKED","NOT CHECKED",
                "MAYBE","UNCERTAIN"}) {
            if(upper.contains(unknown))return false;
        }
        Matcher m=CLAIM.matcher(text);
        if(!m.find())return false;
        int first=Integer.parseInt(m.group(1));
        int last=m.group(2)==null?first:Integer.parseInt(m.group(2));
        if(first>100000 || last>100000 || last<first)return false;
        // A second page claim in the same field is ambiguous, even if it
        // repeats the first number. Never select a convenient substring.
        return !m.find();
    }
}
