package ghidrassist.hardware;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Printed page numbers are edition- and chapter-relative. Only recognize
 * candidates adjacent to a vendor page header; a body "Table D-1" is NOT
 * evidence that the current page is printed D-1.
 */
public final class ManualPrintedPage {
    private ManualPrintedPage() {}
    private static final Pattern PAGE=Pattern.compile(
        "(?i)(?<![A-Z0-9])([A-D]-[1-9][0-9]{0,2}|[1-9][0-9]?-([1-9][0-9]{0,2}))(?![A-Z0-9])");
    public record Hint(String label,String confidence) {
        public String evidence(){
            return "printed_page="+label+" printed_page_provenance="+confidence;
        }
    }
    public static Hint fromText(String text) {
        if(text==null || text.isBlank())return new Hint("UNKNOWN","UNVERIFIED");
        String[] rows=text.replace('’','\'').toUpperCase(Locale.ROOT).split("\\R");
        // PDF text should be in visual/header order. Do not search the body
        // where "Table D-1" and section cross-references are common.
        int cap=Math.min(12,rows.length);
        for(int i=0;i<cap;i++){
            if(!rows[i].contains("USER'S MANUAL"))continue;
            // Require the page label in the actual header line or immediately
            // adjacent. If two candidates appear, publish UNKNOWN.
            String near=(i>0?rows[i-1]:"")+" "+rows[i]+" "+
                (i+1<cap?rows[i+1]:"");
            Matcher m=PAGE.matcher(near);
            String one=null;
            while(m.find()){
                String label=m.group(1);
                if(one!=null && !one.equals(label))
                    return new Hint("UNKNOWN","AMBIGUOUS_HEADER");
                one=label;
            }
            if(one!=null)return new Hint(one,"PDF_TEXT_HEADER_CANDIDATE");
        }
        return new Hint("UNKNOWN","UNVERIFIED");
    }
}
