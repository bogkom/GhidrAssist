package ghidrassist.hardware;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Printed page numbers are edition- and chapter-relative. Only recognize
 * candidates at an actual vendor manual header/footer. A nearby body
 * "Table D-1" is never a printed folio.
 *
 * This class does NOT verify the claimed folio, edition or physical PDF page.
 */
public final class ManualPrintedPage {
    private ManualPrintedPage() {}
    /** Bound untrusted PDFBox-extracted text before uppercasing/splitting. */
    public static final int MAX_PAGE_TEXT_CHARS=1_048_576;
    private static final Pattern PAGE=Pattern.compile(
        "(?i)(?<![A-Z0-9])([A-D]-[1-9][0-9]{0,2}|[1-9][0-9]?-([1-9][0-9]{0,2}))(?![A-Z0-9])");
    private static final Pattern STANDALONE=Pattern.compile(
        "(?i)^\\s*(?:(?:PAGE|P\\.|FOLIO)\\s*[:#-]?\\s*)?"+
        "([A-D]-[1-9][0-9]{0,2}|[1-9][0-9]?-([1-9][0-9]{0,2}))\\s*$");
    private static final Pattern BODY_LABEL=Pattern.compile(
        "(?i).*\\b(?:TABLE|FIGURE|FIG\\.?|SECTION|CHAPTER|APPENDIX)\\s*$");
    public record Hint(String label,String confidence) {
        public String evidence(){
            return "printed_page="+label+" printed_page_provenance="+confidence;
        }
    }
    private static String consumeLabel(String previous,String label) {
        // Do not silently choose the first header if multiple candidate
        // headers or adjacent standalone folios disagree on the same page.
        if(previous==null || previous.equals(label))return label;
        return "AMBIGUOUS";
    }
    public static Hint fromText(String text) {
        if(text==null || text.isBlank())return new Hint("UNKNOWN","UNVERIFIED");
        if(text.length()>MAX_PAGE_TEXT_CHARS)
            return new Hint("UNKNOWN","PDF_TEXT_TOO_LARGE");
        String[] rows=text.replace('’','\'').toUpperCase(Locale.ROOT).split("\\R");
        // Manufacturer folio is often at the bottom of the extracted page.
        // Scan the top and bottom only; never mine arbitrary page body text.
        int head=Math.min(12,rows.length);
        int tail=Math.max(head,rows.length-12);
        String selected=null;
        for(int i=0;i<rows.length;i++){
            if(i>=head && i<tail)continue;
            if(!rows[i].contains("USER'S MANUAL"))continue;
            // A true folio may be in the manual header itself. Do not use
            // "TABLE D-1", "FIGURE 5-20", etc., even within that line.
            Matcher header=PAGE.matcher(rows[i]);
            while(header.find()){
                if(BODY_LABEL.matcher(rows[i].substring(0,header.start())).matches())
                    continue;
                selected=consumeLabel(selected,header.group(1));
                if("AMBIGUOUS".equals(selected))
                    return new Hint("UNKNOWN","AMBIGUOUS_HEADER");
            }
            // Adjacent lines must consist solely of a folio (optionally
            // prefixed by "Page"/"Folio"). The previous implementation
            // concatenated surrounding lines and mistook "Table D-1"
            // immediately below USER'S MANUAL for the page label.
            for(int adjacent:new int[]{i-1,i+1}){
                if(adjacent<0 || adjacent>=rows.length)continue;
                Matcher standalone=STANDALONE.matcher(rows[adjacent]);
                if(!standalone.matches())continue;
                selected=consumeLabel(selected,standalone.group(1));
                if("AMBIGUOUS".equals(selected))
                    return new Hint("UNKNOWN","AMBIGUOUS_HEADER");
            }
        }
        return selected!=null?
            new Hint(selected,"PDF_TEXT_HEADER_CANDIDATE"):
            new Hint("UNKNOWN","UNVERIFIED");
    }
}
