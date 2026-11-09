package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * GA-06/10/16: source-only checks of bitfield names in the *text extracted*
 * from exact claimed physical PDF folios. These text tokens do not prove
 * field masks, reset conditions, edition, applicability or execution.
 *
 * PDF download, checksum, page count and extraction happen in the
 * independent pinned-publisher CI lane. Arbitrary caller-provided text
 * remains untrusted even when it contains the expected token.
 */
public final class HardwareBitfieldPageWitness {
    private HardwareBitfieldPageWitness(){}
    public static final int MAX_PAGES=16, MAX_PAGE_CHARS=256*1024;
    public enum State {
        NAME_ON_CLAIMED_PAGE, NAME_NOT_ON_CLAIMED_PAGE,
        PAGE_TEXT_MISSING, SHORT_NAME_AMBIGUOUS,
        FIELD_PAGE_CLAIM_UNUSABLE
    }
    public record Row(String register,String field,int mask,
                      int firstPage,int lastPage,State state,
                      List<Integer> matchedPhysicalPages) {
        public Row {
            if(register==null || field==null || mask==0 || state==null ||
                    firstPage<1 || lastPage<firstPage ||
                    matchedPhysicalPages==null)
                throw new IllegalArgumentException("Invalid physical page witness");
            matchedPhysicalPages=List.copyOf(matchedPhysicalPages);
        }
    }
    public record Result(String profile,String manualUrl,String editionClaim,
                         String publisherPdfSha256,
                         int sourceEntries,int matched,int missing,
                         int ambiguous,List<Row> rows) {
        public Result {
            rows=List.copyOf(rows);
        }
        public String markdown() {
            var b=new StringBuilder("## GA-06/10/16 MC68332 physical PDF field-name witness\n\n")
                .append("- Device: ").append(profile)
                .append("; manual: ").append(manualUrl)
                .append("; edition **claim**: ").append(editionClaim).append(".\n")
                .append("- Publisher PDF SHA-256 pin (external CI, NOT verified ")
                .append("for caller-supplied text): ")
                .append(publisherPdfSha256).append(".\n")
                .append("- Field entries: ").append(sourceEntries)
                .append("; name tokens on claimed folios: ").append(matched)
                .append("; missing/absent text: ").append(missing)
                .append("; ambiguous/short tokens: ").append(ambiguous).append(".\n")
                .append("- **TEXT TOKEN ONLY; NOT A VERIFIED BITFIELD DEFINITION.** ")
                .append("The token is neither a mask/value/edition/page-layout ")
                .append("verification nor proof of MCU applicability, active ")
                .append("SIMCR/MM, instruction execution, reset state or Review/Apply. ")
                .append("Local/RAG PDF bytes are NOT authenticated.\n\n");
            if(rows.isEmpty())return b.append("No device-specific sources.\n").toString();
            b.append("| Register | Field | Mask claim | Physical PDF page claim | ")
             .append("Text token status | Matching folios |\n")
             .append("|---|---|---|---|---|---|\n");
            for(var r:rows) {
                b.append("| ").append(r.register()).append(" | ").append(r.field())
                 .append(" | ").append(String.format(Locale.ROOT,
                    "0x%08X",Integer.toUnsignedLong(r.mask())))
                 .append(" | ").append(r.firstPage());
                if(r.lastPage()!=r.firstPage())b.append("-").append(r.lastPage());
                b.append(" | ").append(r.state()).append(" | ");
                if(r.matchedPhysicalPages().isEmpty())b.append("UNKNOWN");
                else for(int i=0;i<r.matchedPhysicalPages().size();i++) {
                    if(i>0)b.append(",");
                    b.append(r.matchedPhysicalPages().get(i));
                }
                b.append(" |\n");
            }
            return b.toString();
        }
    }

    /**
     * Recognizes full literal field tokens only. A bare W/X/Y or MM is not
     * sufficiently discriminative in extracted prose and must be reviewed
     * manually. Never search neighboring pages to fix a wrong page claim.
     */
    public static Result inspect(HardwareProfiles.Profile profile,
                                 Map<Integer,String> extractedPages) {
        if(profile==null || extractedPages==null ||
                extractedPages.size()>MAX_PAGES)
            throw new IllegalArgumentException("Unbounded PDF text witness");
        var pages=new TreeMap<Integer,String>();
        for(var entry:extractedPages.entrySet()) {
            if(entry.getKey()==null || entry.getKey()<1 ||
                    entry.getKey()>100000 ||
                    entry.getValue()==null ||
                    entry.getValue().length()>MAX_PAGE_CHARS)
                throw new IllegalArgumentException("Invalid PDF page text");
            pages.put(entry.getKey(),entry.getValue());
        }
        var ledger=HardwareBitfieldSourceLedger.inspect(profile);
        List<Row> rows=new ArrayList<>();
        int matched=0,missing=0,ambiguous=0;
        for(var field:ledger.entries()) {
            int first=field.firstPage(),last=field.lastPage();
            State state;
            List<Integer> found=new ArrayList<>();
            if(first<1 || last<first || last-first>MAX_PAGES) {
                state=State.FIELD_PAGE_CLAIM_UNUSABLE;
            }else if(field.field().length()<4) {
                // E.g. "MM" or "W" may appear in unrelated PDF prose.
                state=State.SHORT_NAME_AMBIGUOUS;
            }else {
                boolean missingText=false;
                var token=Pattern.compile("(?<![A-Za-z0-9_])"+
                    Pattern.quote(field.field())+"(?![A-Za-z0-9_])",
                    Pattern.CASE_INSENSITIVE);
                for(int page=first;page<=last;page++) {
                    String text=pages.get(page);
                    if(text==null || text.isBlank()) {
                        missingText=true;continue;
                    }
                    if(token.matcher(text).find())found.add(page);
                }
                state=missingText?State.PAGE_TEXT_MISSING:
                    found.isEmpty()?State.NAME_NOT_ON_CLAIMED_PAGE:
                    State.NAME_ON_CLAIMED_PAGE;
                // Missing any claimed physical folio prevents calling the
                // multi-page citation positively verified as a text source.
                if(missingText)found.clear();
            }
            if(state==State.NAME_ON_CLAIMED_PAGE)matched++;
            else if(state==State.SHORT_NAME_AMBIGUOUS)ambiguous++;
            else missing++;
            rows.add(new Row(field.register(),field.field(),
                (int)field.mask(),first,last,state,found));
        }
        return new Result(ledger.device(),ledger.manualUrl(),
            ledger.editionClaim(),ledger.device().equals("MC68332")?
                HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256:"UNKNOWN",
            rows.size(),matched,missing,ambiguous,rows);
    }
}
