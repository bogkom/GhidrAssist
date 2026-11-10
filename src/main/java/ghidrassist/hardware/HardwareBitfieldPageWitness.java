package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
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
            if(register==null || register.isBlank() || field==null ||
                    field.isBlank() || mask<=0 || (mask&0xffff0000)!=0 ||
                    state==null || firstPage<1 || lastPage<firstPage ||
                    lastPage>100000 || matchedPhysicalPages==null ||
                    matchedPhysicalPages.size()>MAX_PAGES ||
                    matchedPhysicalPages.stream().anyMatch(Objects::isNull) ||
                    (state==State.NAME_ON_CLAIMED_PAGE) !=
                        !matchedPhysicalPages.isEmpty() ||
                    state==State.NAME_ON_CLAIMED_PAGE && field.length()<4)
                throw new IllegalArgumentException("Invalid physical page witness");
            int previous=firstPage-1;
            for(int page:matchedPhysicalPages) {
                if(page<=previous || page>lastPage)
                    throw new IllegalArgumentException(
                        "Unordered or out-of-range physical PDF witness");
                previous=page;
            }
            matchedPhysicalPages=List.copyOf(matchedPhysicalPages);
        }
    }
    public record Result(String profile,String manualUrl,String editionClaim,
                         String publisherPdfSha256,
                         int sourceEntries,int matched,int missing,
                         int ambiguous,List<Row> rows) {
        public Result {
            if(profile==null || manualUrl==null || editionClaim==null ||
                    publisherPdfSha256==null || rows==null ||
                    rows.size()>256 || rows.stream().anyMatch(Objects::isNull) ||
                    sourceEntries!=rows.size() || matched<0 || missing<0 ||
                    ambiguous<0 || matched+missing+ambiguous!=sourceEntries)
                throw new IllegalArgumentException("Inconsistent physical PDF source report");
            if("MC68332".equals(profile)) {
                // Only the built-in, explicitly selected 15-field device
                // source ledger may acquire the publisher's expected pin.
                // The pin is a claim, NOT authentication of supplied text.
                if(!HardwareProfiles.MC68332_MANUAL.equals(manualUrl) ||
                        !HardwareBitfieldSourceLedger.MC68332_EDITION_CLAIM
                            .equals(editionClaim) ||
                        !HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256
                            .equals(publisherPdfSha256))
                    throw new IllegalArgumentException("Foreign MC68332 source metadata");
                var reviewed=HardwareBitfieldSourceLedger.inspect(
                    HardwareProfiles.mc68332()).entries();
                if(rows.size()!=reviewed.size())
                    throw new IllegalArgumentException("Missing reviewed PDF fields");
                for(int i=0;i<rows.size();i++) {
                    Row row=rows.get(i);
                    var source=reviewed.get(i);
                    if(!row.register().equals(source.register()) ||
                            !row.field().equals(source.field()) ||
                            Integer.toUnsignedLong(row.mask())!=source.mask() ||
                            row.firstPage()!=source.firstPage() ||
                            row.lastPage()!=source.lastPage())
                        throw new IllegalArgumentException(
                            "Reordered, altered or foreign PDF field source");
                }
            }else if(!rows.isEmpty() || sourceEntries!=0 ||
                    !manualUrl.equals("UNKNOWN") ||
                    !editionClaim.equals("UNKNOWN") ||
                    !publisherPdfSha256.equals("UNKNOWN"))
                throw new IllegalArgumentException(
                    "Generic CPU32 cannot publish MC68332 field evidence");
            int m=0,a=0;
            for(Row row:rows) {
                if(row.state()==State.NAME_ON_CLAIMED_PAGE)m++;
                else if(row.state()==State.SHORT_NAME_AMBIGUOUS)a++;
            }
            if(m!=matched || a!=ambiguous)
                throw new IllegalArgumentException(
                    "Forged PDF field token or ambiguity count");
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
