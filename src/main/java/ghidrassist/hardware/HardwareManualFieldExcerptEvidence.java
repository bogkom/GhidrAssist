package ghidrassist.hardware;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * GA-06/10/16: independent field-heading AND nearby descriptive-source
 * snippets on exact MC68332UM physical PDF folios 219–221.
 *
 * The independently reviewed 15-position diagram is a separate input:
 * neither a text hit nor a checksum supplied by a caller is proof of the
 * publisher's PDF bytes, printed edition, hardware execution or MCU identity.
 * The official Actions lane separately downloads + hashes 265 PDF pages
 * before invoking this pure, bounded inspector on extracted text.
 */
public final class HardwareManualFieldExcerptEvidence {
    private HardwareManualFieldExcerptEvidence() {}
    public static final int MAX_PAGES=16, MAX_PAGE_CHARS=256*1024;
    public static final int MAX_NEARBY=410;
    private static final String PIN=HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256;
    private static final String EDITION=HardwareBitfieldSourceLedger.MC68332_EDITION_CLAIM;

    /** Description-page folio differs from the mask's drawing page. */
    public record Reviewed(String register,String field,long mask,
            int diagramPage,int descriptionPage,String printedFolio,
            String heading,String nearbyText) {
        public Reviewed {
            if(register==null || field==null || mask==0 ||
                    descriptionPage<1 || diagramPage<1 ||
                    printedFolio==null || heading==null || nearbyText==null ||
                    heading.isBlank() || nearbyText.isBlank())
                throw new IllegalArgumentException("Malformed reviewed field");
        }
        public String key(){return register+"/"+field;}
    }
    private static final List<Reviewed> REVIEWED=List.of(
        new Reviewed("SIMCR","EXOFF",0x8000,219,219,"D-5",
            "EXOFF - External Clock Off","CLKOUT pin is driven from an internal clock source"),
        new Reviewed("SIMCR","FRZSW",0x4000,219,219,"D-5",
            "FRZSW - Freeze Software Enable","software watchdog and periodic interrupt timer"),
        new Reviewed("SIMCR","FRZBM",0x2000,219,219,"D-5",
            "FRZBM - Freeze Bus Monitor Enable","bus monitor continues to operate"),
        new Reviewed("SIMCR","SLVEN",0x0800,219,219,"D-5",
            "SLVEN - Factory Test Mode Enabled","external bus master has direct access to the IMB"),
        new Reviewed("SIMCR","SHEN",0x0300,219,219,"D-5",
            "SHEN[1:0] - Show Cycle Enable","EBI does with the external bus"),
        new Reviewed("SIMCR","SUPV",0x0080,219,220,"D-6",
            "SUPV - Supervisor/Unrestricted Data Space","SIM global registers in either supervisor or user data space"),
        new Reviewed("SIMCR","MM",0x0040,219,220,"D-6",
            "MM - Module Mapping","Internal modules are addressed from $FFF000"),
        new Reviewed("SIMCR","IARB",0x000f,219,220,"D-6",
            "IARB[3:0] - Interrupt Arbitration Field","SIM interrupt arbitration priority"),
        new Reviewed("SYNCR","W",0x8000,220,220,"D-6",
            "W - Frequency Control (VCO)","Base VCO frequency"),
        new Reviewed("SYNCR","X",0x4000,220,220,"D-6",
            "X - Frequency Control Bit (Prescale)","VCO frequency divided by four"),
        new Reviewed("SYNCR","Y",0x3f00,220,220,"D-6",
            "Y[5:0] - Frequency Control (Counter)","modulus 64 down counter"),
        new Reviewed("SYNCR","EDIV",0x0080,220,220,"D-6",
            "EDIV - ECLK Divide Rate","ECLK is system clock divided by 8"),
        new Reviewed("SYNCR","RSTEN",0x0004,220,221,"D-7",
            "RSTEN - Reset Enable","Loss of reference causes system reset"),
        new Reviewed("SYNCR","STSIM",0x0002,220,221,"D-7",
            "STSIM - Stop Mode System Integration Clock","SIM clock driven by an external source"),
        new Reviewed("SYNCR","STEXT",0x0001,220,221,"D-7",
            "STEXT - Stop Mode External Clock","CLKOUT held low during low-power stop")
    );
    public static List<Reviewed> reviewed(){return REVIEWED;}

    public enum State {
        MATCHED_TEXT_CANDIDATE, PROFILE_FIELD_MISSING,
        MASK_OR_DIAGRAM_MISMATCH, DESCRIPTION_PAGE_CLAIM_MISMATCH,
        PUBLISHER_PIN_UNMATCHED, PAGE_TEXT_MISSING,
        FOLIO_OR_MODEL_HEADER_MISMATCH, FIELD_HEADING_MISSING,
        DESCRIPTION_NOT_NEAR_HEADING
    }
    public record Citation(Reviewed reviewed,State state,
            String excerpt,String excerptSha256) {
        public Citation {
            if(reviewed==null || state==null)
                throw new IllegalArgumentException("Missing citation source");
            if(state==State.MATCHED_TEXT_CANDIDATE) {
                if(excerpt==null || excerptSha256==null ||
                        excerpt.isBlank() || !excerptSha256.matches("[0-9a-f]{64}"))
                    throw new IllegalArgumentException("Positive source requires excerpt digest");
            }else if(excerpt!=null || excerptSha256!=null)
                throw new IllegalArgumentException("Failed citation cannot retain positive evidence");
        }
    }
    public record Report(String device,String editionClaim,String pdfUrl,
            String expectedPublisherSha256,String suppliedIndexedSha256,
            List<Citation> citations,int matches,int omitted,int unexpected) {
        public Report {
            if(device==null || editionClaim==null || pdfUrl==null ||
                    expectedPublisherSha256==null || suppliedIndexedSha256==null ||
                    citations==null || matches<0 || omitted<0 || unexpected<0)
                throw new IllegalArgumentException("Unbounded citation report");
            citations=List.copyOf(citations);
        }
        public boolean allReviewedTextCandidatesMatch() {
            return "MC68332".equals(device) &&
                expectedPublisherSha256.equals(suppliedIndexedSha256) &&
                citations.size()==15 && matches==15 &&
                omitted==0 && unexpected==0;
        }
        public String markdown(){
            StringBuilder b=new StringBuilder(
                "## GA-06/10/16 MC68332UM reviewed field-description citations\n\n")
                .append("- Explicit device: ").append(device)
                .append("; manual edition **claim**: ").append(editionClaim)
                .append("; publisher URL: ").append(pdfUrl).append(".\n")
                .append("- Expected publisher PDF SHA-256: ")
                .append(expectedPublisherSha256)
                .append("; supplied index-time SHA-256: ")
                .append(suppliedIndexedSha256).append(".\n")
                .append("- Matched reviewed heading + nearby meaning candidates: ")
                .append(matches).append("; missing/mismatch: ").append(omitted)
                .append("; unexpected profile fields: ").append(unexpected)
                .append(".\n- **PURE TEXT COMPARISON, NOT PDF AUTHENTICATION.** ")
                .append("Only independent CI can check publisher bytes and ")
                .append("265-page folio mapping. Matching an index-time hash ")
                .append("does not authenticate arbitrary RAG text or the current file; ")
                .append("no active MCU/MM/VBR/ISR, reset state, executed path or ")
                .append("Review/Apply is inferred.\n\n")
                .append("| Register/field | Mask | Diagram PDF | Description folio/PDF | ")
                .append("Text status | Bounded source excerpt SHA-256 |\n")
                .append("|---|---|---|---|---|---|\n");
            for(Citation c:citations) {
                Reviewed r=c.reviewed();
                b.append("| ").append(r.key())
                 .append(" | 0x").append(Long.toHexString(r.mask()).toUpperCase(Locale.ROOT))
                 .append(" | ").append(r.diagramPage())
                 .append(" | ").append(r.printedFolio()).append(" / ")
                 .append(r.descriptionPage()).append(" | ").append(c.state())
                 .append(" | ").append(c.excerptSha256()==null?"UNKNOWN":
                    c.excerptSha256())
                 .append(" |\n");
            }
            return b.toString();
        }
    }

    private static String canonical(String text){
        return text.replace('\u2014','-').replace('\u2013','-')
            .replace('\u2212','-').replace("\u00ad","")
            .replace("\u0002","").replace('\u2019','\'')
            .replace('\u00a0',' ')
            .replaceAll("\\s+"," ").strip().toUpperCase(Locale.ROOT);
    }
    private static String sha256(String excerpt){
        try {
            byte[] bytes=MessageDigest.getInstance("SHA-256")
                .digest(excerpt.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(bytes);
        }catch(NoSuchAlgorithmException impossible){
            throw new IllegalStateException(impossible);
        }
    }
    private static boolean pageIdentity(String text,int page,String printed){
        // This is still content of untrusted PDFTextStripper output.
        // The publisher CI separately authenticates exact PDF bytes.
        return text.contains("MC68332") && text.contains("USER'S MANUAL") &&
            text.contains(printed) &&
            ((page==219 && "D-5".equals(printed)) ||
             (page==220 && "D-6".equals(printed)) ||
             (page==221 && "D-7".equals(printed)));
    }

    public static Report inspect(HardwareProfiles.Profile selectedDevice,
            Map<Integer,String> pages,String indexedSha256) {
        if(selectedDevice==null)
            throw new IllegalArgumentException("Explicit MCU profile required");
        if(!selectedDevice.concreteDevice || !"MC68332".equals(selectedDevice.id))
            return new Report(selectedDevice.id,"UNKNOWN","UNKNOWN",
                PIN,"UNKNOWN",List.of(),0,0,0);
        return compareClaims(selectedDevice.id,
            HardwareBitfieldSourceLedger.inspect(selectedDevice).entries(),
            pages,indexedSha256);
    }

    /** Package-private for deterministic adversarial register/page test input. */
    static Report compareClaims(String device,
            List<HardwareBitfieldSourceLedger.Entry> claims,
            Map<Integer,String> rawPages,String indexedSha256) {
        if(device==null || claims==null || rawPages==null ||
                claims.size()>256 || rawPages.size()>MAX_PAGES)
            throw new IllegalArgumentException("Unbounded citation source");
        Map<Integer,String> pages=new HashMap<>();
        for(var e:rawPages.entrySet()) {
            if(e.getKey()==null || e.getKey()<1 || e.getKey()>100000 ||
                    e.getValue()==null || e.getValue().length()>MAX_PAGE_CHARS)
                throw new IllegalArgumentException("Invalid physical page text");
            pages.put(e.getKey(),canonical(e.getValue()));
        }
        if(!"MC68332".equals(device))
            return new Report(device,"UNKNOWN","UNKNOWN",PIN,"UNKNOWN",
                List.of(),0,0,0);
        String declared=indexedSha256==null?"UNKNOWN":indexedSha256;
        Map<String,HardwareBitfieldSourceLedger.Entry> fields=new HashMap<>();
        for(var e:claims) {
            if(e==null || fields.putIfAbsent(e.register()+"/"+e.field(),e)!=null)
                throw new IllegalArgumentException("Duplicate/null source citation");
        }
        var diagram=HardwareBitfieldLayoutWitness.compareClaims(
            device,claims,rawPages);
        Map<String,HardwareBitfieldLayoutWitness.Row> drawings=new HashMap<>();
        for(var d:diagram.rows())drawings.put(
            d.diagram().register()+"/"+d.diagram().field(),d);
        List<Citation> citations=new ArrayList<>();
        int matched=0;
        for(Reviewed r:REVIEWED) {
            var claimed=fields.remove(r.key());
            var layout=drawings.get(r.key());
            String source=pages.get(r.descriptionPage());
            State state;
            String excerpt=null, excerptHash=null;
            if(claimed==null)state=State.PROFILE_FIELD_MISSING;
            else if(claimed.mask()!=r.mask() ||
                    layout==null ||
                    layout.diagram().physicalDiagramPage()!=r.diagramPage() ||
                    layout.state()!=HardwareBitfieldLayoutWitness.State
                        .CLAIM_MATCHES_REVIEWED_DIAGRAM)
                state=State.MASK_OR_DIAGRAM_MISMATCH;
            else if(claimed.firstPage()>r.descriptionPage() ||
                    claimed.lastPage()<r.descriptionPage())
                state=State.DESCRIPTION_PAGE_CLAIM_MISMATCH;
            else if(!PIN.equals(declared))
                state=State.PUBLISHER_PIN_UNMATCHED;
            else if(source==null || source.isBlank())
                state=State.PAGE_TEXT_MISSING;
            else if(!pageIdentity(source,r.descriptionPage(),r.printedFolio()))
                state=State.FOLIO_OR_MODEL_HEADER_MISMATCH;
            else {
                String heading=canonical(r.heading());
                String meaning=canonical(r.nearbyText());
                int at=source.indexOf(heading);
                if(at<0)state=State.FIELD_HEADING_MISSING;
                else {
                    int start=at+heading.length();
                    int found=source.indexOf(meaning,start);
                    if(found<start || found-start>MAX_NEARBY)
                        state=State.DESCRIPTION_NOT_NEAR_HEADING;
                    else {
                        int end=found+meaning.length();
                        excerpt=source.substring(at,end);
                        excerptHash=sha256(excerpt);
                        state=State.MATCHED_TEXT_CANDIDATE;
                        matched++;
                    }
                }
            }
            citations.add(new Citation(r,state,excerpt,excerptHash));
        }
        return new Report(device,EDITION,HardwareProfiles.MC68332_MANUAL,
            PIN,declared,citations,matched,REVIEWED.size()-matched,
            fields.size());
    }
}
