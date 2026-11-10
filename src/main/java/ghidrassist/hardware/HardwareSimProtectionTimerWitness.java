package ghidrassist.hardware;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * GA-06/10/16: independent 10-field SIM protection/periodic timer
 * reference reviewed against MC68332UM Motorola 1995 D-10/D-11.
 *
 * External CI separately downloads NXP's 265-page original and checks
 * the immutable official PDF SHA-256 BEFORE extracting exact pages
 * 224 and 225. Arbitrary map text or an input SHA do NOT authenticate
 * a RAG copy, physical PDF or executed firmware.
 */
public final class HardwareSimProtectionTimerWitness {
    private HardwareSimProtectionTimerWitness(){}
    public static final int MAX_PAGES=8,MAX_PAGE_CHARS=256*1024;
    public static final int MAX_DESCRIPTION_DISTANCE=580;
    public static final String EXPECTED_PUBLISHER_SHA256=
        HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256;
    public static final String EXPECTED_EDITION=
        HardwareBitfieldSourceLedger.MC68332_EDITION_CLAIM;

    public record Reviewed(String register,String field,long mask,
            int offset,int widthBits,int physicalPage,String printedFolio,
            String heading,String meaning,boolean writeOnce) {
        public Reviewed {
            if(register==null || field==null || heading==null || meaning==null ||
                    mask==0 || offset<0 || widthBits<1 || physicalPage<1 ||
                    printedFolio==null || heading.isBlank() || meaning.isBlank())
                throw new IllegalArgumentException("Invalid reviewed register field");
        }
        public String key(){return register+"/"+field;}
    }
    /** Diagram-position masks independently reviewed on source PDF screenshots. */
    private static final List<Reviewed> REVIEWED=List.of(
        new Reviewed("SYPCR","SWE",0x80,0x0a21,8,224,"D-10",
            "SWE - Software Watchdog Enable",
            "Software watchdog disabled",true),
        new Reviewed("SYPCR","SWP",0x40,0x0a21,8,224,"D-10",
            "SWP - Software Watchdog Prescale",
            "Software watchdog clock not prescaled",true),
        new Reviewed("SYPCR","SWT",0x30,0x0a21,8,224,"D-10",
            "SWT[1:0] - Software Watchdog Timing",
            "This field selects software watchdog time-out period",true),
        new Reviewed("SYPCR","HME",0x08,0x0a21,8,224,"D-10",
            "HME - Halt Monitor Enable",
            "Disable halt monitor function",true),
        new Reviewed("SYPCR","BME",0x04,0x0a21,8,224,"D-10",
            "BME - Bus Monitor External Enable",
            "Disable bus monitor function for an internal to external bus cycle",true),
        new Reviewed("SYPCR","BMT",0x03,0x0a21,8,224,"D-10",
            "BMT[1:0] - Bus Monitor Timing",
            "This field selects bus monitor time-out period",true),
        new Reviewed("PICR","PIRQL",0x0700,0x0a22,16,225,"D-11",
            "PIRQL[2:0] - Periodic Interrupt Request Level",
            "This field determines the priority of periodic interrupt requests",false),
        new Reviewed("PICR","PIV",0x00ff,0x0a22,16,225,"D-11",
            "PIV[7:0] - Periodic Interrupt Vector",
            "interrupt vector number supplied by the SIM",false),
        new Reviewed("PITR","PTP",0x0100,0x0a24,16,225,"D-11",
            "PTP - Periodic Timer Prescaler Control",
            "Periodic timer clock not prescaled",false),
        new Reviewed("PITR","PITM",0x00ff,0x0a24,16,225,"D-11",
            "PITM[7:0] - Periodic Interrupt Timing Modulus",
            "8-bit timing modulus used to determine periodic interrupt rate",false)
    );
    public static List<Reviewed> reviewed(){return REVIEWED;}

    public record Claim(String register,String field,long mask,int offset,
            int widthBits,String pageLabel,boolean writeOnce) {
        public Claim {
            if(register==null || field==null || mask==0 ||
                    offset<0 || widthBits<1 || pageLabel==null)
                throw new IllegalArgumentException("Invalid profile claim");
        }
        public String key(){return register+"/"+field;}
    }

    public enum State {
        MATCHED_TEXT_CANDIDATE, PROFILE_FIELD_MISSING,
        MASK_WIDTH_OFFSET_OR_POLICY_DIFFERENT, DESCRIPTION_PAGE_WRONG,
        PAGE_TEXT_MISSING, PAGE_IDENTITY_MISMATCH,
        REGISTER_SECTION_MISSING, DIAGRAM_LABELS_MISSING,
        FIELD_HEADING_MISSING, MEANING_NOT_NEAR_HEADING
    }
    public record Row(Reviewed reviewed,State state,String excerpt,
            String excerptSha256) {
        public Row {
            if(reviewed==null || state==null)
                throw new IllegalArgumentException("Invalid citation row");
            if(state==State.MATCHED_TEXT_CANDIDATE) {
                if(excerpt==null || excerptSha256==null ||
                        excerpt.isBlank() || !excerptSha256.matches("[0-9a-f]{64}"))
                    throw new IllegalArgumentException("Positive citation without bounded digest");
            }else if(excerpt!=null || excerptSha256!=null)
                throw new IllegalArgumentException("Unverified row cannot retain excerpt");
        }
    }
    public record Report(String device,String expectedEdition,
            String expectedPublisherSha256,List<Row> rows,int matched,
            int unexpectedClaims) {
        public Report {
            if(device==null || expectedEdition==null || expectedPublisherSha256==null ||
                    rows==null || matched<0 || unexpectedClaims<0)
                throw new IllegalArgumentException("Invalid source report");
            rows=List.copyOf(rows);
        }
        public boolean allTenCandidatesMatch() {
            return "MC68332".equals(device) && rows.size()==10 &&
                matched==10 && unexpectedClaims==0;
        }
        public String markdown() {
            var b=new StringBuilder(
                "## GA-06/10/16 MC68332 SYPCR/PICR/PITR field citations\n\n")
                .append("- Device: ").append(device)
                .append("; publisher edition claim: ").append(expectedEdition)
                .append("; expected PDF SHA-256 (CI ONLY): ")
                .append(expectedPublisherSha256).append(".\n")
                .append("- Source fields: ").append(rows.size())
                .append("; matched text candidates: ").append(matched)
                .append("; unreviewed profile claims: ").append(unexpectedClaims)
                .append(".\n- **NO PDF AUTHENTICATION BY THIS JAVA INSPECTOR.** ")
                .append("A caller-supplied PDF page is untrusted; original publisher ")
                .append("bytes and edition must be verified independently. ")
                .append("Complete source-side literals do not establish watchdog ")
                .append("operation, timer clock, active PIT interrupt/vector, ")
                .append("hardware reset, actual MMIO writes or Review/Apply.\n\n")
                .append("| Register | Field | Reviewed mask | Physical/printed folio | ")
                .append("Status | Excerpt SHA-256 |\n|---|---|---|---|---|---|\n");
            for(var row:rows) {
                var r=row.reviewed();
                b.append("| ").append(r.register()).append(" | ")
                    .append(r.field()).append(" | 0x")
                    .append(Long.toHexString(r.mask()).toUpperCase(Locale.ROOT))
                    .append(" | PDF ").append(r.physicalPage())
                    .append(" / ").append(r.printedFolio())
                    .append(" | ").append(row.state()).append(" | ")
                    .append(row.excerptSha256()==null?"UNKNOWN":row.excerptSha256())
                    .append(" |\n");
            }
            return b.toString();
        }
    }
    private static String normalize(String source) {
        return source.replace('\u2014','-').replace('\u2013','-')
            .replace('\u2019','\'').replace('\u00a0',' ')
            .replace("\u00ad","").replace("\u0002","")
            .replaceAll("\\s+"," ").strip().toUpperCase(Locale.ROOT);
    }
    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
        }catch(NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
    private static String section(String text,String heading,String next) {
        int start=text.indexOf(heading);
        if(start<0)return null;
        int end=next==null?text.length():text.indexOf(next,start+heading.length());
        if(end<0)end=text.length();
        return text.substring(start,end);
    }
    private static boolean diagram(String register,String section) {
        if("SYPCR".equals(register))
            return section.contains("NOT USED SWE SWP SWT HME BME BMT") &&
                section.contains("15 8 7 6 5 4 3 2 1 0");
        if("PICR".equals(register))
            return section.contains("PIRQL PIV") &&
                section.contains("15 14 13 12 11 10 8 7 0");
        if("PITR".equals(register))
            return section.contains("PTP PITM") &&
                section.contains("15 14 13 12 11 10 9 8 7 0");
        return false;
    }
    /** Existing register/table D-2 address and access citation is separate. */
    public static Report inspect(HardwareProfiles.Profile profile,
            Map<Integer,String> extractedPages) {
        if(profile==null)
            throw new IllegalArgumentException("Explicit profile required");
        if(!profile.concreteDevice || !"MC68332".equals(profile.id))
            return new Report(profile.id,"UNKNOWN","UNKNOWN",List.of(),0,0);
        List<Claim> claims=new ArrayList<>();
        for(var name:List.of("SYPCR","PICR","PITR")){
            var register=profile.register(name);
            if(register==null)continue;
            for(var field:register.fields)
                claims.add(new Claim(register.name,field.name,
                    Integer.toUnsignedLong(field.mask),register.offset,
                    register.widthBits,field.sourcePage,field.writeOnceAfterReset));
        }
        return compareClaims(profile.id,claims,extractedPages);
    }
    /** Pure input seam for profile-mask, folio and unrelated-field attacks. */
    public static Report compareClaims(String device,List<Claim> claims,
            Map<Integer,String> rawPages) {
        if(device==null || claims==null || rawPages==null ||
                claims.size()>256 || rawPages.size()>MAX_PAGES)
            throw new IllegalArgumentException("Unbounded source witness");
        Map<Integer,String> pages=new HashMap<>();
        for(var e:rawPages.entrySet()) {
            if(e.getKey()==null || e.getKey()<1 || e.getKey()>100000 ||
                    e.getValue()==null || e.getValue().length()>MAX_PAGE_CHARS)
                throw new IllegalArgumentException("Invalid physical page text");
            pages.put(e.getKey(),normalize(e.getValue()));
        }
        if(!"MC68332".equals(device))
            return new Report(device,"UNKNOWN","UNKNOWN",List.of(),0,0);
        Map<String,Claim> source=new HashMap<>();
        for(var claim:claims)
            if(claim==null || source.putIfAbsent(claim.key(),claim)!=null)
                throw new IllegalArgumentException("Duplicate/null field claim");
        List<Row> rows=new ArrayList<>();
        int matches=0;
        for(var ref:REVIEWED){
            Claim claim=source.remove(ref.key());
            String page=pages.get(ref.physicalPage());
            String sectionHeading=switch(ref.register()){
                case "SYPCR" -> "D.2.12 SYPCR";
                case "PICR" -> "D.2.13 PICR";
                case "PITR" -> "D.2.14 PITR";
                default -> throw new IllegalStateException("Unknown reviewed section");
            };
            String nextHeading=switch(ref.register()){
                case "SYPCR" -> "D.2.13 PICR";
                case "PICR" -> "D.2.14 PITR";
                case "PITR" -> "D.2.15 SWSR";
                default -> throw new IllegalStateException("Unknown next section");
            };
            State state;
            String excerpt=null,exHash=null;
            if(claim==null)state=State.PROFILE_FIELD_MISSING;
            else if(claim.mask()!=ref.mask() ||
                    claim.offset()!=ref.offset() ||
                    claim.widthBits()!=ref.widthBits() ||
                    claim.writeOnce()!=ref.writeOnce())
                state=State.MASK_WIDTH_OFFSET_OR_POLICY_DIFFERENT;
            else if(!("D-"+(ref.physicalPage()-214)+
                    " (PDF page "+ref.physicalPage()+")").equals(claim.pageLabel()))
                state=State.DESCRIPTION_PAGE_WRONG;
            else if(page==null || page.isBlank())state=State.PAGE_TEXT_MISSING;
            else if(!page.contains("MC68332") ||
                    !page.contains("USER'S MANUAL") ||
                    !page.contains(ref.printedFolio()))
                state=State.PAGE_IDENTITY_MISMATCH;
            else {
                var section=section(page,sectionHeading,nextHeading);
                if(section==null)state=State.REGISTER_SECTION_MISSING;
                else if(!diagram(ref.register(),section))
                    state=State.DIAGRAM_LABELS_MISSING;
                else {
                    int at=section.indexOf(normalize(ref.heading()));
                    if(at<0)state=State.FIELD_HEADING_MISSING;
                    else {
                        int from=at+normalize(ref.heading()).length();
                        int meaning=section.indexOf(normalize(ref.meaning()),from);
                        if(meaning<from ||
                                meaning-from>MAX_DESCRIPTION_DISTANCE)
                            state=State.MEANING_NOT_NEAR_HEADING;
                        else {
                            excerpt=section.substring(at,
                                meaning+normalize(ref.meaning()).length());
                            exHash=sha256(excerpt);
                            state=State.MATCHED_TEXT_CANDIDATE;
                            matches++;
                        }
                    }
                }
            }
            rows.add(new Row(ref,state,excerpt,exHash));
        }
        return new Report(device,EXPECTED_EDITION,EXPECTED_PUBLISHER_SHA256,
            rows,matches,source.size());
    }
}
