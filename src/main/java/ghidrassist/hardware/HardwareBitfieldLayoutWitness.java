package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * GA-06/10/16: compare MC68332 SIMCR/SYNCR profile masks with a separately
 * reviewed position map of the D-5/D-6 16-bit register diagrams.
 *
 * The source image/bit positions were reviewed against MC68332UM Motorola
 * 1995, publisher PDF SHA-256 pinned by the independent official-PDF CI job.
 * A caller-supplied extracted page does NOT authenticate its bytes; and
 * even a matched publisher layout is not proof of runtime MCU state.
 */
public final class HardwareBitfieldLayoutWitness {
    private HardwareBitfieldLayoutWitness(){}
    public static final int MAX_PAGES=16, MAX_PAGE_CHARS=256*1024;
    public static final String PUBLISHER_SHA256=
        HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256;

    public enum State {
        CLAIM_MATCHES_REVIEWED_DIAGRAM,
        MASK_DIFFERS_FROM_DIAGRAM,
        FIELD_CLAIM_MISSING,
        DIAGRAM_TEXT_UNAVAILABLE
    }

    public record DiagramField(String register,String field,int mostSignificantBit,
            int leastSignificantBit,int physicalDiagramPage,String printedDiagramPage) {
        public DiagramField {
            if(register==null || field==null || printedDiagramPage==null ||
                    mostSignificantBit>15 || leastSignificantBit<0 ||
                    mostSignificantBit<leastSignificantBit ||
                    physicalDiagramPage<1)
                throw new IllegalArgumentException("Invalid reviewed bit positions");
        }
        public long mask() {
            int bits=mostSignificantBit-leastSignificantBit+1;
            return ((1L<<bits)-1)<<leastSignificantBit;
        }
    }
    // Positions independently inspected in publisher MC68332UM Appendix D.
    // The field DESCRIPTION can be on D-6/D-7; the BIT DIAGRAM is on
    // physical page 219 for SIMCR and page 220 for SYNCR.
    private static final List<DiagramField> REVIEWED=List.of(
        new DiagramField("SIMCR","EXOFF",15,15,219,"D-5"),
        new DiagramField("SIMCR","FRZSW",14,14,219,"D-5"),
        new DiagramField("SIMCR","FRZBM",13,13,219,"D-5"),
        new DiagramField("SIMCR","SLVEN",11,11,219,"D-5"),
        new DiagramField("SIMCR","SHEN",9,8,219,"D-5"),
        new DiagramField("SIMCR","SUPV",7,7,219,"D-5"),
        new DiagramField("SIMCR","MM",6,6,219,"D-5"),
        new DiagramField("SIMCR","IARB",3,0,219,"D-5"),
        new DiagramField("SYNCR","W",15,15,220,"D-6"),
        new DiagramField("SYNCR","X",14,14,220,"D-6"),
        new DiagramField("SYNCR","Y",13,8,220,"D-6"),
        new DiagramField("SYNCR","EDIV",7,7,220,"D-6"),
        new DiagramField("SYNCR","RSTEN",2,2,220,"D-6"),
        new DiagramField("SYNCR","STSIM",1,1,220,"D-6"),
        new DiagramField("SYNCR","STEXT",0,0,220,"D-6")
    );
    public static List<DiagramField> reviewedPositions() {return REVIEWED;}

    public record Row(DiagramField diagram,Long profileMask,
            String claimedDescriptionPages,State state) {
        public Row {
            if(diagram==null || claimedDescriptionPages==null || state==null)
                throw new IllegalArgumentException("Invalid bit layout comparison");
        }
    }
    public record Report(String device,String expectedPublisherPdfSha256,
            List<Row> rows,int matches,int mismatches,int missingOrUnverifiable,
            int unexpectedProfileFields) {
        public Report {
            if(device==null || expectedPublisherPdfSha256==null ||
                    rows==null || matches<0 || mismatches<0 ||
                    missingOrUnverifiable<0 || unexpectedProfileFields<0)
                throw new IllegalArgumentException("Invalid bit diagram report");
            rows=List.copyOf(rows);
        }
        public boolean allReviewedMasksMatch() {
            return "MC68332".equals(device) && rows.size()==15 &&
                matches==15 && mismatches==0 && missingOrUnverifiable==0 &&
                unexpectedProfileFields==0;
        }
        public String markdown() {
            var out=new StringBuilder(
                "## GA-06/10/16 reviewed SIMCR/SYNCR bit diagram comparison\n\n")
                .append("- Explicit device scope: ").append(device)
                .append("; publisher SHA-256 **expected in CI**, not ")
                .append("authenticated for caller supplied text: ")
                .append(expectedPublisherPdfSha256).append(".\n")
                .append("- Reviewed diagram/claimed mask matches: ")
                .append(matches).append("; mismatched masks: ")
                .append(mismatches).append("; missing/uncertain page text: ")
                .append(missingOrUnverifiable).append("; unexpected profile fields: ")
                .append(unexpectedProfileFields).append(".\n")
                .append("- **DIAGRAM POSITION REVIEW ONLY.** Matching masks ")
                .append("are compared with a separately reviewed image of the ")
                .append("publisher manual, with diagram row/text and PDF SHA-256 ")
                .append("independently gated in GitHub Actions. Supplied text ")
                .append("alone proves no PDF identity, bit semantics, reset ")
                .append("values, active SIMCR/MM, execution or Review/Apply.\n\n")
                .append("| Register | Field | Reviewed diagram bits | ")
                .append("Reviewed mask | Profile mask | Diagram folio | ")
                .append("Separate description page claim | Status |\n")
                .append("|---|---|---|---|---|---|---|---|\n");
            for(var row:rows) {
                var d=row.diagram();
                out.append("| ").append(d.register()).append(" | ")
                    .append(d.field()).append(" | ")
                    .append(d.mostSignificantBit());
                if(d.leastSignificantBit()!=d.mostSignificantBit())
                    out.append(":").append(d.leastSignificantBit());
                out.append(" | ").append(hex(d.mask()))
                    .append(" | ").append(row.profileMask()==null?
                        "UNKNOWN":hex(row.profileMask()))
                    .append(" | ").append(d.printedDiagramPage())
                    .append(" / PDF ").append(d.physicalDiagramPage())
                    .append(" | ").append(row.claimedDescriptionPages())
                    .append(" | ").append(row.state()).append(" |\n");
            }
            return out.toString();
        }
    }
    private static String hex(long mask) {
        return String.format(Locale.ROOT,"0x%04X",mask);
    }

    private static boolean diagramAvailable(int page,Map<Integer,String> text) {
        String content=text.get(page);
        if(content==null || content.isBlank())return false;
        String normalized=content.replace('\u00a0',' ')
            .replaceAll("\\s+"," ").toUpperCase(Locale.ROOT);
        if(page==219)
            return normalized.contains("D.2.1 SIMCR") &&
                normalized.contains("15 14 13 12 11 10 9 8 7 6 5 4 3 0") &&
                normalized.contains(
                    "EXOFF FRZSW FRZBM 0 SLVEN 0 SHEN SUPV MM 0 0 IARB");
        if(page==220)
            return normalized.contains("D.2.3 SYNCR") &&
                normalized.contains("15 14 13 8 7 6 5 4 3 2 1 0") &&
                normalized.contains(
                    "W X Y EDIV 0 0 SLIMP SLOCK RSTEN STSIM STEXT");
        return false;
    }

    /** Pure source-only check: neither hashes nor parses any local PDF. */
    public static Report inspect(HardwareProfiles.Profile profile,
                                  Map<Integer,String> extractedPages) {
        if(profile==null)
            throw new IllegalArgumentException("Explicit MCU profile required");
        return compareClaims(profile.id,
            HardwareBitfieldSourceLedger.inspect(profile).entries(),
            extractedPages);
    }

    /** Exposes only candidate comparisons, useful for malformed-profile tests. */
    public static Report compareClaims(String device,
            List<HardwareBitfieldSourceLedger.Entry> claims,
            Map<Integer,String> extractedPages) {
        if(device==null || claims==null || extractedPages==null ||
                claims.size()>256 || extractedPages.size()>MAX_PAGES)
            throw new IllegalArgumentException("Unbounded layout audit");
        Map<Integer,String> texts=new HashMap<>();
        for(var e:extractedPages.entrySet()) {
            if(e.getKey()==null || e.getKey()<1 || e.getKey()>100000 ||
                    e.getValue()==null || e.getValue().length()>MAX_PAGE_CHARS)
                throw new IllegalArgumentException("Invalid physical PDF page text");
            texts.put(e.getKey(),e.getValue());
        }
        if(!"MC68332".equals(device))
            return new Report(device,"UNKNOWN",List.of(),0,0,0,0);
        Map<String,HardwareBitfieldSourceLedger.Entry> fields=new HashMap<>();
        for(var e:claims) {
            if(e==null || fields.putIfAbsent(e.register()+"/"+e.field(),e)!=null)
                throw new IllegalArgumentException("Duplicate/null bitfield source claim");
        }
        List<Row> rows=new ArrayList<>();
        int matches=0,mismatches=0,missing=0;
        for(DiagramField d:REVIEWED) {
            var source=fields.remove(d.register()+"/"+d.field());
            String pages=source==null?"UNKNOWN":source.firstPage()==source.lastPage()?
                Integer.toString(source.firstPage()):
                source.firstPage()+"-"+source.lastPage();
            Long mask=source==null?null:source.mask();
            State state;
            if(source==null)state=State.FIELD_CLAIM_MISSING;
            else if(!diagramAvailable(d.physicalDiagramPage(),texts))
                state=State.DIAGRAM_TEXT_UNAVAILABLE;
            else if(source.mask()!=d.mask())state=State.MASK_DIFFERS_FROM_DIAGRAM;
            else state=State.CLAIM_MATCHES_REVIEWED_DIAGRAM;
            switch(state) {
                case CLAIM_MATCHES_REVIEWED_DIAGRAM -> matches++;
                case MASK_DIFFERS_FROM_DIAGRAM -> mismatches++;
                default -> missing++;
            }
            rows.add(new Row(d,mask,pages,state));
        }
        return new Report(device,PUBLISHER_SHA256,rows,matches,
            mismatches,missing,fields.size());
    }
}
