package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * GA-06/10/16: source-only comparison of ten selected MC68332 SIM D-2
 * register rows, after independent visual inspection of the table image.
 * This does NOT authenticate supplied PDF text, imply a running MM mode,
 * or decode a physical external chip-select map.
 */
public final class HardwareSimD2RegisterWitness {
    private HardwareSimD2RegisterWitness(){}
    public static final int MAX_PAGE_CHARS=256*1024;
    public static final String PUBLISHER_PIN=
        HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256;
    public record Reference(String name,int offset,int widthBits,
            HardwareProfiles.Access access,int physicalPage,String printedPage) {
        public Reference {
            if(name==null || !name.matches("[A-Z0-9]{3,20}") ||
                    offset<0 || offset>=0x1000 ||
                    (widthBits!=8 && widthBits!=16) ||
                    access==null || physicalPage<1 || printedPage==null)
                throw new IllegalArgumentException("Bad reviewed SIM row");
        }
        public String tableAddress(){
            // Table D-2 prints aligned 16-bit ROW addresses, even when
            // only the lower byte at offset+1 implements an 8-bit register.
            // The profile must retain the real odd byte address.
            return String.format(Locale.ROOT,"$YFF%03X",
                widthBits==8?offset&~1:offset);
        }
    }
    public static final List<Reference> REVIEWED=List.of(
        new Reference("PORTE0",0x0a11,8,
            HardwareProfiles.Access.CONFIGURABLE_SUPERVISOR_USER,218,"D-4"),
        new Reference("DDRE",0x0a15,8,
            HardwareProfiles.Access.CONFIGURABLE_SUPERVISOR_USER,218,"D-4"),
        new Reference("PFPAR",0x0a1f,8,
            HardwareProfiles.Access.SUPERVISOR,218,"D-4"),
        new Reference("SYPCR",0x0a21,8,
            HardwareProfiles.Access.SUPERVISOR,218,"D-4"),
        new Reference("SWSR",0x0a27,8,
            HardwareProfiles.Access.SUPERVISOR,218,"D-4"),
        new Reference("CSPAR0",0x0a44,16,
            HardwareProfiles.Access.SUPERVISOR,218,"D-4"),
        new Reference("CSPAR1",0x0a46,16,
            HardwareProfiles.Access.SUPERVISOR,218,"D-4"),
        new Reference("CSBAR0",0x0a4c,16,
            HardwareProfiles.Access.SUPERVISOR,218,"D-4"),
        new Reference("CSBAR8",0x0a6c,16,
            HardwareProfiles.Access.SUPERVISOR,219,"D-5"),
        new Reference("CSOR8",0x0a6e,16,
            HardwareProfiles.Access.SUPERVISOR,219,"D-5")
    );
    public enum State {
        MATCHED_TABLE_AND_PROFILE, TABLE_ROW_MISSING,
        PROFILE_DEFINITION_DIFFERENT, PROFILE_REGISTER_MISSING,
        TABLE_PAGE_MISSING
    }
    public record Row(Reference reviewed,State state,String profileSourcePage) {}
    public record Result(String device,int matched,int incomplete,
            List<Row> rows) {
        public Result {rows=List.copyOf(rows);}
        public boolean completeSample(){
            return "MC68332".equals(device) && matched==REVIEWED.size() &&
                incomplete==0 && rows.size()==REVIEWED.size();
        }
        public String markdown(){
            var s=new StringBuilder(
                "## MC68332 SIM Table D-2 bounded register source witnesses\n\n")
                .append("- Explicit device: ").append(device)
                .append("; source PDF pin: ").append(PUBLISHER_PIN)
                .append(" (validated ONLY by separate publisher CI, not local text).\n")
                .append("- Matched table-and-profile source claims: ")
                .append(matched).append("; incomplete/changed: ")
                .append(incomplete).append(".\n")
                .append("- **SOURCE ROW ONLY**: register offset, access class ")
                .append("and width are still *static* device-profile facts. ")
                .append("Not MCU execution, configured MM, CSBAR/CSOR physical ")
                .append("mapping, read/write policy or Review/Apply permission.\n\n")
                .append("| Name | Table address claim | Register offset | ")
                .append("Width | Access class | Printed/PDF table page | ")
                .append("Profile source page | State |\n")
                .append("|---|---|---|---:|---|---|---|---|\n");
            for(var r:rows){
                var v=r.reviewed();
                s.append("| ").append(v.name()).append(" | ")
                 .append(v.tableAddress()).append(" | 0x")
                 .append(String.format(Locale.ROOT,"%04X",v.offset()))
                 .append(" | ").append(v.widthBits())
                 .append(" | ").append(v.access())
                 .append(" | ").append(v.printedPage()).append("/PDF ")
                 .append(v.physicalPage())
                 .append(" | ").append(r.profileSourcePage())
                 .append(" | ").append(r.state()).append(" |\n");
            }
            return s.toString();
        }
    }
    private static boolean rowInPage(Reference reference,String text) {
        // The PDF text layer may wrap one long table cell onto a second
        // line (e.g. SYPCR). Never search an adjacent register row for the
        // missing name; a bounded negative lookahead stops at next address.
        String normalized=text.replace('\u00a0',' ').toUpperCase(Locale.ROOT);
        String address=Pattern.quote(reference.tableAddress());
        String token=Pattern.quote(reference.name());
        return Pattern.compile(address+
            "(?:(?!\\$YFFA[0-9A-F]{2})[\\s\\S]){0,160}?"+
            "(?<![A-Z0-9_])"+token+"(?![A-Z0-9_])")
            .matcher(normalized).find();
    }
    public static Result inspect(HardwareProfiles.Profile profile,
                                  Map<Integer,String> extractedPages){
        if(profile==null || extractedPages==null ||
                extractedPages.size()>2)
            throw new IllegalArgumentException("Explicit device and two-page budget required");
        var pages=new TreeMap<Integer,String>();
        for(var e:extractedPages.entrySet()){
            if(e.getKey()==null || (e.getKey()!=218 && e.getKey()!=219) ||
                    e.getValue()==null || e.getValue().length()>MAX_PAGE_CHARS)
                throw new IllegalArgumentException("Unexpected physical PDF page");
            pages.put(e.getKey(),e.getValue());
        }
        if(!profile.concreteDevice || !"MC68332".equals(profile.id))
            return new Result(profile.id,0,0,List.of());
        int valid=0,invalid=0;
        var rows=new ArrayList<Row>();
        for(var r:REVIEWED){
            var live=profile.register(r.name());
            String page=live==null?"UNKNOWN":live.sourcePage;
            State state;
            if(live==null)state=State.PROFILE_REGISTER_MISSING;
            else if(live.offset!=r.offset() ||
                    live.widthBits!=r.widthBits() ||
                    live.access!=r.access() ||
                    !HardwareProfileAudit.physicalPage(live.sourcePage) ||
                    !live.sourcePage.contains("PDF page "+r.physicalPage()+")"))
                state=State.PROFILE_DEFINITION_DIFFERENT;
            else if(!pages.containsKey(r.physicalPage()) ||
                    pages.get(r.physicalPage()).isBlank())
                state=State.TABLE_PAGE_MISSING;
            else if(!rowInPage(r,pages.get(r.physicalPage())))
                state=State.TABLE_ROW_MISSING;
            else state=State.MATCHED_TABLE_AND_PROFILE;
            if(state==State.MATCHED_TABLE_AND_PROFILE)valid++;
            else invalid++;
            rows.add(new Row(r,state,page));
        }
        return new Result(profile.id,valid,invalid,rows);
    }
}
