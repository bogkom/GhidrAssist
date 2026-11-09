package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * GA-06/10/16: bounded independent source-row witness for MC68332 chip-select
 * register *addresses* in the publisher's MC68332UM Table D-2.
 *
 * Exact page/row evidence is not a proof of CS assertion, external bus map,
 * active SIMCR MM, CS register field meanings, or local/RAG PDF provenance.
 * Publisher SHA and PDF pagination are verified separately in CI.
 */
public final class HardwareSimChipSelectTableWitness {
    private HardwareSimChipSelectTableWitness() {}

    public static final int PDF_D4=218;
    public static final int PDF_D5=219;
    public static final int MAX_TEXT_CHARS=256*1024;
    public static final int EXPECTED_ROWS=26;
    private static final Pattern TABLE_ROW=Pattern.compile(
        "(?im)\\$YFFA([0-9A-F]{2})\\s+CHIP-SELECT\\s+"+
        "(PIN ASSIGNMENT|BASE|OPTION)\\s*"+
        "(BOOT|10|[0-9])?\\s*\\((CSPAR[01]|CSBARBT|CSORBT|"+
        "CSBAR(?:10|[0-9])|CSOR(?:10|[0-9]))\\)");
    public enum State {
        MATCHED_EXACT_PUBLISHER_ROW, MISSING_OR_WRONG_PDF_ROW,
        PROFILE_ADDRESS_OR_WIDTH_MISMATCH, DUPLICATE_PROFILE_NAME,
        MISSING_PROFILE_REGISTER
    }
    public record Expectation(String name,int offset,int physicalPage,
                              String rowKind) {
        public Expectation {
            if(name==null || rowKind==null || offset<0 || offset>0xfff ||
                    physicalPage!=PDF_D4 && physicalPage!=PDF_D5)
                throw new IllegalArgumentException("Invalid chip-select source row");
        }
        public String addressToken() {
            return String.format(Locale.ROOT,"$YFFA%02X",offset-0xa00);
        }
    }
    public record Row(Expectation expected,Integer profileOffset,
            Integer profileWidth,State state) {
        public Row {
            if(expected==null || state==null)
                throw new IllegalArgumentException("Invalid table witness row");
        }
    }
    public record Report(String profile,int matched,int missing,int conflicts,
                         List<Row> rows,boolean textComplete) {
        public Report {
            if(profile==null || matched<0 || missing<0 || conflicts<0 ||
                    rows==null || rows.size()>EXPECTED_ROWS)
                throw new IllegalArgumentException("Invalid chip-select report");
            rows=List.copyOf(rows);
        }
        public boolean exact() {
            return "MC68332".equals(profile) && textComplete &&
                rows.size()==EXPECTED_ROWS && matched==EXPECTED_ROWS &&
                missing==0 && conflicts==0;
        }
        public String markdown() {
            var b=new StringBuilder(
                "## GA-06/10/16 MC68332 Table D-2 chip-select register address rows\n\n")
                .append("- Explicit MCU: ").append(profile)
                .append("; expected publisher MC68332UM (Motorola 1995), ")
                .append("Table D-2, printed D-4/D-5 (physical PDF 218/219).\n")
                .append("- Matches: ").append(matched)
                .append("; missing/wrong rows: ").append(missing)
                .append("; profile conflicts: ").append(conflicts)
                .append("; supplied source text complete: ").append(textComplete)
                .append(".\n")
                .append("- **SOURCE ROWS ONLY — NOT A VERIFIED PHYSICAL BUS MAP.** ")
                .append("No proof of active CS pin, SIMCR/MM, PORTC, CSOR ")
                .append("matching, runtime writes, device identity or Review/Apply. ")
                .append("This pure parser does NOT authenticate PDF bytes; ")
                .append("the exact publisher SHA/folio verification belongs to CI.\n\n")
                .append("| Register | Reviewed address | Profile offset | Width | ")
                .append("Physical PDF folio | Status |\n")
                .append("|---|---|---|---|---|---|\n");
            for(var r:rows) {
                b.append("| ").append(r.expected().name())
                 .append(" | ").append(r.expected().addressToken())
                 .append(" | ").append(r.profileOffset()==null?"UNKNOWN":
                    String.format(Locale.ROOT,"0x%03X",r.profileOffset()))
                 .append(" | ").append(r.profileWidth()==null?"UNKNOWN":
                    r.profileWidth())
                 .append(" | ").append(r.expected().physicalPage())
                 .append(" | ").append(r.state()).append(" |\n");
            }
            return b.toString();
        }
    }
    private static final List<Expectation> REFERENCE;
    static {
        var rows=new ArrayList<Expectation>();
        rows.add(new Expectation("CSPAR0",0xa44,PDF_D4,"PIN ASSIGNMENT"));
        rows.add(new Expectation("CSPAR1",0xa46,PDF_D4,"PIN ASSIGNMENT"));
        rows.add(new Expectation("CSBARBT",0xa48,PDF_D4,"BASE BOOT"));
        rows.add(new Expectation("CSORBT",0xa4a,PDF_D4,"OPTION BOOT"));
        for(int cs=0;cs<=10;cs++) {
            int base=0xa4c+4*cs;
            rows.add(new Expectation("CSBAR"+cs,base,
                cs<=4?PDF_D4:PDF_D5,"BASE "+cs));
            rows.add(new Expectation("CSOR"+cs,base+2,
                cs<=3?PDF_D4:PDF_D5,"OPTION "+cs));
        }
        REFERENCE=List.copyOf(rows);
    }
    public static List<Expectation> reviewedRows() {return REFERENCE;}

    private record PdfRow(int offset,String kind,String register) {}
    private static Map<String,PdfRow> parsedPage(String text) {
        Map<String,PdfRow> found=new HashMap<>();
        Matcher m=TABLE_ROW.matcher(text);
        while(m.find()) {
            String name=m.group(4).toUpperCase(Locale.ROOT);
            int offset=0xa00+Integer.parseInt(m.group(1),16);
            String kind=m.group(2).toUpperCase(Locale.ROOT);
            String number=m.group(3);
            if("PIN ASSIGNMENT".equals(kind))kind="PIN ASSIGNMENT";
            else kind+=" "+(number==null?"":number.toUpperCase(Locale.ROOT));
            if(found.putIfAbsent(name,new PdfRow(offset,kind,name))!=null)
                throw new IllegalArgumentException(
                    "Duplicate chip-select table row "+name);
        }
        return found;
    }

    public static Report inspect(HardwareProfiles.Profile profile,
                                 Map<Integer,String> physicalPageText) {
        if(profile==null || physicalPageText==null ||
                physicalPageText.size()>2)
            throw new IllegalArgumentException("Missing or unbounded source pages");
        for(var e:physicalPageText.entrySet()) {
            if(e.getKey()==null ||
                    e.getKey()!=PDF_D4 && e.getKey()!=PDF_D5 ||
                    e.getValue()==null || e.getValue().length()>MAX_TEXT_CHARS)
                throw new IllegalArgumentException("Untrusted PDF page input");
        }
        if(!profile.concreteDevice || !"MC68332".equals(profile.id))
            return new Report(profile.id,0,0,0,List.of(),false);
        Map<Integer,Map<String,PdfRow>> pdf=new HashMap<>();
        for(var e:physicalPageText.entrySet())
            pdf.put(e.getKey(),parsedPage(e.getValue()));
        Map<String,List<HardwareProfiles.Register>> registers=new HashMap<>();
        for(var reg:profile.registers)
            registers.computeIfAbsent(reg.name,k->new ArrayList<>()).add(reg);

        List<Row> audit=new ArrayList<>();
        int matched=0,missing=0,conflicts=0;
        for(var expected:REFERENCE) {
            var candidates=registers.getOrDefault(expected.name(),List.of());
            HardwareProfiles.Register reg=candidates.size()==1?
                candidates.get(0):null;
            var page=pdf.getOrDefault(expected.physicalPage(),Map.of());
            PdfRow row=page.get(expected.name());
            State state;
            if(candidates.isEmpty())state=State.MISSING_PROFILE_REGISTER;
            else if(candidates.size()>1)state=State.DUPLICATE_PROFILE_NAME;
            else if(reg.offset!=expected.offset() || reg.widthBits!=16 ||
                    !"SIM".equals(reg.module))
                state=State.PROFILE_ADDRESS_OR_WIDTH_MISMATCH;
            else if(row==null || row.offset()!=expected.offset() ||
                    !row.kind().equals(expected.rowKind()))
                state=State.MISSING_OR_WRONG_PDF_ROW;
            else state=State.MATCHED_EXACT_PUBLISHER_ROW;
            if(state==State.MATCHED_EXACT_PUBLISHER_ROW)matched++;
            else if(state==State.MISSING_OR_WRONG_PDF_ROW)missing++;
            else conflicts++;
            audit.add(new Row(expected,reg==null?null:reg.offset,
                reg==null?null:reg.widthBits,state));
        }
        return new Report(profile.id,matched,missing,conflicts,audit,
            pdf.containsKey(PDF_D4) && pdf.containsKey(PDF_D5));
    }
}
