package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Conservative text-layer register/address **candidates** extracted from
 * individual technical-manual PDF pages. Layout, bitfields, reset values,
 * device identity and correspondence between columns are NOT validated.
 * Never writes hardware_profiles.tsv or Ghidra symbols automatically.
 */
public final class ManualRegisterHints {
    private ManualRegisterHints(){}

    private static final String TOKEN="[A-Z][A-Z0-9_]{2,19}";
    private static final String ADDRESS="(?:0[Xx])?([0-9a-fA-F]{6,8})";
    private static final Pattern NAME_FIRST=Pattern.compile(
        "^\\s*("+TOKEN+")\\s{1,20}"+ADDRESS+"(?:\\s+(8|16|32))?\\s*(?:\\|.*)?$",
        Pattern.CASE_INSENSITIVE);
    private static final Pattern ADDRESS_FIRST=Pattern.compile(
        "^\\s*"+ADDRESS+"\\s{1,20}("+TOKEN+")(?:\\s+(8|16|32))?\\s*(?:\\|.*)?$",
        Pattern.CASE_INSENSITIVE);

    public static final class Candidate {
        public final int page;
        public final int line;
        public final String registerName;
        public final long address;
        public final Integer widthBits;
        public final String originalRow;
        public final String uncertainty;

        private Candidate(int page,int line,String registerName,long address,
                Integer widthBits,String originalRow) {
            this.page=page;
            this.line=line;
            this.registerName=registerName;
            this.address=address;
            this.widthBits=widthBits;
            this.originalRow=originalRow;
            this.uncertainty="HEURISTIC_PDF_TEXT_ROW; NOT validated against PDF layout or hardware identity";
        }
        public String toEvidenceLine(){
            return "page="+page+" line="+line+" candidate="+registerName+
                " address="+ChipSelectModel.hex(address,6)+
                " width="+(widthBits==null?"UNVERIFIED":widthBits)+
                " provenance=PDF_TEXT_ONLY layout=UNVERIFIED";
        }
    }
    public static List<Candidate> parsePage(int page,String sourceText){
        if(page<1)throw new IllegalArgumentException("PDF pages are 1-based");
        if(sourceText==null || sourceText.isBlank())return List.of();
        List<Candidate> found=new ArrayList<>();
        String[] rows=sourceText.split("\\R",-1);
        for(int line=0;line<rows.length;line++){
            String raw=rows[line].strip();
            // Reject visual multicolumn indicators created by PDFTextStripper.
            // Such rows need manual reconstruction from source-page positions.
            if(raw.isEmpty()||raw.length()>180 || raw.contains("    |    "))continue;
            Matcher a=NAME_FIRST.matcher(raw);
            Matcher b=ADDRESS_FIRST.matcher(raw);
            String name,hex,width;
            if(a.matches()){
                name=a.group(1);hex=a.group(2);width=a.group(3);
            }else if(b.matches()){
                hex=b.group(1);name=b.group(2);width=b.group(3);
            }else continue;
            // Reject plain English words which happen to start with A-Z.
            if(!name.matches("(?i).*[A-Z].*[0-9_]+.*") &&
                    !name.matches("(?i)^(SIMCR|SYNCR|CSPAR|QSMCR|TPUMCR|TRAMBAR|TRAMMCR|CANMCR)$"))
                continue;
            try{
                long addr=Long.parseLong(hex,16);
                if(addr>0xffffffL || addr<0x100L)continue;
                Integer bits=width==null?null:Integer.parseInt(width);
                found.add(new Candidate(page,line+1,name.toUpperCase(Locale.ROOT),
                    addr,bits,raw));
            }catch(NumberFormatException ignored){
                // An ambiguous number is NOT imported as a fabricated address.
            }
        }
        return Collections.unmodifiableList(found);
    }
    public static String evidenceTail(int page,String content,int maxCandidates){
        if(maxCandidates<0)throw new IllegalArgumentException("Negative limit");
        List<Candidate> candidates=parsePage(page,content);
        if(candidates.isEmpty() || maxCandidates==0)return "";
        StringBuilder b=new StringBuilder("\n\n[UNVERIFIED REGISTER/ADDRESS ROW HINTS"+
            " FROM PDF PAGE "+page+"; NOT A VERIFIED HARDWARE PROFILE]\n");
        int n=0;
        for(Candidate c:candidates){
            if(n++>=maxCandidates)break;
            b.append(c.toEvidenceLine()).append("\n");
        }
        if(candidates.size()>maxCandidates)
            b.append("... additional ambiguous rows omitted; inspect original PDF page.\n");
        return b.toString();
    }
}
