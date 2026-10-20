package ghidrassist.hardware;

import java.util.List;

/** No PDFBox/Ghidra needed; tests extracted page-text semantics only. */
public final class ManualRegisterHintsSelfTest {
    private static void ok(boolean v,String msg){if(!v)throw new AssertionError(msg);}
    public static void main(String[] args){
        String page="SYSTEM INTEGRATION MODULE\n"+
            "SIMCR  0xFFFA00  16\n"+
            "CSPAR0 0xFFFA44 16\n"+
            "0xFFF080 CANMCR 16\n"+
            "0xFFFA68  CSBAR7  16\n"+
            "CSBAR7    |    0xFFFA68 16\n"+
            "Register width 16\n"+
            "This is not a real register 0xFFFA04\n";
        List<ManualRegisterHints.Candidate> hits=ManualRegisterHints.parsePage(129,page);
        ok(hits.size()==4,"only unambiguous single-row address/name pairs");
        ok(hits.get(0).page==129 && hits.get(0).line==2,"source-page/line provenance");
        ok(hits.get(0).address==0xfffa00 && hits.get(0).widthBits==16,"SIMCR mapping");
        ok(hits.get(2).registerName.equals("CANMCR"),"address-first pattern");
        ok(hits.get(3).registerName.equals("CSBAR7"),"CS index pattern");
        String note=ManualRegisterHints.evidenceTail(129,page,2);
        ok(note.contains("UNVERIFIED") && note.contains("PDF PAGE 129") &&
           note.contains("additional ambiguous rows omitted"),"uncertainty flags");
        ok(ManualRegisterHints.parsePage(1,"No extractable text").isEmpty(),
            "no invented registers");
        boolean invalid=false;
        try{ManualRegisterHints.parsePage(0,page);}
        catch(IllegalArgumentException e){invalid=true;}
        ok(invalid,"page number check");
        System.out.println("ManualRegisterHintsSelfTest OK");
    }
}
