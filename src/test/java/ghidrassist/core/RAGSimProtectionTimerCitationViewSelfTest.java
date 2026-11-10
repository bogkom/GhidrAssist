package ghidrassist.core;

import ghidrassist.hardware.HardwareBitfieldSourceLedger;
import ghidrassist.hardware.HardwareSimProtectionTimerWitness;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class RAGSimProtectionTimerCitationViewSelfTest {
    private RAGSimProtectionTimerCitationViewSelfTest(){}
    private static int count;
    private static void ok(boolean b,String why){count++;if(!b)throw new AssertionError(why);}
    private static void denied(Runnable f,String why) {
        boolean bad=false;try{f.run();}catch(IllegalArgumentException e){bad=true;}
        ok(bad,why);
    }
    private static String content(int pdfPage) {
        StringBuilder b=new StringBuilder("MC68332 USER'S MANUAL D-"+(pdfPage-214)+"\n");
        if(pdfPage==224)b.append("D.2.12 SYPCR - System Protection Control Register $YFFA21\n"+
            "15 8 7 6 5 4 3 2 1 0\nNOT USED SWE SWP SWT HME BME BMT\n");
        else b.append("D.2.13 PICR - Periodic Interrupt Control Register $YFFA22\n"+
            "15 14 13 12 11 10 8 7 0\n0 0 0 0 0 PIRQL PIV\n");
        for(var r:HardwareSimProtectionTimerWitness.reviewed()){
            if(r.physicalPage()!=pdfPage || r.register().equals("PITR"))continue;
            b.append(r.heading()).append("\n0 = ").append(r.meaning()).append("\n");
        }
        if(pdfPage==225) {
            b.append("D.2.14 PITR - Periodic Interrupt Timer Register $YFFA24\n"+
                "15 14 13 12 11 10 9 8 7 0\n0 0 0 0 0 0 0 PTP PITM\n");
            for(var r:HardwareSimProtectionTimerWitness.reviewed()){
                if(!r.register().equals("PITR"))continue;
                b.append(r.heading()).append("\n0 = ")
                    .append(r.meaning()).append("\n");
            }
            b.append("D.2.15 SWSR - Software Service Register $YFFA27");
        }
        return b.toString();
    }
    private static Map<Integer,RAGIndexedPdfPageEvidence.Page> pages(){
        var out=new HashMap<Integer,RAGIndexedPdfPageEvidence.Page>();
        for(int n:List.of(224,225))out.put(n,new RAGIndexedPdfPageEvidence.Page(
            n,content(n),HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256,
            "/isolated/MC68332UM.pdf","isolated",1));
        return out;
    }
    public static void main(String[] args) {
        var pdf=pages();
        var s=RAGSimProtectionTimerCitationView.render("MC68332",
            "MC68332UM.pdf","SYPCR","SWT",pdf);
        ok(s.contains("FIELD: SWT MASK: 0x30 REGISTER_WIDTH_BITS: 8") &&
            s.contains("DESCRIPTION_PDF: 224 PRINTED_FOLIO: D-10") &&
            s.contains("WRITE_ONCE_REGISTER: true") &&
            s.contains("ALL_10_REVIEWED_TEXT_CANDIDATES: true") &&
            s.contains("ALL_10_PINNED_PUBLISHER_EXCERPTS: false") &&
            s.contains("MATCHES_PINNED_EXCERPT: false") &&
            s.contains("INDEXED_TEXT_NOT_CURRENT_FILE_AUTHENTICATION"),
            "SYPCR SWT static field provenance and explicit write-once caution");
        var pic=RAGSimProtectionTimerCitationView.render("MC68332",
            "MC68332UM.pdf","PICR",null,pdf);
        ok(pic.contains("FIELD: PIRQL MASK: 0x700") &&
            pic.contains("FIELD: PIV MASK: 0xFF") &&
            !pic.contains("FIELD: SWE"),
            "PICR source view contains only two periodic interrupt fields");
        var pit=RAGSimProtectionTimerCitationView.render("MC68332",
            "MC68332UM.pdf","PITR","PITM",pdf);
        ok(pit.contains("FIELD: PITM MASK: 0xFF") &&
            pit.contains("active periodic interrupt/vector") &&
            !pit.contains("FIELD: PTP"),
            "PITR modulus is a candidate, not active timer evidence");
        denied(()->RAGSimProtectionTimerCitationView.render(
            "CPU32","MC68332UM.pdf","SYPCR",null,pdf),
            "Generic CPU32 never implicitly inherits hardware registers");
        denied(()->RAGSimProtectionTimerCitationView.render(
            "MC68332","MC68332UM.pdf","SYNCR",null,pdf),
            "Old SIMCR/SYNCR chapter cannot be misrouted into new source");
        denied(()->RAGSimProtectionTimerCitationView.render(
            "MC68332","MC68332UM.pdf","PICR","invented",pdf),
            "Unknown field cannot create a source citation");
        var missing=new HashMap<>(pdf);missing.remove(224);
        denied(()->RAGSimProtectionTimerCitationView.render(
            "MC68332","MC68332UM.pdf","PICR","PIV",missing),
            "Exact two-folio source is mandatory");
        var other=new HashMap<>(pdf);
        other.put(225,new RAGIndexedPdfPageEvidence.Page(225,content(225),
            "0".repeat(64),"/isolated/MC68332UM.pdf","isolated",1));
        denied(()->RAGSimProtectionTimerCitationView.render(
            "MC68332","MC68332UM.pdf","PICR","PIV",other),
            "Indexed SHA mismatch between D-10/D-11 refused");
        var forged=new HashMap<>(pdf);
        forged.put(224,new RAGIndexedPdfPageEvidence.Page(224,content(224),
            "0".repeat(64),"/isolated/MC68332UM.pdf","isolated",1));
        forged.put(225,new RAGIndexedPdfPageEvidence.Page(225,content(225),
            "0".repeat(64),"/isolated/MC68332UM.pdf","isolated",1));
        denied(()->RAGSimProtectionTimerCitationView.render(
            "MC68332","MC68332UM.pdf","SYPCR",null,forged),
            "Arbitrarily rehashed non-publisher PDF cannot borrow edition pin");
        denied(()->RAGSimProtectionTimerCitationView.render(
            "MC68332","injected\nPASS","SYPCR",null,pdf),
            "Untrusted source path cannot inject success markers");
        System.out.println("RAGSimProtectionTimerCitationViewSelfTest PASS checks="+count);
    }
}
