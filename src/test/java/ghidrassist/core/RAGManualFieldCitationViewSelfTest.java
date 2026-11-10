package ghidrassist.core;

import ghidrassist.hardware.HardwareManualFieldExcerptEvidence;
import ghidrassist.hardware.HardwareBitfieldSourceLedger;
import java.util.HashMap;
import java.util.Map;

/** Pure caller-facing citation regression independent of Ghidra/RAG files. */
public final class RAGManualFieldCitationViewSelfTest {
    private RAGManualFieldCitationViewSelfTest(){}
    private static int checks;
    private static void ok(boolean yes,String why) {
        checks++;if(!yes)throw new AssertionError(why);
    }
    private static void denied(Runnable test,String why) {
        boolean failed=false;
        try{test.run();}catch(IllegalArgumentException expected){failed=true;}
        ok(failed,why);
    }
    private static final String PIN=HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256;
    private static String page(int n) {
        StringBuilder text=new StringBuilder(
            "MC68332 USER'S MANUAL D-"+(n-214)+"\n");
        if(n==219)text.append(
            "D.2.1 SIMCR — Module Configuration Register $YFFA00\n"+
            "15 14 13 12 11 10 9 8 7 6 5 4 3 0\n"+
            "EXOFF FRZSW FRZBM 0 SLVEN 0 SHEN SUPV MM 0 0 IARB\n");
        if(n==220)text.append(
            "D.2.3 SYNCR — Clock Synthesizer Control Register $YFFA04\n"+
            "15 14 13 8 7 6 5 4 3 2 1 0\n"+
            "W X Y EDIV 0 0 SLIMP SLOCK RSTEN STSIM STEXT\n");
        for(var entry:HardwareManualFieldExcerptEvidence.reviewed())
            if(entry.descriptionPage()==n)
                text.append(entry.heading()).append("\n")
                    .append("0 = ").append(entry.nearbyText()).append(".\n");
        return text.toString();
    }
    private static Map<Integer,RAGIndexedPdfPageEvidence.Page> pages() {
        var group=new HashMap<Integer,RAGIndexedPdfPageEvidence.Page>();
        for(int n:RAGManualFieldCitationView.PAGES)
            group.put(n,new RAGIndexedPdfPageEvidence.Page(
                n,page(n),PIN,"/isolated/manual.pdf","isolated",1));
        return group;
    }
    public static void main(String[] args) {
        var group=pages();
        String selected=RAGManualFieldCitationView.render(
            "MC68332","MC68332UM.pdf","SIMCR","MM",group);
        ok(selected.contains("FIELD: MM MASK: 0x40 DIAGRAM_PDF: 219"+
                " DESCRIPTION_PDF: 220 PRINTED_FOLIO: D-6") &&
            selected.contains("FULL_15_TEXT_CANDIDATES: true") &&
            selected.contains("MATCHES_PINNED_EXCERPT: false") &&
            selected.contains("INDEXED_TEXT_ONLY_NOT_CURRENT_PDF_AUTHENTICATION") &&
            selected.contains("EDITION_CLAIM: MC68332UM"),
            "Explicit MC68332 field MM returns source page, mask and unknown PDF authentication");
        String syncr=RAGManualFieldCitationView.render(
            "MC68332","MC68332UM.pdf","SYNCR",null,group);
        ok(syncr.contains("FIELD: W ") && syncr.contains("FIELD: X ") &&
            syncr.contains("FIELD: Y ") && syncr.contains("FIELD: STEXT ") &&
            !syncr.contains("FIELD: MM "),
            "Request scoped to one MCU register; short names still expanded");
        denied(()->RAGManualFieldCitationView.render(
            "CPU32","MC68332UM.pdf","SIMCR","MM",group),
            "Generic CPU32 may not silently select MC68332");
        denied(()->RAGManualFieldCitationView.render(
            "MC68332","MC68332UM.pdf","CSBAR8",null,group),
            "Unreviewed register has no 15-field source citations");
        denied(()->RAGManualFieldCitationView.render(
            "MC68332","MC68332UM.pdf","SIMCR","FAKE",group),
            "Unknown bitfield cannot inherit a nearby real excerpt");
        var changedDigest=new HashMap<>(group);
        changedDigest.put(221,new RAGIndexedPdfPageEvidence.Page(221,
            page(221),"0".repeat(64),"/isolated/manual.pdf","isolated",1));
        denied(()->RAGManualFieldCitationView.render(
            "MC68332","MC68332UM.pdf","SIMCR","MM",changedDigest),
            "Mixing physically separate indexed PDF hashes denied");
        var missingFolio=new HashMap<>(group);
        missingFolio.remove(221);
        denied(()->RAGManualFieldCitationView.render(
            "MC68332","MC68332UM.pdf","SIMCR","MM",missingFolio),
            "Missing D-7 page refuses full independent source group");
        var changedPin=new HashMap<>(group);
        changedPin.put(220,new RAGIndexedPdfPageEvidence.Page(
            220,page(220),"a".repeat(64),"/isolated/manual.pdf",
            "isolated",1));
        denied(()->RAGManualFieldCitationView.render(
            "MC68332","MC68332UM.pdf","SIMCR","MM",changedPin),
            "A rehashed arbitrary PDF source cannot claim pinned edition evidence");
        denied(()->RAGManualFieldCitationView.render(
            "MC68332","fake\nEDITION VERIFIED","SIMCR","MM",group),
            "Untrusted filename cannot inject provenance line into result");
        var forgedHeading=new HashMap<>(group);
        forgedHeading.put(220,new RAGIndexedPdfPageEvidence.Page(
            220,page(220).replace(
                "MM - Module Mapping","MM - fabricated document"),
            PIN,"/isolated/manual.pdf","isolated",1));
        String missing=RAGManualFieldCitationView.render(
            "MC68332","MC68332UM.pdf","SIMCR","MM",forgedHeading);
        ok(missing.contains("FULL_15_TEXT_CANDIDATES: false") &&
            missing.contains("STATE: FIELD_HEADING_MISSING") &&
            !missing.contains("BOUNDED_INDEXED_EXCERPT: MM"),
            "Forged field heading cannot yield a positive matched indexed excerpt");
        System.out.println("RAGManualFieldCitationViewSelfTest PASS checks="+checks);
    }
}
