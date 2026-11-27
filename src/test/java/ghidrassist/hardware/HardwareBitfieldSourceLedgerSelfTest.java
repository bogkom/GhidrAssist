package ghidrassist.hardware;

import java.util.List;

/** Source-only GA-10/16 field/page/edition RAG provenance regression. */
public final class HardwareBitfieldSourceLedgerSelfTest {
    private HardwareBitfieldSourceLedgerSelfTest() {}
    private static int checks;
    private static void check(boolean value,String message) {
        checks++;
        if(!value)throw new AssertionError(message);
    }
    private static void rejects(Runnable action,String message) {
        boolean denied=false;
        try{action.run();}
        catch(IllegalArgumentException expected){denied=true;}
        check(denied,message);
    }
    public static void main(String[] args) {
        var mc=HardwareBitfieldSourceLedger.inspect(HardwareProfiles.mc68332());
        check(mc.device().equals("MC68332") &&
              mc.manualUrl().equals(HardwareProfiles.MC68332_MANUAL) &&
              mc.editionClaim().contains("Motorola 1995"),
              "bound MC68332 manual URL and printed edition claim");
        check(mc.entries().size()==15 && mc.excludedFields()==0,
              "8 SIMCR plus 7 SYNCR bitfield citations");
        check(mc.entries().stream().filter(e->e.register().equals("SIMCR")).count()==8 &&
              mc.entries().stream().filter(e->e.register().equals("SYNCR")).count()==7,
              "only sourced MC68332 fields in the catalog");
        for(var field:mc.entries()) {
            check(field.firstPage()>=219 && field.lastPage()<=221,
                  "every current field has bounded appendix D page claim");
            check(field.mask()!=0 && field.label().contains("PDF page"),
                  "each cited field has an explicit mask and physical page");
        }
        var mm=mc.entries().stream()
            .filter(e->e.register().equals("SIMCR") && e.field().equals("MM"))
            .findFirst().orElseThrow();
        check(mm.firstPage()==219 && mm.lastPage()==220 && mm.mask()==0x40,
              "SIMCR MM D-5/D-6 physical page range");
        var shen=mc.entries().stream()
            .filter(e->e.register().equals("SIMCR") && e.field().equals("SHEN"))
            .findFirst().orElseThrow();
        check(shen.firstPage()==219 && shen.lastPage()==219 &&
              shen.mask()==0x0300,
              "SIMCR SHEN[1:0] two-bit sourced field");
        var stsim=mc.entries().stream()
            .filter(e->e.register().equals("SYNCR") && e.field().equals("STSIM"))
            .findFirst().orElseThrow();
        check(stsim.firstPage()==221 && stsim.lastPage()==221,
              "SYNCR low-power source at physical PDF page 221");
        String md=mc.markdown();
        check(md.contains("GA-10/16 bitfield source-page ledger") &&
              md.contains("| SIMCR | SHEN |") &&
              md.contains("| SYNCR | STSIM |") &&
              md.contains("PDF BYTES UNVERIFIED") &&
              md.contains("No locally supplied PDF bytes or SHA-256 authenticated") &&
              md.contains(HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256) &&
              md.contains("not checked against any local/RAG PDF copy"),
              "RAG Markdown must retain citations AND authentication caveat");
        check(HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256
                  .matches("[a-f0-9]{64}"),
              "publisher SHA-256 pin must be structurally complete");
        var generic=HardwareBitfieldSourceLedger.inspect(HardwareProfiles.cpu32Family());
        check(generic.entries().isEmpty() && generic.excludedFields()==0 &&
              !generic.markdown().contains("| SIMCR |"),
              "generic CPU32 does not inherit an MC68332 source ledger");
        boolean immutable=false;
        try {mc.entries().clear();}
        catch(UnsupportedOperationException expected) {immutable=true;}
        check(immutable,"citation inventory immutable");
        boolean bad=false;
        try {HardwareBitfieldSourceLedger.inspect(null);}
        catch(IllegalArgumentException expected) {bad=true;}
        check(bad,"missing profile rejected");
        bad=false;
        try {new HardwareBitfieldSourceLedger.Entry("SIMCR","MM",0,219,220,
            "D-5/D-6 (PDF pages 219-220)");}
        catch(IllegalArgumentException expected){bad=true;}
        check(bad,"zero mask cannot masquerade as sourced field");
        bad=false;
        try {new HardwareBitfieldSourceLedger.Entry("SIMCR","MM",0x40,220,219,
            "D-5/D-6 (PDF pages 219-220)");}
        catch(IllegalArgumentException expected){bad=true;}
        check(bad,"reversed physical page range rejected");
        check(ManualPdfPageClaim.physicalRange("D-6 (PDF page 220)")
                  .equals(new ManualPdfPageClaim.PhysicalRange(220,220)) &&
              ManualPdfPageClaim.physicalRange("D-5/D-6 (PDF pages 219-220)")
                  .equals(new ManualPdfPageClaim.PhysicalRange(219,220)) &&
              ManualPdfPageClaim.physicalRange("PDF pages 220-219")==null &&
              ManualPdfPageClaim.physicalRange("PDF page ?")==null,
              "accepted and rejected page labels share one parser");
        // Public row/report constructors must not promote self-declared
        // page numbers, metadata or arbitrary fields into sourced claims.
        rejects(()->new HardwareBitfieldSourceLedger.Entry(
            "SIMCR","MM",0x40,219,221,"D-5/D-6 (PDF pages 219-220)"),
            "row and label PDF-page range must agree exactly");
        rejects(()->new HardwareBitfieldSourceLedger.Entry(
            "SIMCR","MM",0x40,219,220,
            "PDF page 219; PDF pages 219-220"),
            "second physical page marker makes source ambiguous");
        rejects(()->new HardwareBitfieldSourceLedger.Entry(
            "SIMCR","MM",0x100000000L,219,220,
            "D-5/D-6 (PDF pages 219-220)"),
            "impossible bit mask cannot be reported");
        rejects(()->new HardwareBitfieldSourceLedger.Entry(
            "SIMCR|injected","MM",0x40,219,220,
            "D-5/D-6 (PDF pages 219-220)"),
            "register identity cannot inject Markdown columns");
        rejects(()->new HardwareBitfieldSourceLedger.Entry(
            "SIMCR","MM",0x40,219,220,
            "D-5/D-6 (PDF pages 219-220) "+String.valueOf((char)0xd800)),
            "lone UTF-16 surrogate invalidates page citation");

        var pinned=new HardwareBitfieldSourceLedger.Report(
            "MC68332",HardwareProfiles.MC68332_MANUAL,
            HardwareBitfieldSourceLedger.MC68332_EDITION_CLAIM,
            mc.entries(),mc.excludedFields());
        check(pinned.markdown().equals(mc.markdown()),
            "complete canonical publisher inventory remains accepted");
        rejects(()->new HardwareBitfieldSourceLedger.Report(
            "MC68332","https://example.invalid/other.pdf",
            HardwareBitfieldSourceLedger.MC68332_EDITION_CLAIM,
            mc.entries(),0),
            "foreign PDF URL cannot borrow MC68332 SHA-256");
        rejects(()->new HardwareBitfieldSourceLedger.Report(
            "MC68332",HardwareProfiles.MC68332_MANUAL,"Different edition",
            mc.entries(),0),
            "foreign edition cannot borrow publisher digest");
        rejects(()->new HardwareBitfieldSourceLedger.Report(
            "MC68332",HardwareProfiles.MC68332_MANUAL,
            HardwareBitfieldSourceLedger.MC68332_EDITION_CLAIM,
            List.of(mc.entries().get(0)),14),
            "a forged 1-of-15 row cannot claim a complete sourced catalog");
        rejects(()->new HardwareBitfieldSourceLedger.Report(
            "MC68332",HardwareProfiles.MC68332_MANUAL,
            HardwareBitfieldSourceLedger.MC68332_EDITION_CLAIM,
            List.of(mc.entries().get(0),mc.entries().get(0)),13),
            "duplicate source rows cannot replace 15 canonical fields");
        var fake=new HardwareBitfieldSourceLedger.Entry(
            "SIMCR","FAKE",1,219,219,"D-5 (PDF page 219)");
        rejects(()->new HardwareBitfieldSourceLedger.Report(
            "MC68332",HardwareProfiles.MC68332_MANUAL,
            HardwareBitfieldSourceLedger.MC68332_EDITION_CLAIM,
            List.of(fake),14),
            "arbitrary register bitfield cannot inherit publisher source");
        var injected=new HardwareBitfieldSourceLedger.Entry(
            "SIMCR","MM",0x40,219,220,
            "D-5/D-6 (PDF pages 219-220) | <img src=x> [link](https://example.invalid)");
        rejects(()->new HardwareBitfieldSourceLedger.Report(
            "MC68332",HardwareProfiles.MC68332_MANUAL,
            HardwareBitfieldSourceLedger.MC68332_EDITION_CLAIM,
            List.of(injected),14),
            "matching page numbers do not authorize forged HTML/Markdown");
        rejects(()->new HardwareBitfieldSourceLedger.Report(
            "CPU32","UNKNOWN","UNKNOWN",
            List.of(mc.entries().get(0)),0),
            "generic CPU32 cannot publish MC68332 register pages");
        rejects(()->new HardwareBitfieldSourceLedger.Report(
            "CPU32",HardwareProfiles.MC68332_MANUAL,
            HardwareBitfieldSourceLedger.MC68332_EDITION_CLAIM,
            List.of(),0),
            "generic CPU32 cannot claim the publisher PDF digest");
        rejects(()->new HardwareBitfieldSourceLedger.Report(
            "CPU32|injected","UNKNOWN","UNKNOWN",List.of(),0),
            "untrusted generic device labels cannot inject Markdown");

        System.out.println("HardwareBitfieldSourceLedgerSelfTest OK checks="+checks);
    }
}
