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
              md.contains("No PDF file bytes or SHA-256 authenticated"),
              "RAG Markdown must retain citations AND authentication caveat");
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
        System.out.println("HardwareBitfieldSourceLedgerSelfTest OK checks="+checks);
    }
}
