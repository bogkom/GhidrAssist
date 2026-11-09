package ghidrassist.hardware;

import java.util.Map;
import java.util.TreeMap;

/** Pure Java21 GA-06/10/16 test of exact SIM D-2 vendor-table claims. */
public final class HardwareSimD2RegisterWitnessSelfTest {
    private HardwareSimD2RegisterWitnessSelfTest(){}
    private static int checks;
    private static void check(boolean value,String why){
        checks++;if(!value)throw new AssertionError(why);
    }
    private static void refuses(Runnable r,String why){
        boolean rejected=false;
        try{r.run();}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,why);
    }
    private static String d4(){
        return """
            D-4 Table D-2 SIM Address Map
            S/U $YFFA10 NOT USED PORT E DATA (PORTE0)
            S/U $YFFA14 NOT USED PORT E DATA DIRECTION (DDRE)
            S $YFFA1E NOT USED PORT F PIN ASSIGNMENT (PFPAR)
            S $YFFA20 NOT USED SYSTEM PROTECTION CONTROL
                            (SYPCR)
            S $YFFA26 NOT USED SOFTWARE SERVICE (SWSR)
            S $YFFA44 CHIP-SELECT PIN ASSIGNMENT (CSPAR0)
            S $YFFA46 CHIP-SELECT PIN ASSIGNMENT (CSPAR1)
            S $YFFA4C CHIP-SELECT BASE 0 (CSBAR0)
            """;
    }
    private static String d5(){
        return """
            D-5 Table D-2 SIM Address Map
            S $YFFA6C CHIP-SELECT BASE 8 (CSBAR8)
            S $YFFA6E CHIP-SELECT OPTION 8 (CSOR8)
            """;
    }
    private static HardwareSimD2RegisterWitness.Row row(
            HardwareSimD2RegisterWitness.Result result,String name){
        return result.rows().stream().filter(r->r.reviewed().name().equals(name))
            .findFirst().orElseThrow();
    }
    public static void main(String[] args)throws Exception {
        var profile=HardwareProfiles.mc68332();
        var text=Map.of(218,d4(),219,d5());
        var matched=HardwareSimD2RegisterWitness.inspect(profile,text);
        check(matched.completeSample() && matched.rows().size()==10 &&
                matched.matched()==10 && matched.incomplete()==0,
            "MC68332 ten source-table rows match exact profile addresses/width/access");
        check(row(matched,"SYPCR").reviewed().tableAddress().equals("$YFFA20") &&
                row(matched,"SYPCR").reviewed().offset()==0xa21 &&
                row(matched,"SWSR").reviewed().tableAddress().equals("$YFFA26") &&
                row(matched,"SWSR").reviewed().offset()==0xa27,
            "8-bit low-byte physical addresses differ from aligned 16-bit table rows");
        check(row(matched,"CSBAR8").reviewed().physicalPage()==219 &&
                row(matched,"CSBAR0").reviewed().physicalPage()==218 &&
                row(matched,"CSOR8").reviewed().offset()==0xa6e,
            "Chip-select table D-4/D-5 page boundary and offset preserved");
        check(row(matched,"PORTE0").reviewed().access()==
                    HardwareProfiles.Access.CONFIGURABLE_SUPERVISOR_USER &&
                row(matched,"CSPAR0").reviewed().access()==
                    HardwareProfiles.Access.SUPERVISOR,
            "Supervisor vs S/U access table classes are not conflated");
        String markdown=matched.markdown();
        check(markdown.contains("SOURCE ROW ONLY") &&
                markdown.contains("not local text") &&
                markdown.contains("0x0A21") &&
                markdown.contains("$YFFA20") &&
                markdown.contains("Review/Apply"),
            "Report separates table row, physical byte and non-runtime source status");
        var missingD4=HardwareSimD2RegisterWitness.inspect(profile,
            Map.of(219,d5()));
        check(missingD4.matched()==2 && missingD4.incomplete()==8 &&
                row(missingD4,"SYPCR").state()==
                    HardwareSimD2RegisterWitness.State.TABLE_PAGE_MISSING,
            "Missing D-4 physical folio cannot be repaired using D-5");
        var swapped=HardwareSimD2RegisterWitness.inspect(profile,
            Map.of(218,d5(),219,d4()));
        check(swapped.matched()==0 && swapped.incomplete()==10,
            "Swapped source pages never validate opposite physical folio");
        var misleading=HardwareSimD2RegisterWitness.inspect(profile,
            Map.of(218,d4().replace("(SYPCR)","(NOT_SYPCR)"),
                219,d5()));
        check(row(misleading,"SYPCR").state()==
                HardwareSimD2RegisterWitness.State.TABLE_ROW_MISSING,
            "Missing register name next to address cannot pass by substring");
        var wrapped=HardwareSimD2RegisterWitness.inspect(profile,
            Map.of(218,d4().replace("(SYPCR)","          (SYPCR)"),
                219,d5()));
        check(wrapped.completeSample(),
            "Wrapped SYPCR description belongs to same Table D-2 address row");
        check(HardwareSimD2RegisterWitness.inspect(
                HardwareProfiles.cpu32Family(),text).rows().isEmpty(),
            "Generic CPU32 does not inherit MC68332 SIM register evidence");
        refuses(()->HardwareSimD2RegisterWitness.inspect(profile,
            Map.of(0,"fake")),"Physical page 0 rejected");
        refuses(()->HardwareSimD2RegisterWitness.inspect(profile,
            Map.of(220,"wrong page")),"Wrong physical folio rejected");
        refuses(()->HardwareSimD2RegisterWitness.inspect(profile,
            Map.of(218,"X".repeat(HardwareSimD2RegisterWitness.MAX_PAGE_CHARS+1))),
            "Unbounded PDF page text rejected");
        boolean immutable=false;
        try{matched.rows().clear();}catch(UnsupportedOperationException expected){
            immutable=true;
        }
        check(immutable,"Audit result source rows are immutable");
        if(args.length!=0 && args.length!=2)
            throw new IllegalArgumentException("Expected official PDF pages 218, 219");
        if(args.length==2){
            var publisher=HardwareSimD2RegisterWitness.inspect(profile,Map.of(
                218,java.nio.file.Files.readString(java.nio.file.Path.of(args[0])),
                219,java.nio.file.Files.readString(java.nio.file.Path.of(args[1]))));
            // The workflow first authenticates publisher bytes via a
            // SHA-256 pin. This pure Java method trusts neither local nor
            // arbitrary RAG PDF copies.
            check(publisher.completeSample(),
                "NXP MC68332UM exact D-4/D-5 Table D-2 address/width/access witness");
            System.out.println("PINNED NXP MC68332UM SIM TABLE D-2 TEN ROWS PASS");
        }
        System.out.println("HardwareSimD2RegisterWitnessSelfTest PASS checks="+checks);
    }
}
