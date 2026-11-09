package ghidrassist.hardware;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Pure deterministic GA-06/10/16 exact MC68332UM D-4/D-5 table proof. */
public final class HardwareSimChipSelectTableWitnessSelfTest {
    private HardwareSimChipSelectTableWitnessSelfTest() {}
    private static int checks;
    private static void check(boolean b,String why) {
        checks++;
        if(!b)throw new AssertionError(why);
    }
    private static void rejected(Runnable test,String why) {
        boolean refused=false;
        try{test.run();}catch(IllegalArgumentException expected){refused=true;}
        check(refused,why);
    }
    private static Map<Integer,String> syntheticPages() {
        Map<Integer,StringBuilder> pages=new HashMap<>();
        pages.put(218,new StringBuilder("Table D-2 SIM Address Map\n"));
        pages.put(219,new StringBuilder("Table D-2 SIM Address Map continued\n"));
        for(var row:HardwareSimChipSelectTableWitness.reviewedRows()) {
            pages.get(row.physicalPage()).append("S ")
                .append(row.addressToken()).append(" CHIP-SELECT ")
                .append(row.rowKind()).append(" (")
                .append(row.name()).append(")\n");
        }
        return Map.of(218,pages.get(218).toString(),
            219,pages.get(219).toString());
    }
    private static HardwareSimChipSelectTableWitness.Row get(
            HardwareSimChipSelectTableWitness.Report r,String name) {
        return r.rows().stream().filter(x->x.expected().name().equals(name))
            .findFirst().orElseThrow();
    }
    public static void main(String[] args)throws Exception {
        var source=syntheticPages();
        var catalog=HardwareProfiles.mc68332();
        var result=HardwareSimChipSelectTableWitness.inspect(catalog,source);
        check(result.exact() && result.rows().size()==26 &&
                result.matched()==26 && result.conflicts()==0,
            "All 26 independently reviewed chip-select rows in MC68332");
        check(get(result,"CSBAR0").expected().offset()==0xa4c &&
                get(result,"CSOR0").expected().offset()==0xa4e &&
                get(result,"CSBAR10").expected().offset()==0xa74 &&
                get(result,"CSOR10").expected().offset()==0xa76 &&
                get(result,"CSBARBT").expected().offset()==0xa48,
            "Exact address sequence for boot and CS[0..10]");
        check(get(result,"CSBAR4").expected().physicalPage()==218 &&
                get(result,"CSOR4").expected().physicalPage()==219 &&
                get(result,"CSPAR1").expected().physicalPage()==218,
            "PDF D-4→D-5 page boundary never inferred from CS group");
        check(result.markdown().contains("NOT A VERIFIED PHYSICAL BUS MAP") &&
                result.markdown().contains("Review/Apply") &&
                result.markdown().contains("PDF 218/219") &&
                result.markdown().contains("| CSOR4 | $YFFA5E |"),
            "Bounded report retains source uncertainty and real PDF folios");
        var shifted=new HashMap<>(source);
        shifted.put(218,source.get(218).replace(
            "$YFFA5C CHIP-SELECT BASE 4 (CSBAR4)",
            "$YFFA5E CHIP-SELECT BASE 4 (CSBAR4)"));
        var wrong=HardwareSimChipSelectTableWitness.inspect(catalog,shifted);
        check(!wrong.exact() && wrong.missing()==1 &&
                get(wrong,"CSBAR4").state()==
                    HardwareSimChipSelectTableWitness.State.MISSING_OR_WRONG_PDF_ROW,
            "Wrong table address refused, even with correct register name");
        var swapped=HardwareSimChipSelectTableWitness.inspect(catalog,
            Map.of(218,source.get(219),219,source.get(218)));
        check(swapped.matched()==0 && swapped.missing()==26 && !swapped.exact(),
            "Page swap cannot be repaired by names anywhere in document");
        var missing=HardwareSimChipSelectTableWitness.inspect(catalog,
            Map.of(218,source.get(218)));
        check(!missing.exact() && !missing.textComplete() &&
                missing.missing()>0,
            "Missing second physical PDF folio never implies complete table");
        var wrongLabel=new HashMap<>(source);
        wrongLabel.put(219,source.get(219).replace(
            "CHIP-SELECT OPTION 4 (CSOR4)",
            "CHIP-SELECT BASE 4 (CSOR4)"));
        check(!HardwareSimChipSelectTableWitness.inspect(catalog,wrongLabel).exact(),
            "CSBAR/CSOR label mismatch rejected for otherwise correct address");
        var duplicate=new HashMap<>(source);
        duplicate.put(219,source.get(219)+
            "S $YFFA5E CHIP-SELECT OPTION 4 (CSOR4)\n");
        rejected(()->HardwareSimChipSelectTableWitness.inspect(catalog,duplicate),
            "Repeated table source row is ambiguous and rejected");
        check(HardwareSimChipSelectTableWitness.inspect(
                HardwareProfiles.cpu32Family(),source).rows().isEmpty(),
            "Generic CPU32 inherits no MC68332 chip-select source assertions");
        rejected(()->HardwareSimChipSelectTableWitness.inspect(catalog,
                Map.of(217,source.get(218))),
            "Wrong physical PDF page number is not a source witness");
        rejected(()->HardwareSimChipSelectTableWitness.inspect(catalog,
                Map.of(218,"x".repeat(
                    HardwareSimChipSelectTableWitness.MAX_TEXT_CHARS+1))),
            "Excessive PDF source text bounded");
        rejected(()->HardwareSimChipSelectTableWitness.inspect(catalog,
                Map.of(218,source.get(218),219,source.get(219),220,"extra")),
            "Unreviewed third PDF page rejected");
        boolean immutable=false;
        try{result.rows().clear();}catch(UnsupportedOperationException expected){
            immutable=true;
        }
        check(immutable,"Read-only report is immutable");

        if(args.length!=0 && args.length!=2)
            throw new IllegalArgumentException(
                "Require physical PDF 218 and 219 extracted from same verified manual");
        if(args.length==2) {
            var official=HardwareSimChipSelectTableWitness.inspect(catalog,
                Map.of(218,Files.readString(Path.of(args[0])),
                    219,Files.readString(Path.of(args[1]))));
            check(official.exact(),
                "Official SHA-pinned MC68332UM Table D-2 all 26 register rows");
            System.out.println("PINNED MC68332UM D-4/D-5 CS SOURCE ROWS PASS: "+
                "26/26 exact address/name/page witnesses; NOT runtime CS map");
        }
        System.out.println("HardwareSimChipSelectTableWitnessSelfTest PASS checks="+checks);
    }
}
