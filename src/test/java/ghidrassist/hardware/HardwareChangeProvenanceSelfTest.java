package ghidrassist.hardware;

import java.util.List;

/** Pure Java GA-13 provenance / CSV safety regression. */
public final class HardwareChangeProvenanceSelfTest {
    private HardwareChangeProvenanceSelfTest() {}
    private static void check(boolean yes,String message) {
        if(!yes)throw new AssertionError(message);
    }
    public static void main(String[] args) {
        String user=HardwareChangeProvenance.describeSourceType("USER_DEFINED");
        check(user.contains("author UNKNOWN") && user.contains("human/AI/script"),
            "USER_DEFINED does not identify a human editor");
        check(HardwareChangeProvenance.describeSourceType("analysis")
            .contains("identity UNKNOWN"),"ANALYSIS does not identify tool/agent");
        check(HardwareChangeProvenance.describeSourceType("IMPORTED")
            .contains("importer UNKNOWN"),"importer identity not fabricated");
        check(HardwareChangeProvenance.describeSourceType("DEFAULT")
            .contains("Ghidra generated"),"Ghidra default source");
        check(HardwareChangeProvenance.describeSourceType(null)
            .contains("UNKNOWN"),"no source must remain unknown");
        check(HardwareChangeProvenance.describeSourceType("CUSTOM")
            .contains("UNKNOWN"),"unsupported future API must not imply actor");

        var a=new HardwareChangeProvenance.ReviewRow("REGISTER",
            "0xFFFA00..0xFFFA01","SIMCR","already,\"set\"\n","USER_DEFINED",
            "ALREADY_PRESENT",false,"Manual, review needed");
        var b=new HardwareChangeProvenance.ReviewRow("MEMORY",
            "0xFFF000..0xFFF7FF","TPURAM_CANDIDATE",null,null,
            "MANUAL_REVIEW",false,"TRAMBAR unknown");
        var rows=HardwareChangeProvenance.snapshot(List.of(a,b));
        String csv=HardwareChangeProvenance.csv(rows);
        check(csv.startsWith("kind,address_range,proposed_name,existing_name,") &&
            csv.contains("preflight_decision,selected,evidence"),
            "complete stable column schema");
        check(csv.contains("\"already,\"\"set\"\" \""),
            "quoted comma, quotes and newline safely escaped");
        check(csv.contains("\"(no primary symbol)\"") &&
            csv.contains("\"UNKNOWN — no primary symbol SourceType\""),
            "unknown symbol/source not invented");
        check(csv.contains("\"GhidrAssist review proposal; selected MC68332 hypothesis\"") &&
            csv.contains(",false,") &&
            csv.contains("\"ALREADY_PRESENT\""),
            "distinguish proposal origin, approved state and existing symbol");
        boolean unmodifiable=false;
        try{rows.clear();}catch(UnsupportedOperationException expected){unmodifiable=true;}
        check(unmodifiable,"review snapshot must not be mutable");
        boolean invalid=false;
        try{HardwareChangeProvenance.csv(null);}
        catch(IllegalArgumentException expected){invalid=true;}
        check(invalid,"null input rejects rather than generating false snapshot");
        var malicious = new HardwareChangeProvenance.ReviewRow("REGISTER",
            "0x00000000","=HYPERLINK(\"https://evil.invalid\")",
            "  +1+2","USER_DEFINED","MANUAL_REVIEW",false,
            "\t@SUM(1,2)\nnewline");
        String safe=HardwareChangeProvenance.csv(List.of(malicious));
        check(safe.contains("\"'=HYPERLINK(\"\"https://evil.invalid\"\")\"") &&
            safe.contains("\"'  +1+2\"") &&
            safe.contains("\"'\t@SUM(1,2) newline\""),
            "CSV quotes alone cannot prevent formula execution");
        var unicode = new HardwareChangeProvenance.ReviewRow("REGISTER",
            "0x0","\uFEFF=1+2","\u200B-9",null,"MANUAL_REVIEW",false,
            "\u2028=PAYLOAD\u2029");
        String safeUnicode=HardwareChangeProvenance.csv(List.of(unicode));
        check(safeUnicode.contains("\"'\uFEFF=1+2\"") &&
            safeUnicode.contains("\"'\u200B-9\"") &&
            !safeUnicode.contains("\u2028") && !safeUnicode.contains("\u2029"),
            "Unicode spacing must not hide spreadsheet formulas/newline markers");
        // Java 21 Unicode Cf code points are not necessarily whitespace.
        // A spreadsheet importer may ignore format controls before a
        // formula prefix; quoting the CSV column is not a protection.
        String supplementaryFormat=new String(Character.toChars(0xE0001));
        check(Character.getType(0xE0001)==Character.FORMAT &&
            Character.getType('\u2060')==Character.FORMAT,
            "synthetic invisible formula prefixes are Unicode format");
        var hiddenFormula=new HardwareChangeProvenance.ReviewRow("REGISTER",
            "0x0","\u2060=SUM(1,2)",
            " \u200d\u200e+1+1",null,"MANUAL_REVIEW",false,
            supplementaryFormat+"@SUM(2,3)");
        String safeFormat=HardwareChangeProvenance.csv(List.of(hiddenFormula));
        check(safeFormat.contains("\"'\u2060=SUM(1,2)\"") &&
            safeFormat.contains("\"' \u200d\u200e+1+1\"") &&
            safeFormat.contains("\"'"+supplementaryFormat+"@SUM(2,3)\""),
            "all leading Unicode Cf controls must not conceal CSV formulae");
        var harmlessFormat=new HardwareChangeProvenance.ReviewRow(
            "REGISTER","0x0","name\u2060=symbol",null,null,
            "MANUAL_REVIEW",false,"ordinary label");
        check(HardwareChangeProvenance.csv(List.of(harmlessFormat))
            .contains("\"name\u2060=symbol\""),
            "format characters inside ordinary nonformula text are preserved");
        var many=new java.util.ArrayList<HardwareChangeProvenance.ReviewRow>();
        for(int n=0;n<HardwareChangeProvenance.MAX_CSV_ROWS+7;n++)
            many.add(a);
        String capped=HardwareChangeProvenance.csv(many);
        check(capped.contains("\"OMITTED_ROWS\"") &&
            capped.contains("7 rows omitted by cap") &&
            capped.contains("INCOMPLETE_EXPORT_NEVER_AUTO_APPLY") &&
            capped.lines().count()==HardwareChangeProvenance.MAX_CSV_ROWS+2,
            "bounded output with counted omission record");
        boolean nullRow=false;
        var withNull=new java.util.ArrayList<HardwareChangeProvenance.ReviewRow>();
        withNull.add(a);withNull.add(null);
        try{HardwareChangeProvenance.csv(withNull);}
        catch(IllegalArgumentException expected){nullRow=true;}
        check(nullRow,"null entry must not silently disappear from provenance");
        var huge=new HardwareChangeProvenance.ReviewRow("REGISTER","0x0",
            "=HYPERLINK("+"X".repeat(1_000_000),null,"ANALYSIS",
            "MANUAL_REVIEW",false,"E".repeat(1_000_000));
        String bounded=HardwareChangeProvenance.csv(List.of(huge));
        check(bounded.length()<4000 &&
            bounded.contains("SOURCE_TRUNCATED") &&
            bounded.contains("\"'=HYPERLINK("),
            "giant provenance fields cannot produce unbounded CSV or executable formulas");
        var largeRows=new java.util.ArrayList<HardwareChangeProvenance.ReviewRow>();
        for(int n=0;n<HardwareChangeProvenance.MAX_CSV_ROWS+3;n++)
            largeRows.add(huge);
        String cappedFields=HardwareChangeProvenance.csv(largeRows);
        check(cappedFields.length()<25_000_000 &&
            cappedFields.contains("3 rows omitted by cap") &&
            cappedFields.contains("SOURCE_TRUNCATED"),
            "both row count and each cell are bounded; omissions signaled");
        System.out.println("HardwareChangeProvenanceSelfTest OK");
    }
}
