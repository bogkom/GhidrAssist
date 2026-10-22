package ghidrassist.core;

public final class RAGQueryFocusSelfTest {
    private static void ok(boolean b,String m){if(!b)throw new AssertionError(m);}
    public static void main(String[] args){
        String q="#func\nZnajdź SIMCR 0xFFFA00 i bit MM. Wskaż inne rejestry.";
        String focused=RAGQueryFocus.focus(q);
        ok(focused.contains("SIMCR MM") && focused.contains("Module Mapping"),
            "SIMCR query must retrieve SIMCR/MM documentation");
        ok(!focused.contains("#func") && !focused.contains("inne rejestry"),
            "no expanded code or unfocused boilerplate");
        String cs = RAGQueryFocus.focus("Zdekoduj CSBAR0 CSOR0, chip-select CS0 i CS1");
        ok(cs.contains("Table 4-22") && cs.contains("DSACK") && cs.contains("CSBAR1"),
            "chip-select needs address and option-register evidence");
        String mixed = RAGQueryFocus.focus("SIMCR MM oraz CSOR0 i CSBAR0");
        ok(mixed.contains("SIMCR") && mixed.contains("CSOR0") && mixed.contains("CSBAR0"),
            "SIMCR must not erase a concurrent chip-select question");
        ok(RAGQueryFocus.isChipSelectQuery("QSPI peripheral chip select unrelated?"),
            "explicit chip-select phrase is recognized");
        ok(RAGQueryFocus.focus("Jak działa watchdog?").contains("watchdog"),
            "unrelated queries are unchanged");
        System.out.println("RAGQueryFocusSelfTest OK");
    }
}
