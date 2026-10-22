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
        ok(RAGQueryFocus.focus("Jak działa watchdog?").contains("watchdog"),
            "unrelated queries are unchanged");
        System.out.println("RAGQueryFocusSelfTest OK");
    }
}
