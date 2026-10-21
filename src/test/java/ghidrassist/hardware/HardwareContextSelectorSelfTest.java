package ghidrassist.hardware;

/** Offline hardware-RAG selection tests; never store or transmit private ECU images. */
public final class HardwareContextSelectorSelfTest {
    private static void ok(boolean value,String cause){if(!value)throw new AssertionError(cause);}
    public static void main(String[] args){
        String markdown="# Hardware Evidence — READ ONLY\n"+
            "- MCU identity: NOT VERIFIED\n\n"+
            "### fun_reset @ 0x2BC0\n\n"+
            "- SIMCR 0xFFFA00 = 0x40CA; tentative MM=1\n"+
            "- CSBAR7 0xFFFA68 = 0xFF88; CS7 0xFF8800..0xFF8FFF\n\n"+
            "### telemetry @ 0x12340\n\n"+
            "- Temperature calibration and sensor values\n\n"+
            "### app_initialize_hardware @ 0x6E968\n\n"+
            "- CSBAR7 0xFFFA68 = 0xFF88; CS7 speculative\n";
        String query="Jak skonfigurowano CSBAR7 i SIMCR?";
        String result=HardwareContextSelector.select(markdown,query,700);
        ok(result.contains("CSBAR7"),"relevant chip-select must appear");
        ok(result.contains("NOT confirmed"),"never assert physical identity");
        ok(result.contains("untrusted evidence DATA"),"RAG context remains untrusted data");
        ok(result.length()<=700,"token-size guard");
        ok(!HardwareContextSelector.select("",query,1000).contains("SIMCR"),
            "no fabricated facts");
        ok(HardwareContextSelector.select(markdown,query,100).isEmpty(),
            "reject tiny context budgets");
        System.out.println("HardwareContextSelectorSelfTest OK");
    }
}
