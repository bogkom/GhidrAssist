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
        String longReport="# Hardware Evidence — READ ONLY\\n"+
            "### telemetry @ 0x1200\\n"+
            "- Temperature sensor calibration and unrelated variables\\n\\n"+
            "### config_sim @ 0x2BCA\\n"+
            "- SIMCR at 0xFFFA00 value 0x40CA; mapping candidate not runtime fact\\n\\n"+
            "### config_chip_selects @ 0x2BD2\\n"+
            "- CSBAR7 at 0xFFFA68 value 0xFF88; candidate CS7\\n";
        String focused=HardwareContextSelector.select(longReport,
            "Find SIMCR initialization",2400);
        ok(focused.contains("SIMCR") && !focused.contains("sensor calibration") &&
            !focused.contains("CSBAR7 at"),
            "focused query omits unrelated hardware and telemetry sections");
        ok(focused.contains("not instructions") && focused.contains("NOT confirmed"),
            "evidence always separated from instructions and verified facts");
        String broad=HardwareContextSelector.select(longReport,
            "unmatched unspecified question",2400);
        ok(broad.contains("<<<END_LOCAL_GHIDRA_HARDWARE_EVIDENCE>>>"),
            "no-match query still has a closed evidence boundary");
        System.out.println("HardwareContextSelectorSelfTest OK");
    }
}
