package ghidrassist.hardware;

/**
 * Presentation-only filter: read-only Analyze shows key MCU initialization
 * sites. Hardware scanning, CFG state, naming and Review / Apply still use
 * the complete processor register catalog.
 */
public final class HardwareReportScope {
    private HardwareReportScope() {}
    public static boolean isInitializationRegister(String name) {
        if (name == null) return false;
        return name.equals("SIMCR") || name.equals("TRAMBAR")
            || name.matches("CSBAR(?:BT|10|[0-9])")
            || name.matches("CSOR(?:BT|10|[0-9])");
    }
}
