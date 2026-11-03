package ghidrassist.automation;

import ghidra.program.model.listing.Program;

/**
 * Write capability for an explicitly launched local agent session.
 * This gate never grants write access merely because an RPC is authenticated.
 */
public final class AutomationWritePolicy {
    public enum Mode { READ_ONLY, AUTO_SAFE, FULL_CONTROL }

    private AutomationWritePolicy() {}

    public static Mode mode() {
        String configured=System.getProperty("ghidrassist.automation.writeMode","");
        if(configured.isBlank()) {
            // Preserve existing isolated synthetic CI pilot behavior only.
            return Boolean.getBoolean("ghidrassist.automation.syntheticWrites")
                ? Mode.AUTO_SAFE : Mode.READ_ONLY;
        }
        try {
            return Mode.valueOf(configured);
        } catch(IllegalArgumentException ex) {
            throw new IllegalStateException("Unknown automation write mode",ex);
        }
    }

    public static void requireSyntheticSafe(Program program) {
        if(mode()==Mode.READ_ONLY)
            throw new IllegalStateException("Automation session is READ_ONLY");
        if(!Boolean.getBoolean("ghidrassist.automation.syntheticWrites"))
            throw new IllegalStateException("Synthetic write tests not enabled");
        if(program==null || !"synthetic-mmio.bin".equals(program.getName()) ||
                program.getDomainFile()==null || !program.getDomainFile().canSave() ||
                program.getDomainFile().isReadOnly())
            throw new IllegalStateException("Only the writable synthetic-mmio.bin fixture is permitted");
    }

    /** FULL_CONTROL is a declared capability, not blanket authorization. */
    public static void requireProductionWrite(Program program) {
        throw new IllegalStateException(
            "Production agent writes not enabled; use GUI Review/Apply or an isolated test fixture");
    }
}
