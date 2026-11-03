package ghidrassist.automation;

import ghidra.program.model.listing.Program;
import ghidra.framework.model.Project;
import java.nio.file.Path;

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

    /**
     * An explicit *copy-only* operator attestation. Neither a token nor a filename
     * proves a project was copied: launchers must require the user to supply a
     * separate working-copy project and verify it before granting this capability.
     */
    public static void requireReviewCopy(Program program, Project project) {
        if(mode()!=Mode.AUTO_SAFE ||
                !Boolean.getBoolean("ghidrassist.automation.reviewCopy") ||
                Boolean.getBoolean("ghidrassist.automation.syntheticWrites"))
            throw new IllegalStateException("Review-copy AUTO_SAFE capability not enabled");
        if(program==null || project==null || program.getDomainFile()==null ||
                !program.getDomainFile().canSave() || program.getDomainFile().isReadOnly())
            throw new IllegalStateException("Writable project copy and program required");
        String expectedProject=System.getProperty("ghidrassist.automation.reviewCopyProject","");
        String expectedProgram=System.getProperty("ghidrassist.automation.reviewCopyProgram","");
        String expectedHash=System.getProperty("ghidrassist.automation.reviewCopySha256","");
        if(expectedProject.isBlank() || !expectedProgram.startsWith("/") ||
                !expectedHash.matches("(?i)[0-9a-f]{64}"))
            throw new IllegalStateException("Review-copy identity receipt incomplete");
        Path actual=Path.of(project.getProjectLocator().getLocation(),
            project.getProjectLocator().getName()+".gpr").toAbsolutePath().normalize();
        if(!actual.equals(Path.of(expectedProject).toAbsolutePath().normalize()) ||
                !expectedProgram.equals(program.getDomainFile().getPathname()) ||
                program.getExecutableSHA256()==null ||
                !expectedHash.equalsIgnoreCase(program.getExecutableSHA256()))
            throw new IllegalStateException("Active project/program/source hash differs from copy receipt");
    }

    /** FULL_CONTROL is a declared capability, not blanket authorization. */
    public static void requireProductionWrite(Program program) {
        throw new IllegalStateException(
            "Production agent writes not enabled; use GUI Review/Apply or an isolated test fixture");
    }
}
