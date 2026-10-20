// Run after installing the GhidrAssist extension built from this branch.
//@category GhidrAssist.Hardware
import ghidra.app.script.GhidraScript;
import ghidrassist.hardware.HardwareProfiles;
import ghidrassist.hardware.SimcrMmAnalyzer;

import java.util.Arrays;

/**
 * First-stage read-only SIMCR/MM probe. This is intentionally a script runner:
 * the permanent Hardware Analysis tab is planned for a later phase.
 */
public class GhidrAssist_SIMCR_MM_Report extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open a program first.");
            return;
        }

        String profileId = askChoice("Hardware profile (explicit selection)",
            "Choose a profile. The Ghidra language ID alone does NOT identify the chip.",
            Arrays.asList("CPU32", "MC68332"), "MC68332");
        if (!"MC68332".equals(profileId)) {
            printerr("CPU32 is an instruction-set family, not a peripheral profile. " +
                "Choose a confirmed device to perform SIMCR analysis.");
            return;
        }

        String language = currentProgram.getLanguageID().toString();
        println("Program: " + currentProgram.getName());
        println("Ghidra language (not hardware proof): " + language);
        println("Hardware profile selected by user: " + profileId);
        SimcrMmAnalyzer.Report report = new SimcrMmAnalyzer()
            .analyze(currentProgram, HardwareProfiles.select(profileId), monitor);
        println(report.toText());
    }
}
