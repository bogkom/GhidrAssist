package ghidrassist.hardware;

import java.util.List;
import java.util.Locale;

/**
 * Conservative MOVEC direction classification. The caller supplies Ghidra's
 * decoded operand-register names in instruction order; no textual disassembly
 * or source-code address is trusted as a substitute for decoded operands.
 */
public final class HardwareMovecDirectionEvidence {
    private HardwareMovecDirectionEvidence() {}

    public enum Verdict { TO_VBR, NOT_TO_VBR, UNKNOWN }

    public static Verdict classify(boolean movec, int operandCount,
            List<String> sourceRegisters, List<String> destinationRegisters,
            boolean sourceHasNonRegister, boolean destinationHasNonRegister) {
        if (!movec) return Verdict.NOT_TO_VBR;
        if (operandCount != 2 || sourceRegisters == null || destinationRegisters == null ||
                sourceHasNonRegister || destinationHasNonRegister ||
                sourceRegisters.size() != 1 || destinationRegisters.size() != 1)
            return Verdict.UNKNOWN;
        String source = sourceRegisters.get(0);
        String destination = destinationRegisters.get(0);
        if (source == null || destination == null || source.isBlank() || destination.isBlank())
            return Verdict.UNKNOWN;
        String s = source.toUpperCase(Locale.ROOT);
        String d = destination.toUpperCase(Locale.ROOT);
        // MOVEC VBR,VBR or duplicate destination-register evidence is not a
        // trustworthy independent write witness.
        if (s.equals(d)) return Verdict.UNKNOWN;
        return d.equals("VBR") ? Verdict.TO_VBR : Verdict.NOT_TO_VBR;
    }
}
