package ghidrassist.hardware;

/**
 * GA-01/02/03/11: exact *syntactic* direct-CALL evidence gate.
 *
 * Ghidra may expose a single user-/analysis-created CALL reference on an
 * instruction whose decoded flow type is still COMPUTED_CALL. A reference
 * cannot promote JSR (An), an unknown register, or a bounded byte-proven
 * indirect source to a global direct-call graph edge. CPU32 decoding,
 * not reference cardinality, must establish directness.
 *
 * True means an eligible direct-call SOURCE candidate only. The caller
 * must still verify exactly one recognized callee FUNCTION ENTRY.
 * It never proves actual execution, a branch condition, MMIO effects,
 * an active VBR/ISR, or Review/Apply authorization.
 */
public final class HardwareDirectCallGate {
    private HardwareDirectCallGate() {}

    /** Unknown/untrusted or ambiguous call sites cannot become graph edges. */
    public static boolean directCandidate(boolean isCall,boolean computed,
            int flowTargetCount) {
        return isCall && !computed && flowTargetCount==1;
    }
}
