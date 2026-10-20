package ghidrassist.hardware;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Read-only evidence collection for MC68332 SIMCR/MM. Does not patch memory,
 * generate labels or claim to know runtime control-flow order.
 *
 * Known limitation: a pointer computed in a register may have no reference to
 * SIMCR. The conservative report must explicitly say that the inventory may
 * be incomplete. Local p-code/constant propagation will be added later.
 */
public final class SimcrMmAnalyzer {
    public enum Effect { SET_MM, CLEAR_MM, PRESERVE_MM, UNKNOWN }
    public enum Confidence { DIRECT_IMMEDIATE, POSSIBLE_REFERENCE, HEURISTIC }

    public static final class Finding {
        public final Address instruction;
        public final long registerAddress;
        public final String instructionText;
        public final boolean referencedAsWrite;
        public final Effect effect;
        public final Confidence confidence;
        public final String explanation;

        private Finding(Address instruction, long registerAddress, String instructionText,
                boolean referencedAsWrite, Effect effect, Confidence confidence,
                String explanation) {
            this.instruction = instruction;
            this.registerAddress = registerAddress;
            this.instructionText = instructionText;
            this.referencedAsWrite = referencedAsWrite;
            this.effect = effect;
            this.confidence = confidence;
            this.explanation = explanation;
        }
    }

    public static final class Report {
        public final String profile;
        public final List<Finding> findings;
        public final int xrefCount;
        public final int scannedInstructionCount;
        public final String caveat;

        private Report(String profile, List<Finding> findings, int xrefCount,
                int scannedInstructionCount) {
            this.profile = profile;
            this.findings = Collections.unmodifiableList(new ArrayList<>(findings));
            this.xrefCount = xrefCount;
            this.scannedInstructionCount = scannedInstructionCount;
            this.caveat = "Static candidate sites only, not executed writes. On MC68332, " +
                "the MM field is write-once after reset; several SET_MM sites do not " +
                "imply several successful MM updates. Access to 0xFFFA00 as SIMCR " +
                "requires MM=1 at that time. Indirect addressing, modified pointers, " +
                "aliases, data embedded in code and self-modifying code may be missed. " +
                "No runtime order, final MM value or chip-select map is inferred.";
        }

        public long count(Effect effect) {
            return findings.stream().filter(f -> f.effect == effect).count();
        }

        public String toText() {
            StringBuilder b = new StringBuilder();
            b.append("Hardware Analysis (READ ONLY)\n");
            b.append("Profile: ").append(profile).append("\n");
            b.append("SIMCR candidates: 0x7FFA00 / 0xFFFA00 (16-bit), plus +1 low-byte targets\n");
            b.append("XREFs: ").append(xrefCount).append("; instructions scanned: ")
                .append(scannedInstructionCount).append("\n");
            b.append("SET_MM candidate sites: ").append(count(Effect.SET_MM))
                .append("; clear: ").append(count(Effect.CLEAR_MM))
                .append("; preserve: ").append(count(Effect.PRESERVE_MM))
                .append("; unknown: ").append(count(Effect.UNKNOWN)).append("\n\n");
            for (Finding f : findings) {
                b.append(f.instruction).append(" -> SIMCR 0x")
                    .append(Long.toHexString(f.registerAddress).toUpperCase(Locale.ROOT))
                    .append(" ").append(f.effect).append(" [").append(f.confidence)
                    .append("] ").append(f.instructionText).append("\n");
                b.append("    ").append(f.explanation).append("\n");
            }
            b.append("\nWARNING: ").append(caveat).append("\n");
            return b.toString();
        }
    }

    public Report analyze(Program program, HardwareProfiles.Profile profile,
            TaskMonitor monitor) throws CancelledException {
        if (program == null || profile == null) {
            throw new IllegalArgumentException("Program and profile are required");
        }
        if (!"MC68332".equals(profile.id) || !profile.concreteDevice) {
            throw new IllegalArgumentException("SIMCR/MM decoding requires explicit MC68332 profile");
        }
        if (monitor == null) monitor = TaskMonitor.DUMMY;

        HardwareProfiles.Register simcr = profile.register("SIMCR");
        long low = profile.absoluteAddress(simcr, 0);
        long high = profile.absoluteAddress(simcr, 1);
        Map<String, Finding> found = new LinkedHashMap<>();
        int references = 0;
        for (long addrValue : new long[]{ low, low + 1, high, high + 1 }) {
            monitor.checkCancelled();
            Address target = program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(addrValue);
            ReferenceIterator refs = program.getReferenceManager().getReferencesTo(target);
            while (refs.hasNext()) {
                monitor.checkCancelled();
                Reference ref = refs.next();
                references++;
                Instruction insn = program.getListing().getInstructionContaining(ref.getFromAddress());
                if (insn == null) continue;
                boolean write = ref.getReferenceType().isWrite();
                Finding finding = interpret(insn, addrValue, write, Confidence.POSSIBLE_REFERENCE);
                String candidateKey = key(insn, addrValue);
                Finding previous = found.get(candidateKey);
                if (previous == null || (!previous.referencedAsWrite && write)) {
                    found.put(candidateKey, finding);
                }
            }
        }

        // XREF-free programs are common for raw firmware: inspect explicit
        // destination operands but never treat an arbitrary immediate as an address.
        int scanned = 0;
        InstructionIterator iterator = program.getListing().getInstructions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction insn = iterator.next();
            scanned++;
            int operands = insn.getNumOperands();
            if (operands < 1) continue;
            String mnemonic = mnemonic(insn);
            if (!(mnemonic.startsWith("MOVE") || mnemonic.equals("ORI") ||
                    mnemonic.equals("ANDI") || mnemonic.equals("EORI") ||
                    mnemonic.equals("BSET") || mnemonic.equals("BCLR"))) {
                continue;
            }
            int dest = operands - 1; // Motorola syntax: destination last.
            if (!isAbsoluteDestination(insn, dest)) continue;
            for (long addrValue : new long[]{ low, low + 1, high, high + 1 }) {
                if (!matchesAddress(insn, dest, addrValue)) continue;
                String k = key(insn, addrValue);
                if (!found.containsKey(k)) {
                    found.put(k, interpret(insn, addrValue, true, Confidence.HEURISTIC));
                }
            }
        }
        return new Report(profile.id, new ArrayList<>(found.values()), references, scanned);
    }

    private static String key(Instruction insn, long target) {
        return insn.getAddress().toString() + "/" + Long.toHexString(target);
    }

    private static String mnemonic(Instruction insn) {
        String m = insn.getMnemonicString().toUpperCase(Locale.ROOT);
        int dot = m.indexOf('.');
        return dot >= 0 ? m.substring(0, dot) : m;
    }

    private static boolean isAbsoluteDestination(Instruction insn, int op) {
        Object[] objects = insn.getOpObjects(op);
        if (objects == null) return false;
        for (Object o : objects) if (o instanceof Register) return false;
        String representation = insn.getDefaultOperandRepresentation(op);
        if (representation == null || representation.isBlank() ||
            representation.contains("#") || representation.contains("[") ||
            representation.contains("%")) return false;
        // Absolute 68k operands may appear as ($FFFA00).L; parentheses
        // are not by themselves a sign of register-indirect addressing.
        String upper = representation.toUpperCase(Locale.ROOT);
        for (String reg : new String[]{"A0","A1","A2","A3","A4","A5","A6","A7","PC",
                "SP","D0","D1","D2","D3","D4","D5","D6","D7"}) {
            if (upper.matches(".*(^|[^A-Z0-9])" + reg + "($|[^A-Z0-9]).*")) {
                return false;
            }
        }
        return true;
    }

    private static boolean matchesAddress(Instruction insn, int op, long target) {
        Object[] objects = insn.getOpObjects(op);
        if (objects == null) return false;
        for (Object o : objects) {
            if (o instanceof Address a && a.getOffset() == target) return true;
            if (o instanceof Scalar s && s.getUnsignedValue() == target) return true;
        }
        return false;
    }

    private static Finding interpret(Instruction insn, long target,
            boolean write, Confidence fallbackConfidence) {
        String full = insn.toString();
        if (!write) {
            return new Finding(insn.getAddress(), target, full, false,
                Effect.UNKNOWN, Confidence.POSSIBLE_REFERENCE,
                "Reference is not marked as a write; may be a read or an address lookup.");
        }

        String m = mnemonic(insn);
        int operands = insn.getNumOperands();
        if (operands != 2 || !isAbsoluteDestination(insn, 1) ||
                !matchesAddress(insn, 1, target)) {
            return new Finding(insn.getAddress(), target, full, true,
                Effect.UNKNOWN, fallbackConfidence,
                "Possible write; destination or source not proven to be a direct immediate.");
        }

        // Immediate operand must be explicitly marked #; otherwise Scalar
        // objects may denote displacement or address and are not reliable.
        String sourceText = insn.getDefaultOperandRepresentation(0);
        Scalar s = insn.getScalar(0);
        if (sourceText == null || !sourceText.trim().startsWith("#") || s == null) {
            return new Finding(insn.getAddress(), target, full, true,
                Effect.UNKNOWN, fallbackConfidence,
                "Source is register/memory or non-immediate; requires value-flow analysis.");
        }

        long immediate = s.getUnsignedValue();
        boolean lowByteAddress = (target & 1L) != 0;
        int relevantMask = lowByteAddress ? 0x40 : HardwareProfiles.MM_MASK;
        boolean mmBit = (immediate & relevantMask) != 0;
        Effect effect = Effect.UNKNOWN;
        String explanation = "Immediate value alone does not determine MM.";
        String mn = insn.getMnemonicString().toUpperCase(Locale.ROOT);
        boolean word = mn.endsWith(".W") && !lowByteAddress;
        boolean relevantByte = mn.endsWith(".B") && lowByteAddress;
        if (m.equals("MOVE") && (word || relevantByte)) {
            effect = mmBit ? Effect.SET_MM : Effect.CLEAR_MM;
            explanation = "Immediate overwrite of relevant SIMCR word/low-byte, fixing MM.";
        } else if (m.equals("ORI") && (word || relevantByte) && mmBit) {
            effect = Effect.SET_MM;
            explanation = "OR mask includes MM.";
        } else if (m.equals("ORI") && (word || relevantByte)) {
            effect = Effect.PRESERVE_MM;
            explanation = "OR mask excludes MM.";
        } else if (m.equals("ANDI") && (word || relevantByte) && !mmBit) {
            effect = Effect.CLEAR_MM;
            explanation = "AND mask clears MM.";
        } else if (m.equals("ANDI") && (word || relevantByte)) {
            effect = Effect.PRESERVE_MM;
            explanation = "AND mask preserves MM.";
        } else if ((m.equals("BSET") || m.equals("BCLR")) &&
                lowByteAddress && immediate == 6) {
            effect = m.equals("BSET") ? Effect.SET_MM : Effect.CLEAR_MM;
            explanation = "68k memory bit operation on SIMCR low byte at base+1, bit 6.";
        } else if (m.equals("BSET") || m.equals("BCLR")) {
            effect = Effect.PRESERVE_MM;
            explanation = "68k memory bit operation does not target MM bit 6 at SIMCR+1.";
        } else if (m.equals("EORI") && (word || relevantByte) && !mmBit) {
            effect = Effect.PRESERVE_MM;
            explanation = "XOR mask excludes MM.";
        } else if (m.equals("EORI") && (word || relevantByte)) {
            explanation = "XOR toggles MM; incoming MM value is required.";
        }
        return new Finding(insn.getAddress(), target, full, true,
            effect, Confidence.DIRECT_IMMEDIATE, explanation);
    }
}
