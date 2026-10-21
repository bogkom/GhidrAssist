package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Explicit, source-backed CPU profiles. Ghidra's language ID is NOT a CPU
 * identification: only the caller may select a specific device profile.
 *
 * Addresses describe on-chip register locations, not externally decoded memory.
 * CSBAR/CSOR windows are runtime state and must never be inferred from the
 * register addresses alone.
 */
public final class HardwareProfiles {
    private HardwareProfiles() {}

    public static final String MC68332_MANUAL =
        "https://www.nxp.com/docs/en/data-sheet/MC68332TS.pdf";
    public static final int MM_MASK = 0x0040;
    public static final long INTERNAL_BASE_MM0 = 0x7ff000L;
    public static final long INTERNAL_BASE_MM1 = 0xfff000L;

    public static final class BitField {
        public final String name;
        public final int mask;
        public final String meaning;

        private BitField(String name, int mask, String meaning) {
            this.name = name;
            this.mask = mask;
            this.meaning = meaning;
        }
    }

    public static final class Register {
        public final String module;
        public final String name;
        /** Offset from the selected 4 KiB internal register window. */
        public final int offset;
        public final int widthBits;
        public final List<BitField> fields;
        public final String source;

        private Register(String module, String name, int offset, int widthBits,
                List<BitField> fields, String source) {
            this.module = module;
            this.name = name;
            this.offset = offset;
            this.widthBits = widthBits;
            this.fields = Collections.unmodifiableList(new ArrayList<>(fields));
            this.source = source;
        }
    }

    public static final class Profile {
        public final String id;
        public final String family;
        public final boolean concreteDevice;
        public final List<Register> registers;
        private final Map<String, Register> byName;

        private Profile(String id, String family, boolean concreteDevice,
                List<Register> registers) {
            this.id = id;
            this.family = family;
            this.concreteDevice = concreteDevice;
            this.registers = Collections.unmodifiableList(new ArrayList<>(registers));
            Map<String, Register> lookup = new LinkedHashMap<>();
            for (Register register : registers) {
                if (lookup.put(register.name, register) != null) {
                    throw new IllegalArgumentException("Duplicate register: " + register.name);
                }
            }
            byName = Collections.unmodifiableMap(lookup);
        }

        public Register register(String name) {
            return byName.get(name.toUpperCase(Locale.ROOT));
        }

        public long absoluteAddress(Register register, int mm) {
            if (!concreteDevice || register == null) {
                throw new IllegalStateException("A concrete verified device profile is required");
            }
            if (mm != 0 && mm != 1) {
                throw new IllegalArgumentException("MM must be 0 or 1");
            }
            return (mm == 0 ? INTERNAL_BASE_MM0 : INTERNAL_BASE_MM1) + register.offset;
        }
    }

    /** Generic CPU32 ISA family does not imply MC68332 peripherals. */
    public static Profile cpu32Family() {
        return new Profile("CPU32", "CPU32", false, Collections.emptyList());
    }

    /** Device profile: must be explicitly selected or independently verified. */
    public static Profile mc68332() {
        List<Register> r = new ArrayList<>();
        String source = MC68332_MANUAL + " ; SIM address map and SIMCR";
        List<BitField> simcrFields = List.of(
            new BitField("MM", MM_MASK,
                "0: internal modules at 0x7ff000-0x7fffff; 1: 0xfff000-0xffffff"),
            new BitField("IARB", 0x000f, "SIM interrupt arbitration ID"));
        r.add(new Register("SIM", "SIMCR", 0x0a00, 16, simcrFields, source));
        r.add(reg("SIM", "SYNCR", 0x0a04, 16, source));
        r.add(reg("SIM", "CSPAR0", 0x0a44, 16, source));
        r.add(reg("SIM", "CSPAR1", 0x0a46, 16, source));
        r.add(reg("SIM", "CSBARBT", 0x0a48, 16, source));
        r.add(reg("SIM", "CSORBT", 0x0a4a, 16, source));
        for (int cs = 0; cs <= 10; cs++) {
            int offset = 0x0a4c + cs * 4;
            r.add(reg("SIM", "CSBAR" + cs, offset, 16, source));
            r.add(reg("SIM", "CSOR" + cs, offset + 2, 16, source));
        }
        // Distinct internal modules; these register-address entries are
        // MC68332-only hypotheses and are NOT CPU32 family-wide guarantees.
        r.add(reg("TPURAM", "TRAMMCR", 0x0b00, 16, MC68332_MANUAL));
        r.add(reg("TPURAM", "TRAMBAR", 0x0b04, 16, MC68332_MANUAL));
        r.add(reg("QSM", "QSMCR", 0x0c00, 16, MC68332_MANUAL));
        r.add(reg("TPU", "TPUMCR", 0x0e00, 16, MC68332_MANUAL));
        return new Profile("MC68332", "CPU32", true, r);
    }

    private static Register reg(String module, String name, int offset,
            int widthBits, String source) {
        return new Register(module, name, offset, widthBits, List.of(), source);
    }

    public static Profile select(String id) {
        if ("CPU32".equalsIgnoreCase(id)) return cpu32Family();
        if ("MC68332".equalsIgnoreCase(id)) return mc68332();
        throw new IllegalArgumentException("Unknown profile: " + id +
            "; do not silently substitute another chip");
    }

    /**
     * Decode a CSBAR *potential* 24-bit address window. It may be inactive:
     * actual assertion requires the corresponding CSPAR and CSOR settings,
     * address/function-code matching and the current execution phase.
     */
    public static final class CsbarWindow {
        public final long base;
        public final long size;
        public final long endInclusive;

        private CsbarWindow(long base, long size) {
            this.base = base;
            this.size = size;
            this.endInclusive = base + size - 1;
        }
    }

    public static CsbarWindow decodeCsbar(int value) {
        long[] sizes = { 2048, 8192, 16384, 65536, 131072, 262144, 524288, 1048576 };
        long size = sizes[value & 7];
        long address = ((long) (value & 0xfff8)) << 8;
        long alignedBase = address & ~(size - 1);
        return new CsbarWindow(alignedBase, size);
    }
}
