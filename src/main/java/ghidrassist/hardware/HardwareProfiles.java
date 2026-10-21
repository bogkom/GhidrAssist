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
        "https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf";
    public static final int MM_MASK = 0x0040;
    public static final long INTERNAL_BASE_MM0 = 0x7ff000L;
    public static final long INTERNAL_BASE_MM1 = 0xfff000L;

    public static final class BitField {
        public final String name;
        public final int mask;
        public final String meaning;
        /** Null means no reset value established from a source. */
        public final Integer resetValue;
        public final String sourcePage;
        public final boolean writeOnceAfterReset;

        private BitField(String name, int mask, String meaning) {
            this(name, mask, meaning, null, "UNVERIFIED", false);
        }

        private BitField(String name, int mask, String meaning, Integer resetValue,
                String sourcePage, boolean writeOnceAfterReset) {
            if (name == null || name.isBlank() || mask == 0 ||
                    (resetValue != null && (resetValue & ~mask) != 0))
                throw new IllegalArgumentException("Invalid bitfield");
            this.name = name;
            this.mask = mask;
            this.meaning = meaning;
            this.resetValue = resetValue;
            this.sourcePage = sourcePage;
            this.writeOnceAfterReset = writeOnceAfterReset;
        }
    }

    /** Module aperture is not a claim that every byte is an implemented register. */
    public static final class ModuleRegion {
        public final String id, blockName, sourcePage;
        public final int offset, sizeBytes;
        private ModuleRegion(String id, String blockName, int offset, int sizeBytes,
                String sourcePage) {
            if (offset < 0 || sizeBytes < 1 || offset + sizeBytes > 0x1000)
                throw new IllegalArgumentException("Invalid module aperture");
            this.id = id; this.blockName = blockName;
            this.offset = offset; this.sizeBytes = sizeBytes; this.sourcePage = sourcePage;
        }
    }

    public enum Access { SUPERVISOR, CONFIGURABLE_SUPERVISOR_USER, UNKNOWN }
    public enum WritePolicy { READ_WRITE, READ_ONLY, UNKNOWN }

    public static final class Register {
        public final String module;
        public final String name;
        /** Offset from the selected 4 KiB internal register window. */
        public final int offset;
        public final int widthBits;
        public final List<BitField> fields;
        public final String source;
        public final String sourcePage;
        public final Access access;
        public final WritePolicy writePolicy;
        /** Null = unknown/conditional reset, not zero. */
        public final Integer resetValue;

        private Register(String module, String name, int offset, int widthBits,
                List<BitField> fields, String source) {
            this(module, name, offset, widthBits, fields, source, "UNVERIFIED",
                Access.UNKNOWN, WritePolicy.UNKNOWN, null);
        }
        private Register(String module, String name, int offset, int widthBits,
                List<BitField> fields, String source, String sourcePage,
                Access access, WritePolicy writePolicy, Integer resetValue) {
            if (widthBits != 8 && widthBits != 16 && widthBits != 32)
                throw new IllegalArgumentException("Unsupported register width");
            if (offset < 0 || offset + widthBits / 8 > 0x1000 ||
                    (widthBits > 8 && offset % (widthBits / 8) != 0))
                throw new IllegalArgumentException("Invalid register offset");
            int used = 0;
            for (BitField field : fields) {
                if ((field.mask & used) != 0 ||
                        (widthBits < 32 && (field.mask >>> widthBits) != 0))
                    throw new IllegalArgumentException("Overlapping/out of range bitfield");
                used |= field.mask;
            }
            if (resetValue != null &&
                    ((resetValue & ~((1L << widthBits) - 1)) != 0))
                throw new IllegalArgumentException("Reset value exceeds register width");
            this.module = module;
            this.name = name;
            this.offset = offset;
            this.widthBits = widthBits;
            this.fields = Collections.unmodifiableList(new ArrayList<>(fields));
            this.source = source;
            this.sourcePage = sourcePage;
            this.access = access;
            this.writePolicy = writePolicy;
            this.resetValue = resetValue;
        }
    }

    public static final class Profile {
        public final String id;
        public final String family;
        public final boolean concreteDevice;
        public final List<Register> registers;
        public final List<ModuleRegion> modules;
        private final Map<String, Register> byName;

        private Profile(String id, String family, boolean concreteDevice,
                List<Register> registers, List<ModuleRegion> modules) {
            this.id = id;
            this.family = family;
            this.concreteDevice = concreteDevice;
            this.registers = Collections.unmodifiableList(new ArrayList<>(registers));
            this.modules = List.copyOf(modules);
            for (int i=0; i<modules.size(); i++) {
                ModuleRegion a = modules.get(i);
                for (int j=0; j<i; j++) {
                    ModuleRegion b=modules.get(j);
                    if (a.id.equals(b.id) || a.offset < b.offset+b.sizeBytes &&
                            b.offset < a.offset+a.sizeBytes)
                        throw new IllegalArgumentException("Duplicate/overlapping modules");
                }
            }
            Map<String, Register> lookup = new LinkedHashMap<>();
            for (Register register : registers) {
                boolean inModule = false;
                for (ModuleRegion mod : modules)
                    if (register.module.equals(mod.id) && register.offset >= mod.offset &&
                            register.offset + register.widthBits/8 <= mod.offset+mod.sizeBytes)
                        inModule = true;
                if (!inModule) throw new IllegalArgumentException(
                    "Register outside module: " + register.name);
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
        return new Profile("CPU32", "CPU32", false, List.of(), List.of());
    }

    /** Device profile: must be explicitly selected or independently verified. */
    public static Profile mc68332() {
        List<Register> r = new ArrayList<>();
        String source = MC68332_MANUAL + " ; Appendix D, Table D-2";
        List<BitField> simcrFields = List.of(
            new BitField("MM", MM_MASK,
                "0: internal modules at 0x7ff000-0x7fffff; 1: 0xfff000-0xffffff",
                null, "D-5/D-6 (PDF pages 219-220)", true),
            new BitField("SUPV", 0x0080,
                "Controls access to S/U-class SIM registers", null,
                "D-6 (PDF page 220)", false),
            new BitField("IARB", 0x000f, "SIM interrupt arbitration ID",
                0x000f, "D-6 (PDF page 220)", false));
        r.add(new Register("SIM", "SIMCR", 0x0a00, 16, simcrFields, source,
            "D-4/D-5/D-6 (PDF pages 218-220)", Access.SUPERVISOR,
            WritePolicy.READ_WRITE, null));
        r.add(reg("SIM", "SYNCR", 0x0a04, 16, source));
        // The upper byte of $YFFA06 is reserved; RSR is a single byte at +7.
        r.add(new Register("SIM", "RSR", 0x0a07, 8, List.of(), source,
            "D-4/D-7 (PDF pages 218/221)", Access.SUPERVISOR,
            WritePolicy.READ_ONLY, null));
        r.add(new Register("SIM", "PICR", 0x0a22, 16, List.of(), source,
            "D-4 (PDF page 218)", Access.SUPERVISOR,
            WritePolicy.UNKNOWN, null));
        r.add(new Register("SIM", "PITR", 0x0a24, 16, List.of(), source,
            "D-4 (PDF page 218)", Access.SUPERVISOR,
            WritePolicy.UNKNOWN, null));
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
        List<ModuleRegion> modules = List.of(
            module("SIM", "SIM_REGISTERS_MM1", 0x0a00, 128),
            module("TPURAM", "TPURAM_CONTROL_MM1", 0x0b00, 64),
            module("QSM", "QSM_MM1", 0x0c00, 512),
            module("TPU", "TPU_MM1", 0x0e00, 512));
        return new Profile("MC68332", "CPU32", true, r, modules);
    }

    private static ModuleRegion module(String id, String name, int offset, int size) {
        return new ModuleRegion(id, name, offset, size,
            MC68332_MANUAL + " ; Appendix D, Table D-1, printed D-1 (PDF page 215)");
    }

    private static Register reg(String module, String name, int offset,
            int widthBits, String source) {
        return new Register(module, name, offset, widthBits, List.of(), source,
            module.equals("SIM") ? "D-4/D-5 (PDF pages 218-219)" :
            "Appendix D (page to be verified)", module.equals("SIM") ?
            Access.SUPERVISOR : Access.UNKNOWN, WritePolicy.UNKNOWN, null);
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
