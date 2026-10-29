package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Pure, model-scoped interpretation of *complete* observed register words.
 * No Ghidra writes, no execution trace, no hardware state inference.
 * Only source-paginated bitfields from the explicitly selected profile
 * may be decoded. Unspecified bits are never assigned invented meanings.
 */
public final class HardwareBitfieldDecoder {
    private HardwareBitfieldDecoder() {}

    public enum Status {
        DECODED, DEVICE_NOT_SELECTED, REGISTER_UNKNOWN, VALUE_UNKNOWN,
        WIDTH_MISMATCH, VALUE_OUT_OF_RANGE, NO_SOURCED_FIELDS
    }

    public record FieldEvidence(String name, int mask, int value,
            String sourcePage, boolean writeOnceAfterReset) {}

    public record Result(Status status, String profile, String register,
            Integer observedWord, int widthBits, List<FieldEvidence> fields,
            long unspecifiedMask) {
        public Result {
            fields = List.copyOf(fields);
        }

        /** Safe, bounded, single-line Markdown detail for a *static* code site. */
        public String summary() {
            if (status != Status.DECODED) {
                return "bitfield decode " + status + " (no hardware state inferred)";
            }
            StringBuilder b = new StringBuilder("documented " + profile + " fields [");
            for (int i = 0; i < fields.size(); i++) {
                FieldEvidence f = fields.get(i);
                if (i > 0) b.append("; ");
                int shiftedMask = f.mask() >>> Integer.numberOfTrailingZeros(f.mask());
                b.append(f.name()).append("=")
                    .append(shiftedMask == 1
                        ? Integer.toString(f.value())
                        : "0x" + Integer.toHexString(f.value()).toUpperCase(Locale.ROOT))
                    .append(" (mask ")
                    .append(hex(Integer.toUnsignedLong(f.mask()), widthBits))
                    .append("; ").append(f.sourcePage());
                if (f.writeOnceAfterReset()) b.append("; write-once after reset");
                b.append(")");
            }
            b.append("]; other bits UNINTERPRETED (mask ")
                .append(hex(unspecifiedMask, widthBits))
                .append("); static constant only, not proven hardware state or write order");
            return b.toString();
        }
    }

    /**
     * @param widthBits actual width of a complete literal register write;
     *                  caller must reject partial/merged/unknown writes.
     * A generic CPU32 ISA profile must never inherit MC68332 bit meanings.
     */
    public static Result decode(HardwareProfiles.Profile profile, String registerName,
            Integer observedWord, int widthBits) {
        String name = registerName == null ? "" :
            registerName.toUpperCase(Locale.ROOT);
        String id = profile == null ? "UNKNOWN" : profile.id;
        if (profile == null || !profile.concreteDevice)
            return result(Status.DEVICE_NOT_SELECTED,id,name,observedWord,widthBits);
        HardwareProfiles.Register reg = profile.register(name);
        if (reg == null)
            return result(Status.REGISTER_UNKNOWN,id,name,observedWord,widthBits);
        if (widthBits != reg.widthBits)
            return result(Status.WIDTH_MISMATCH,id,name,observedWord,widthBits);
        if (observedWord == null)
            return result(Status.VALUE_UNKNOWN,id,name,null,widthBits);
        long fullMask = (1L << widthBits) - 1;
        long unsigned = Integer.toUnsignedLong(observedWord);
        if ((unsigned & ~fullMask) != 0)
            return result(Status.VALUE_OUT_OF_RANGE,id,name,observedWord,widthBits);
        List<FieldEvidence> evidence = new ArrayList<>();
        long documented = 0;
        for (HardwareProfiles.BitField f : reg.fields) {
            if (f.sourcePage == null || f.sourcePage.isBlank() ||
                    "UNVERIFIED".equalsIgnoreCase(f.sourcePage))
                continue; // Never promote unsourced fields to verified facts.
            int shift = Integer.numberOfTrailingZeros(f.mask);
            int value = (observedWord & f.mask) >>> shift;
            evidence.add(new FieldEvidence(f.name,f.mask,value,
                f.sourcePage,f.writeOnceAfterReset));
            documented |= Integer.toUnsignedLong(f.mask);
        }
        if (evidence.isEmpty())
            return result(Status.NO_SOURCED_FIELDS,id,name,observedWord,widthBits);
        return new Result(Status.DECODED,id,name,observedWord,widthBits,
            evidence, fullMask & ~documented);
    }

    private static Result result(Status status,String profile,String name,
            Integer value,int widthBits) {
        return new Result(status,profile,name,value,widthBits,List.of(),0);
    }

    private static String hex(long value,int bits) {
        return String.format(Locale.ROOT,"0x%0" + (bits / 4) + "X",value);
    }
}
