package ghidrassist.hardware;

import java.util.Collection;

/**
 * Conservative resolution of P-code STORE sites.
 * A constant destination is usable only when EVERY STORE in the instruction
 * refers to the same known location and there is exactly one STORE. Multiple
 * memory effects (including MOVEM), unknown aliases and missing STOREs cannot
 * be promoted to an MMIO constant without stronger proof.
 */
public final class HardwarePcodeStoreSafety {
    private HardwarePcodeStoreSafety() {}

    public static Long uniqueTarget(Collection<Long> stores) {
        if (stores == null || stores.size() != 1) return null;
        Long target = stores.iterator().next();
        if (target == null || target < 0 || target > HardwareDataflow.MASK24)
            return null;
        return target;
    }

    /** Any STORE without a provable single address is an MMIO alias barrier. */
    public static boolean unknownAlias(Collection<Long> stores) {
        return stores != null && !stores.isEmpty() && uniqueTarget(stores) == null;
    }
}
