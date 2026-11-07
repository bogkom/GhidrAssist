package ghidrassist.hardware;

/**
 * Pure-Java width-aware constant evaluator for a deliberately small subset
 * of Ghidra P-code. Unknown operations or invalid varnode widths never
 * produce a guessed MMIO destination. Output is the raw unsigned bit pattern
 * at its P-code width; 24-bit MCU bus masking belongs only at STORE.
 */
public final class HardwarePcodeConstantMath {
    private HardwarePcodeConstantMath() {}

    public enum Operation { COPY, ZERO_EXTEND, SIGN_EXTEND, ADD, SUBTRACT }

    private static boolean width(int bytes) {
        return bytes >= 1 && bytes <= Long.BYTES;
    }

    private static long mask(int bytes) {
        return bytes == Long.BYTES ? -1L : (1L << (bytes * 8)) - 1;
    }

    /**
     * Constant propagation is valid only when all operand sizes agree with
     * the declared P-code operation. Arithmetic wraps at the output width,
     * whereas sign extension interprets the sign bit of the INPUT width.
     */
    public static Long evaluate(Operation operation,Long left,int leftBytes,
                                Long right,int rightBytes,int outBytes) {
        if(operation==null || left==null ||
                !width(leftBytes) || !width(outBytes))return null;
        long l=left & mask(leftBytes);
        switch(operation) {
            case COPY:
                if(right!=null || leftBytes!=outBytes)return null;
                return l;
            case ZERO_EXTEND:
                if(right!=null || leftBytes>=outBytes)return null;
                return l;
            case SIGN_EXTEND:
                if(right!=null || leftBytes>=outBytes)return null;
                int shift=64-leftBytes*8;
                return ((l<<shift)>>shift)&mask(outBytes);
            case ADD:
            case SUBTRACT:
                if(right==null || !width(rightBytes) ||
                        leftBytes!=rightBytes || leftBytes!=outBytes)
                    return null;
                long r=right & mask(rightBytes);
                return (operation==Operation.ADD?l+r:l-r)&mask(outBytes);
            default:
                return null;
        }
    }

    /** Only the last CPU32 external address translation is modulo 24-bit. */
    public static Long externalAddress(Long raw,int pointerBytes) {
        // A truncated 8/16-bit value is not an independently proven
        // CPU32 pointer. The actual P-code STORE address is 32-bit.
        if(raw==null || pointerBytes!=4)return null;
        return raw & HardwareDataflow.MASK24;
    }
}
