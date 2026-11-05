package ghidrassist.hardware;

import java.util.Locale;

/** Parse exact CPU32 A/D operands without upgrading a partial-width register. */
public final class HardwareRegisterOperand {
    private HardwareRegisterOperand(){}
    /**
     * Exact CPU32 immediate-token gate. Ghidra 12.1.4 PUBLIC prints the
     * short signed MOVEQ immediate as -0x1 WITHOUT '#', unlike MOVE.L.
     * Only MOVEQ has this fixed encoding; every other opcode still
     * requires its explicit '#' marker. Ghidra must ALSO provide a
     * real Scalar for the operand before the value is considered known.
     */
    public static boolean isImmediateToken(String operand,String mnemonic){
        if(operand==null || mnemonic==null)return false;
        String token=operand.toUpperCase(Locale.ROOT).trim();
        if(token.startsWith("#"))return true;
        return "MOVEQ".equals(mnemonic.toUpperCase(Locale.ROOT)) &&
            token.matches("[-+]?(?:0X[0-9A-F]+|[0-9]+)");
    }
    /**
     * Ghidra 12.1.4 CPU32 renders some size-qualified register operands as
     * D0w/D1b/D2l. Only accept that suffix if the instruction spelling has
     * the same width. A destination MOVE.W still remains a PARTIAL Dn write
     * and must be modeled as a clobber by the caller, not SET_POINTER.
     */
    public static String sourceOrDestination(String operand,String mnemonic){
        if(operand==null || mnemonic==null)return null;
        String value=operand.toUpperCase(Locale.ROOT).trim();
        if(value.matches("[AD][0-7]"))return value;
        if(!value.matches("D[0-7][BWL]"))return null;
        String text=mnemonic.toUpperCase(Locale.ROOT);
        if(!text.endsWith("."+value.charAt(2)))return null;
        return value.substring(0,2);
    }
}
