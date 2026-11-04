package ghidrassist.hardware;

import java.util.Locale;

/** Parse exact CPU32 A/D operands without upgrading a partial-width register. */
public final class HardwareRegisterOperand {
    private HardwareRegisterOperand(){}
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
