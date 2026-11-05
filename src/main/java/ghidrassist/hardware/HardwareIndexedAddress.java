package ghidrassist.hardware;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Strictly parsed Ghidra/Motorola 68k indexed operand syntax. Unrecognized
 * extensions, PC-relative forms and memory-indirect encodings remain unknown.
 * Parsing is NOT proof of a computed value: CFG propagation must know both
 * register operands at the write site.
 */
public final class HardwareIndexedAddress {
    private HardwareIndexedAddress() {}
    /** A CPU32 indexed operand cannot carry an arbitrarily long literal. */
    public static final int MAX_OPERAND_CHARS=128;
    // Full 68k extension displacements are at most 32-bit. An unsigned
    // rendering (0xFFFFFFFF) may denote the same bus-address offset as -1.
    // Reject >32-bit numbers BEFORE modulo-24-bit effective-address math.
    public static final long MIN_SIGNED_DISPLACEMENT=-0x80000000L;
    public static final long MAX_UNSIGNED_DISPLACEMENT=0xffffffffL;
    private static final String NUMBER="(?:[-+]?(?:0X[0-9A-F]+|\\$[0-9A-F]+|[0-9]+))";
    // Ghidra 12.1.4 PUBLIC CPU32 renders the brief extension word as
    // (0x1,A1,D1w*0x1), while other listing renderers use D1.W*1.
    // Accept only these equivalent unambiguous width/scale spellings.
    private static final String INDEX=
        "([AD][0-7])\\.?([WL])(?:\\*((?:[1248]|0X[1248])))?";
    private static final Pattern OUTSIDE=Pattern.compile(
        "^("+NUMBER+")?\\(([AD][0-7]),"+INDEX+"\\)$");
    private static final Pattern INSIDE=Pattern.compile(
        "^\\(("+NUMBER+"),([AD][0-7]),"+INDEX+"\\)$");

    public record Expression(String base, String index, int indexBits,
            int scale, long displacement) {
        public Expression {
            if (base == null || !base.matches("A[0-7]") ||
                    index == null || !index.matches("[AD][0-7]") ||
                    (indexBits != 16 && indexBits != 32) ||
                    (scale != 1 && scale != 2 && scale != 4 && scale != 8))
                throw new IllegalArgumentException("Invalid indexed expression");
        }
    }

    public static Expression parse(String operand) {
        if (operand == null || operand.isBlank() ||
                operand.length()>MAX_OPERAND_CHARS) return null;
        String s=operand.replace(" ","").toUpperCase(Locale.ROOT);
        if (s.contains("[") || s.contains("]") || s.contains("PC") ||
                s.contains("@") || s.contains("#")) return null;
        Matcher m=OUTSIDE.matcher(s);
        boolean interior=false;
        if (!m.matches()) {
            m=INSIDE.matcher(s);
            interior=true;
            if (!m.matches()) return null;
        }
        String displacementText=m.group(1);
        String base=m.group(2),index=m.group(3);
        int bits=m.group(4).equals("W")?16:32;
        String scaleText=m.group(5);
        int scale=scaleText==null?1:
            scaleText.startsWith("0X")?
                Integer.parseInt(scaleText.substring(2),16):
                Integer.parseInt(scaleText);
        long displacement=0;
        if (displacementText!=null) {
            try {
                String digits=displacementText;
                int sign=1;
                if(digits.startsWith("-")){sign=-1;digits=digits.substring(1);}
                else if(digits.startsWith("+"))digits=digits.substring(1);
                long magnitude;
                if(digits.startsWith("$"))magnitude=Long.parseLong(digits.substring(1),16);
                else if(digits.startsWith("0X"))magnitude=Long.parseLong(digits.substring(2),16);
                else magnitude=Long.parseLong(digits);
                if(magnitude<0 || magnitude>(sign<0?
                        -MIN_SIGNED_DISPLACEMENT:MAX_UNSIGNED_DISPLACEMENT))
                    return null;
                displacement=sign<0?-magnitude:magnitude;
            } catch (NumberFormatException invalid) {return null;}
        }
        return new Expression(base,index,bits,scale,displacement);
    }
}
