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
    private static final String NUMBER="(?:[-+]?(?:0X[0-9A-F]+|\\$[0-9A-F]+|[0-9]+))";
    private static final Pattern OUTSIDE=Pattern.compile(
        "^("+NUMBER+")?\\(([AD][0-7]),([AD][0-7])\\.(W|L)(?:\\*([1248]))?\\)$");
    private static final Pattern INSIDE=Pattern.compile(
        "^\\(("+NUMBER+"),([AD][0-7]),([AD][0-7])\\.(W|L)(?:\\*([1248]))?\\)$");

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
        if (operand == null || operand.isBlank()) return null;
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
        int scale=m.group(5)==null?1:Integer.parseInt(m.group(5));
        long displacement=0;
        if (displacementText!=null) {
            try {
                String digits=displacementText;
                int sign=1;
                if(digits.startsWith("-")){sign=-1;digits=digits.substring(1);}
                else if(digits.startsWith("+"))digits=digits.substring(1);
                if(digits.startsWith("$"))displacement=Long.parseLong(digits.substring(1),16)*sign;
                else if(digits.startsWith("0X"))displacement=Long.parseLong(digits.substring(2),16)*sign;
                else displacement=Long.parseLong(digits)*sign;
            } catch (NumberFormatException invalid) {return null;}
        }
        return new Expression(base,index,bits,scale,displacement);
    }
}
