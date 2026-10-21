package ghidrassist.hardware;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Motorola 68k auto-update addressing changes the base A-register even when
 * the instruction destination is a different register. A stale base constant
 * MUST NOT flow into subsequent hardware stores.
 */
public final class HardwareAutoUpdateRegisters {
    private HardwareAutoUpdateRegisters() {}
    private static final Pattern POST=Pattern.compile("^\\(A([0-7])\\)\\+$");
    private static final Pattern PRE=Pattern.compile("^\\-\\(A([0-7])\\)$");
    public static Set<String> changedByOperand(String operand) {
        if(operand==null)return Set.of();
        String compact=operand.replaceAll("\\s+","").toUpperCase(Locale.ROOT);
        Matcher post=POST.matcher(compact);
        if(post.matches())return Set.of("A"+post.group(1));
        Matcher pre=PRE.matcher(compact);
        if(pre.matches())return Set.of("A"+pre.group(1));
        return Set.of();
    }
}
