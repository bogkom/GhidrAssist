package ghidrassist.hardware;

import java.util.Locale;
import java.util.Collection;
import java.util.LinkedHashSet;
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
    /** Include every independently written A/D register except a register
     * whose new value is already modeled by the CFG instruction kind. */
    public static Set<String> unmodeledOutputs(HardwareDataflow.Kind kind,
            String modeledRegister,Collection<String> outputs) {
        if(kind==null || outputs==null)throw new IllegalArgumentException("Missing effect");
        Set<String> unknown=new LinkedHashSet<>();
        for(String register:outputs) {
            if(register==null || !register.matches("[AD][0-7]"))
                throw new IllegalArgumentException("Invalid P-code A/D output");
            unknown.add(register);
        }
        if(kind==HardwareDataflow.Kind.SET_POINTER ||
                kind==HardwareDataflow.Kind.COPY_POINTER ||
                kind==HardwareDataflow.Kind.ADJUST_POINTER ||
                kind==HardwareDataflow.Kind.CLOBBER_POINTER)
            unknown.remove(modeledRegister);
        return Set.copyOf(unknown);
    }

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
