package ghidrassist.hardware;

import static ghidrassist.hardware.HardwarePcodeConstantMath.Operation.*;

/** Deterministic Java21 regression for CPU32 P-code width and alias safety. */
public final class HardwarePcodeConstantMathSelfTest {
    private HardwarePcodeConstantMathSelfTest() {}
    private static int checks;
    private static void eq(Long actual,Long expected,String why) {
        checks++;
        if(!java.util.Objects.equals(actual,expected))
            throw new AssertionError(why+": actual="+actual+", expected="+expected);
    }
    public static void main(String[] args) {
        eq(HardwarePcodeConstantMath.evaluate(COPY,0x1ffL,1,null,0,1),
            0xffL,"COPY masks 8-bit output");
        eq(HardwarePcodeConstantMath.evaluate(COPY,0x1234L,2,null,0,4),
            null,"COPY width mismatch is unknown");
        eq(HardwarePcodeConstantMath.evaluate(ZERO_EXTEND,0x80L,1,null,0,4),
            0x80L,"zero extension must not sign extend");
        eq(HardwarePcodeConstantMath.evaluate(SIGN_EXTEND,0x80L,1,null,0,4),
            0xffffff80L,"sign extend 8 to 32");
        eq(HardwarePcodeConstantMath.evaluate(SIGN_EXTEND,0x8000L,2,null,0,4),
            0xffff8000L,"sign extend 16 to 32");
        eq(HardwarePcodeConstantMath.evaluate(SIGN_EXTEND,0x7fffL,2,null,0,4),
            0x7fffL,"positive 16-bit sign extension");
        eq(HardwarePcodeConstantMath.evaluate(SIGN_EXTEND,0xffffL,2,null,0,8),
            -1L,"sign extend 16 to 64");
        eq(HardwarePcodeConstantMath.evaluate(ZERO_EXTEND,0xffffL,2,null,0,4),
            0xffffL,"zero extend 16 to 32");
        eq(HardwarePcodeConstantMath.evaluate(SIGN_EXTEND,0xffffL,2,null,0,2),
            null,"nonwidening sign extension not inferred");
        eq(HardwarePcodeConstantMath.evaluate(ADD,0xffffL,2,2L,2,2),
            1L,"16-bit modular carry");
        eq(HardwarePcodeConstantMath.evaluate(SUBTRACT,0L,2,1L,2,2),
            0xffffL,"16-bit modular borrow");
        eq(HardwarePcodeConstantMath.evaluate(ADD,0xffffffffL,4,1L,4,4),
            0L,"32-bit arithmetic wrap");
        eq(HardwarePcodeConstantMath.evaluate(SUBTRACT,0L,4,1L,4,4),
            0xffffffffL,"32-bit subtraction sign");
        eq(HardwarePcodeConstantMath.evaluate(ADD,0xffffL,2,1L,4,4),
            null,"arithmetic operand-width mismatch is unknown");
        eq(HardwarePcodeConstantMath.evaluate(ADD,null,4,1L,4,4),
            null,"unknown source stays unknown");
        eq(HardwarePcodeConstantMath.evaluate(ZERO_EXTEND,1L,9,null,0,4),
            null,"oversized source refused");
        eq(HardwarePcodeConstantMath.evaluate(ADD,1L,4,1L,4,9),
            null,"oversized output refused");
        eq(HardwarePcodeConstantMath.evaluate(null,1L,4,null,0,4),
            null,"unsupported operation refused");
        // The complete P-code calculation precedes the 24-bit external bus.
        Long negative=HardwarePcodeConstantMath.evaluate(
            SIGN_EXTEND,0xffffL,2,null,0,4);
        eq(HardwarePcodeConstantMath.externalAddress(negative,4),
            0xffffffL,"negative word sign-extends before 24-bit bus mask");
        eq(HardwarePcodeConstantMath.externalAddress(0x1fffa00L,4),
            0xfffa00L,"external CPU32 address wraps modulo 24");
        eq(HardwarePcodeConstantMath.externalAddress(0xfffa00L,2),
            null,"truncated 16-bit pointer is not proven");
        eq(HardwarePcodeConstantMath.externalAddress(null,4),
            null,"unknown STORE pointer remains unknown");
        eq(HardwarePcodeConstantMath.externalAddress(0xfffa00L,8),
            null,"non-CPU32 STORE pointer stays unresolved");
        System.out.println("HardwarePcodeConstantMathSelfTest PASS checks="+checks);
    }
}
