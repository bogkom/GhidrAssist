package ghidrassist.hardware;

import java.util.List;
import java.util.Set;

public final class HardwareAutoUpdateRegistersSelfTest {
    private static void ok(boolean yes,String why){if(!yes)throw new AssertionError(why);}
    public static void main(String[] args) {
        ok(HardwareAutoUpdateRegisters.changedByOperand("(A0)+")
            .equals(Set.of("A0")),"post-increment invalidates A0");
        ok(HardwareAutoUpdateRegisters.changedByOperand("-(a7)")
            .equals(Set.of("A7")),"pre-decrement invalidates A7");
        ok(HardwareAutoUpdateRegisters.changedByOperand("( A3 ) +")
            .equals(Set.of("A3")),"operand whitespace ignored");
        ok(HardwareAutoUpdateRegisters.changedByOperand("(A0)")
            .isEmpty(),"plain indirect does not auto-change A0");
        ok(HardwareAutoUpdateRegisters.changedByOperand("4(A0,D1.W)")
            .isEmpty(),"indexed displacement is not post-increment");
        ok(HardwareAutoUpdateRegisters.changedByOperand("(PC)+")
            .isEmpty(),"invalid PC auto increment not treated as A register");
        ok(HardwareAutoUpdateRegisters.changedByOperand("-(D0)")
            .isEmpty(),"data register cannot predecrement address");
        System.out.println("HardwareAutoUpdateRegistersSelfTest OK");
    }
}
