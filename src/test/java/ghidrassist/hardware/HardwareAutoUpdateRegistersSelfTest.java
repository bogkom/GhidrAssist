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
        var clobbers=HardwareAutoUpdateRegisters.unmodeledOutputs(
            HardwareDataflow.Kind.OTHER,null,Set.of("A0","D1"));
        ok(clobbers.equals(Set.of("A0","D1")),
            "unmodeled EXG/D-register P-code outputs invalidate all affected registers");
        var modeled=HardwareAutoUpdateRegisters.unmodeledOutputs(
            HardwareDataflow.Kind.SET_POINTER,"A0",Set.of("A0","D1"));
        ok(modeled.equals(Set.of("D1")),
            "only the proven SET_POINTER value survives other register side effects");
        ok(HardwareAutoUpdateRegisters.unmodeledOutputs(
            HardwareDataflow.Kind.STORE_INDIRECT,"A0",Set.of("A0"))
                .equals(Set.of("A0")),
            "post-increment STORE cannot preserve stale base register");
        boolean rejected=false;
        try{HardwareAutoUpdateRegisters.unmodeledOutputs(
            HardwareDataflow.Kind.OTHER,null,Set.of("UNKNOWN"));}
        catch(IllegalArgumentException expected){rejected=true;}
        ok(rejected,"unexpected P-code register IDs are not silently accepted");
        System.out.println("HardwareAutoUpdateRegistersSelfTest OK");
    }
}
