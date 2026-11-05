package ghidrassist.hardware;

public final class HardwareRegisterOperandSelfTest {
    private static void check(boolean v,String message){
        if(!v)throw new AssertionError(message);
    }
    public static void main(String[] ignored){
        check("D0".equals(HardwareRegisterOperand.sourceOrDestination(
            "D0w","MOVE.W")),"Ghidra CPU32 D0w source register decoded");
        check("D1".equals(HardwareRegisterOperand.sourceOrDestination(
            "D1b","MOVE.B")),"Ghidra CPU32 D1b source decoded");
        check("D2".equals(HardwareRegisterOperand.sourceOrDestination(
            "D2l","MOVE.L")),"Ghidra CPU32 D2l full register decoded");
        check("A0".equals(HardwareRegisterOperand.sourceOrDestination(
            "A0","MOVEA.L")),"normal full address register preserved");
        check(HardwareRegisterOperand.sourceOrDestination(
            "D0w","MOVE.L")==null,"word subregister cannot become long value");
        check(HardwareRegisterOperand.sourceOrDestination(
            "D0l","MOVE.W")==null,"long suffix does not match byte count");
        check(HardwareRegisterOperand.sourceOrDestination(
            "D0w","MOVEC")==null,"unsized MOVEC cannot promote Dn word");
        check(HardwareRegisterOperand.sourceOrDestination(
            "D8w","MOVE.W")==null &&
            HardwareRegisterOperand.sourceOrDestination(
                "D0+(A0)","MOVE.W")==null,
            "only exact register operands are allowed");
        check(HardwareRegisterOperand.sourceOrDestination(
            "A7w","MOVE.W")==null,"A7 stack partial view not inferred");
        check(HardwareRegisterOperand.isImmediateToken("-0x1","moveq") &&
            HardwareRegisterOperand.isImmediateToken("0x7f","MOVEQ") &&
            HardwareRegisterOperand.isImmediateToken("#-0x1","MOVEQ"),
            "actual Ghidra signed MOVEQ operand is immediate without '#'");
        check(!HardwareRegisterOperand.isImmediateToken("-0x1","MOVE.W") &&
            !HardwareRegisterOperand.isImmediateToken("0x7f","MOVE.L") &&
            !HardwareRegisterOperand.isImmediateToken("-0x1","MOVEC"),
            "unsuffixed numeric non-MOVEQ operand is not an immediate");
        check(!HardwareRegisterOperand.isImmediateToken("D1","MOVEQ") &&
            !HardwareRegisterOperand.isImmediateToken("(A0)","MOVEQ") &&
            !HardwareRegisterOperand.isImmediateToken("-0x1(A0)","MOVEQ") &&
            !HardwareRegisterOperand.isImmediateToken(null,"MOVEQ"),
            "registers, memory and missing values cannot become MOVEQ constants");
        check(HardwareRegisterOperand.isImmediateToken("#0x40ca","MOVE.W"),
            "original explicit immediate marker remains supported");
        System.out.println("HardwareRegisterOperandSelfTest OK");
    }
}
