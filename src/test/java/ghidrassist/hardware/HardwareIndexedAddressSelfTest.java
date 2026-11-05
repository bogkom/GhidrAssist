package ghidrassist.hardware;

/** Strict parser checks — no Ghidra classes or proprietary samples. */
public final class HardwareIndexedAddressSelfTest {
    private static void ok(boolean b,String reason){if(!b)throw new AssertionError(reason);}
    public static void main(String[] args) {
        var a=HardwareIndexedAddress.parse("16(A0,D1.W*2)");
        ok(a!=null && a.base().equals("A0") && a.index().equals("D1") &&
            a.displacement()==16 && a.indexBits()==16 && a.scale()==2,
            "outside displacement and scaled word");
        var b=HardwareIndexedAddress.parse("($20,A3,A2.L)");
        ok(b!=null && b.displacement()==32 && b.scale()==1 &&
            b.indexBits()==32 && b.index().equals("A2"),
            "inside displacement and long address index");
        // Exact rendering observed in a real Ghidra 12.1.4 PUBLIC
        // CPU32 headless run: Ghidra omits the dot before index width
        // and renders the extension-word scale as hex.
        var actual=HardwareIndexedAddress.parse("(0x1,A1,D1w*0x1)");
        ok(actual!=null && actual.base().equals("A1") &&
            actual.index().equals("D1") && actual.indexBits()==16 &&
            actual.scale()==1 && actual.displacement()==1,
            "real Ghidra CPU32 D1w*0x1 indexed operand");
        var realLong=HardwareIndexedAddress.parse("(0x20,A3,A2l*0x4)");
        ok(realLong!=null && realLong.indexBits()==32 &&
            realLong.scale()==4 && realLong.displacement()==32,
            "Ghidra CPU32 unsigned hex index scale and long index");
        ok(HardwareIndexedAddress.parse("(0x1,A1,D1w*0x3)")==null &&
            HardwareIndexedAddress.parse("(0x1,A1,D1w*0x0)")==null &&
            HardwareIndexedAddress.parse("(0x1,A1,D1w*0x10)")==null &&
            HardwareIndexedAddress.parse("(0x1,A1,D1q*0x1)")==null,
            "unmodeled Ghidra index width/scale remains unresolved");
        ok(HardwareIndexedAddress.parse("([A1],D1w*0x1)")==null &&
            HardwareIndexedAddress.parse("(0x1,PC,D1w*0x1)")==null,
            "actual Ghidra spelling does not allow unsafe memory/PC indirect");
        ok(HardwareIndexedAddress.parse("(A0,D0.W)").displacement()==0,
            "indexed address without displacement");
        ok(HardwareIndexedAddress.parse("-0x20(A0,D0.W)").displacement()==-32,
            "signed hexadecimal displacement");
        ok(HardwareIndexedAddress.parse("(PC,D0.W)")==null,
            "PC-relative not promoted to absolute address");
        ok(HardwareIndexedAddress.parse("([A0],D0.W)")==null,
            "memory-indirect not resolved");
        ok(HardwareIndexedAddress.parse("(A0,D0.B)")==null,
            "byte-sized index invalid");
        ok(HardwareIndexedAddress.parse("(A0,D0.W*3)")==null,
            "invalid scale rejected");
        ok(HardwareIndexedAddress.parse("4(A0,D0.W,D1.W)")==null,
            "complex alias unresolved");
        var highUnsigned=HardwareIndexedAddress.parse(
            "(0xffffffff,A1,D1w*0x1)");
        ok(highUnsigned!=null &&
            highUnsigned.displacement()==0xffffffffL,
            "full 32-bit unsigned CPU32 displacement stays representable");
        var lowSigned=HardwareIndexedAddress.parse(
            "(-0x80000000,A1,D1w*0x1)");
        ok(lowSigned!=null &&
            lowSigned.displacement()==-0x80000000L,
            "negative signed 32-bit boundary remains representable");
        ok(HardwareIndexedAddress.parse("(0x100000000,A1,D1w*0x1)")==null &&
            HardwareIndexedAddress.parse("(-0x80000001,A1,D1w*0x1)")==null &&
            HardwareIndexedAddress.parse("(4294967296,A1,D1w*0x1)")==null &&
            HardwareIndexedAddress.parse("(-2147483649,A1,D1w*0x1)")==null,
            "impossible CPU32 >32-bit extension must never wrap to MMIO");
        ok(HardwareIndexedAddress.parse(
                "(18446744073709551616,A1,D1w*0x1)")==null &&
            HardwareIndexedAddress.parse(
                " ".repeat(HardwareIndexedAddress.MAX_OPERAND_CHARS+1)+
                    "(0x1,A1,D1w*0x1)")==null,
            "oversized operand text and overflow are safely unresolved");
        ok(HardwareIndexedAddress.parse("(0x1,A1,D1w*0x1)")!=null,
            "original real Ghidra 12.1.4 indexed operand remains recognized");
        System.out.println("HardwareIndexedAddressSelfTest OK");
    }
}
