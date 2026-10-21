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
        System.out.println("HardwareIndexedAddressSelfTest OK");
    }
}
