package ghidrassist.hardware;

public final class HardwareBitMathSelfTest {
    private static void ok(boolean yes,String msg){if(!yes)throw new AssertionError(msg);}
    public static void main(String[] args){
        String a=HardwareBitMath.annotate(
            "ram:00009c98 move.w #0x4848,(0x00fffa00).l\n"+
            "ram:00009dd8 move.l #-0x7fead7ea,(0x00fffc18).l");
        ok(a.contains("MM bit 6=1"),"0x4848 must retain bit six");
        ok(a.contains("(0x4848 & 0x0040)=0x0040"),"verified binary AND");
        ok(a.contains("0x80152816"),"signed long two's complement");
        String b=HardwareBitMath.annotate("_DAT_00fffa00 = 0x4848;");
        ok(b.contains("MM bit 6=1"),"Ghidra decompiler constant");
        ok(HardwareBitMath.annotate(
           "move.w #0x4808,(0x00fffa00).l").contains("MM bit 6=0"),"clear state");
        ok(HardwareBitMath.annotate("unrelated text").equals("unrelated text"),
           "do not fabricate register evidence");
        System.out.println("HardwareBitMathSelfTest OK");
    }
}
