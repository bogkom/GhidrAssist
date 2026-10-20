package ghidrassist.hardware;

import java.util.List;

/**
 * Dependency-free regression fixtures from previously disclosed ECU411 Ghidra
 * output; no private firmware bytes in public GitHub.
 */
public final class ChipSelectModelSelfTest {
    private static void ok(boolean condition,String message){
        if(!condition)throw new AssertionError(message);
    }
    public static void main(String[] args) {
        ChipSelectModel.Decoder d=new ChipSelectModel.Decoder("MC68332","fixture (conditional)");
        ChipSelectModel.Window csboot=d.window(-1,0x0006,0x6830,0x2f7f);
        ChipSelectModel.Window cs0=d.window(0,0xf803,0x3870,0x2f7f);
        ChipSelectModel.Window cs1=d.window(1,0xf803,0x5870,0x2f7f);
        ChipSelectModel.Window cs3=d.window(3,0x0006,0x7070,0x2f7f);
        ChipSelectModel.Window cs4=d.window(4,0x03f8,0x7000,0x2f7f);
        ChipSelectModel.Window cs7=d.window(7,0xff88,0x7bf0,0x00aa);
        ChipSelectModel.Window cs9=d.window(9,0xf007,0x6bf0,0x00aa);
        ok(csboot.first==0 && csboot.last==0x7ffff,"512KiB boot");
        ok(cs0.first==0xf80000 && cs0.last==0xf8ffff,"64KiB CS0");
        ok(cs7.first==0xff8800 && cs7.last==0xff8fff,"2KiB CS7");
        ok(cs9.first==0xf00000 && cs9.last==0xffffff,"1MiB CS9");
        ok(cs7.eligibleForAssertion(),"CS7 candidate");
        ok(cs0.byteField==1 && cs1.byteField==2,"two 16-bit BYTE halves");
        ok(ChipSelectModel.overlap(cs0,cs1)==ChipSelectModel.Overlap.COMPLEMENTARY_BYTE_LANES,
            "CS0/1 byte lane split");
        ok(ChipSelectModel.overlap(csboot,cs3)==ChipSelectModel.Overlap.DIFFERENT_READ_WRITE,
            "boot and CS3 have separate R/W conditions");
        ok(ChipSelectModel.overlap(cs4,csboot)==ChipSelectModel.Overlap.DIFFERENT_SPACE,
            "CS4 is CPU space, boot is normal user/supervisor space");
        ok(cs7.hypotheticalAccess(0xff8800,false,true,false)==ChipSelectModel.Match.CONDITIONAL_MATCH,
            "conditional read from candidate external CAN base");
        ok(cs7.hypotheticalAccess(0xff8800,false,true,true)==ChipSelectModel.Match.ADDRESS_ONLY,
            "CPU-space access must not assert CS7");
        ok(!cs7.includes(0xff9000),"window boundary");
        ok(d.window(10,0x0000,0x0000,0x00aa).eligibleForAssertion()==false,
            "BYTE=0 and reserved RW excludes assertion");
        ok(ChipSelectModel.overlap(cs7,d.window(6,0xff78,0x7d30,0x00aa))==
            ChipSelectModel.Overlap.NONE,"non-overlapping CS");
        boolean throwsUnknown=false;
        try { new ChipSelectModel.Decoder("CPU32","unsafe"); }
        catch(IllegalArgumentException expected){throwsUnknown=true;}
        ok(throwsUnknown,"generic CPU32 must not inherit MC68332 module map");
        List<String> messages=ChipSelectModel.overlaps(List.of(cs0,cs1,csboot,cs3,cs4,cs7,cs9));
        ok(messages.stream().anyMatch(x->x.contains("COMPLEMENTARY_BYTE_LANES")),
            "overlap explanations");
        System.out.println("ChipSelectModelSelfTest OK");
    }
}
