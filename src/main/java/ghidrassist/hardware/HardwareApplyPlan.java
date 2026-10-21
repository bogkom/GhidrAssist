package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Review-only proposals. Planning does not open a transaction or alter Ghidra.
 * A concrete MC68332 hypothesis and MM=1 must be selected explicitly.
 *
 * Do not map the overlapping CS0/CS1 byte lanes or broad CS9 window as one
 * external block: such choices need a real electrical/boot-space model.
 */
public final class HardwareApplyPlan {
    private HardwareApplyPlan() {}
    public enum Kind { MEMORY, REGISTER, VBR_STRUCTURE }
    public static final class Item {
        public final Kind kind;
        public final String name;
        public final long address;
        public final int length;
        public final String details;
        Item(Kind kind,String name,long address,int length,String details){
            this.kind=kind;this.name=name;this.address=address;
            this.length=length;this.details=details;
        }
        public long last(){return address+length-1;}
        public String location(){
            return ChipSelectModel.hex(address,6)+".."+ChipSelectModel.hex(last(),6);
        }
    }
    private static void add(List<Item> out,Kind kind,String name,long at,int len,String note){
        if(len<1||at<0||at+len-1>0xffffffL)
            throw new IllegalArgumentException("Invalid 24-bit memory range");
        out.add(new Item(kind,name,at,len,note));
    }
    public static List<Item> mc68332Mm1Candidates(long vbrAddress){
        if(vbrAddress<0 || vbrAddress>0xfffffc || (vbrAddress&3)!=0)
            throw new IllegalArgumentException("VBR must be 4-byte aligned and in 24-bit space");
        List<Item> items=new ArrayList<>();
        add(items,Kind.MEMORY,"SIM_REGISTERS_MM1",0xfffa00,0x80,
            "128-byte uninitialized peripheral region; not proof of MC68332");
        add(items,Kind.MEMORY,"TPURAM_CONTROL_MM1",0xfffb00,8,
            "TRAMMCR/TRAMBAR control words; not relocated TPU RAM");
        add(items,Kind.MEMORY,"QSM_CONTROL_MM1",0xfffc00,2,
            "QSMCR word only; avoid guessing undefined offsets");
        add(items,Kind.MEMORY,"TPU_CONTROL_MM1",0xfffe00,2,
            "TPUMCR word only; avoid guessing undefined offsets");
        add(items,Kind.MEMORY,"TPURAM_2K_CANDIDATE",0xfff000,0x800,
            "2KiB candidate relocated TPU RAM at TRAMBAR=0xFFF0");
        add(items,Kind.MEMORY,"CS7_DEVICE_CANDIDATE",0xff8800,0x800,
            "Only a candidate external chip select, device type UNKNOWN");
        add(items,Kind.MEMORY,"CS8_DEVICE_CANDIDATE",0xff8000,0x800,
            "Only a candidate external chip select, device type UNKNOWN");
        for(HardwareProfiles.Register register:HardwareProfiles.mc68332().registers){
            long at=HardwareProfiles.INTERNAL_BASE_MM1+register.offset;
            add(items,Kind.REGISTER,"HW_MC68332_"+register.name+"_MM1",at,
                register.widthBits/8,
                "Source-backed candidate: "+register.module+
                "; explicitly selected MCU profile; no auto-rename of other symbols");
        }
        add(items,Kind.VBR_STRUCTURE,"CPU32_VBR_256_VECTORS",vbrAddress,256*4,
            "256 x 32-bit vector entries at USER-SUPPLIED VBR base; "+
            "apply only to entirely undefined data; no code clearing");
        return Collections.unmodifiableList(items);
    }
    public static boolean intersects(Item a,Item b){
        return a.address<=b.last()&&b.address<=a.last();
    }
}
