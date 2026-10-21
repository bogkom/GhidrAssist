package ghidrassist.hardware;

import java.util.List;

public final class HardwareApplyPlanSelfTest {
    private static void check(boolean value,String message){
        if(!value)throw new AssertionError(message);
    }
    public static void main(String[] args){
        List<HardwareApplyPlan.Item> items=HardwareApplyPlan.mc68332Mm1Candidates(0);
        check(items.size()>=35,"memory/register/VBR proposals");
        check(items.stream().anyMatch(x->x.name.equals("TPURAM_2K_CANDIDATE") &&
            x.address==0xfff000L && x.length==2048),"conditional TPURAM");
        check(items.stream().anyMatch(x->x.name.equals("TPURAM_CONTROL_MM1") &&
            x.address==0xfffb00L && x.length==0x40),"MC68332UM TPURAM control block");
        check(items.stream().anyMatch(x->x.name.equals("QSM_CONTROL_MM1") &&
            x.address==0xfffc00L && x.length==0x20),"MC68332UM QSM register range");
        check(items.stream().anyMatch(x->x.name.equals("QSM_QUEUE_MM1") &&
            x.address==0xfffd00L && x.length==0x50),"MC68332UM QSM queue RAM");
        check(items.stream().anyMatch(x->x.name.equals("TPU_CONTROL_MM1") &&
            x.address==0xfffe00L && x.length==0x28),"MC68332UM TPU registers");
        check(items.stream().anyMatch(x->x.name.equals("TPU_PARAM_RAM_MM1") &&
            x.address==0xffff00L && x.length==0x100),"MC68332UM TPU parameter RAM");
        check(items.stream().noneMatch(x->x.kind==HardwareApplyPlan.Kind.MEMORY &&
            x.address==0xfffc20L),"unused QSM gap must remain unmapped");
        check(items.stream().noneMatch(x->x.kind==HardwareApplyPlan.Kind.MEMORY &&
            x.address==0xfffe28L),"unused TPU gap must remain unmapped");

        check(items.stream().anyMatch(x->x.name.equals("HW_MC68332_SIMCR_MM1") &&
            x.address==0xfffa00L && x.length==2),"SIMCR label candidate");
        check(items.stream().anyMatch(x->x.name.equals("CS7_DEVICE_CANDIDATE") &&
            x.address==0xff8800L && x.length==2048),"CS7 remains candidate");
        check(items.stream().noneMatch(x->x.name.startsWith("CS9") ||
            x.name.startsWith("CS0")||x.name.startsWith("CS1")),
            "overlapping bus windows never auto-proposed as conventional blocks");
        var vbr=items.get(items.size()-1);
        check(vbr.kind==HardwareApplyPlan.Kind.VBR_STRUCTURE && vbr.length==1024,
            "256 entries of four bytes");
        check(HardwareApplyPlan.intersects(items.get(0),
            items.stream().filter(x->x.name.equals("HW_MC68332_SIMCR_MM1"))
                .findFirst().orElseThrow()),"MMIO block and register intentionally overlap");
        boolean failed=false;
        try{HardwareApplyPlan.mc68332Mm1Candidates(3);}
        catch(IllegalArgumentException expected){failed=true;}
        check(failed,"VBR must be 4-byte aligned");
        failed=false;
        try{HardwareApplyPlan.mc68332Mm1Candidates(0xfffffcL);}
        catch(IllegalArgumentException expected){failed=true;}
        check(failed,"entire 256-entry VBR table must fit in 24-bit space");
        System.out.println("HardwareApplyPlanSelfTest OK");
    }
}
