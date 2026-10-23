package ghidrassist.hardware;

import java.util.List;

public final class HardwareApplyPlanSelfTest {
    private static void check(boolean value,String message){
        if(!value)throw new AssertionError(message);
    }
    public static void main(String[] args){
        List<HardwareApplyPlan.Item> items=HardwareApplyPlan.mc68332Mm1Candidates(0);
        check(items.size()>=57,"expanded memory/register/VBR proposals");
        check(items.stream().anyMatch(x->x.name.equals("TPURAM_2K_CANDIDATE") &&
            x.address==0xfff000L && x.length==2048),"conditional TPURAM");
        check(items.stream().anyMatch(x->x.name.equals("TPURAM_CONTROL_MM1") &&
            x.address==0xfffb00L && x.length==0x40),"MC68332UM TPURAM control block");
        check(items.stream().anyMatch(x->x.name.equals("SIM_REGISTERS_MM1") &&
            x.address==0xfffa00L && x.length==128),"MC68332 Appendix D-1 SIM 128");
        check(items.stream().anyMatch(x->x.name.equals("QSM_MM1") &&
            x.address==0xfffc00L && x.length==512),"MC68332 Appendix D-1 QSM 512");
        check(items.stream().anyMatch(x->x.name.equals("TPU_MM1") &&
            x.address==0xfffe00L && x.length==512),"MC68332 Appendix D-1 TPU 512");
        check(items.stream().noneMatch(x->x.name.equals("QSM_QUEUE_MM1") ||
            x.name.equals("TPU_PARAM_RAM_MM1") ||
            x.name.equals("QSM_CONTROL_MM1") ||
            x.name.equals("TPU_CONTROL_MM1")),
            "QSM and TPU must be complete, non-overlapping module blocks");
        check(items.stream().anyMatch(x->x.name.equals("TPURAM_2K_CANDIDATE") &&
            x.address==0xfff000L && x.length==2048),"relocated standby TPURAM candidate");
        check(items.stream().anyMatch(x->x.name.equals("SIMCR") &&
            x.address==0xfffa00L && x.length==2),"SIMCR label candidate");
        check(items.stream().anyMatch(x->x.name.equals("RSR") &&
            x.address==0xfffa07L && x.length==1 &&
            x.details.contains("READ_ONLY")),"8-bit RSR with access evidence");
        check(items.stream().filter(x->x.kind==HardwareApplyPlan.Kind.MEMORY &&
            (x.name.equals("SIM_REGISTERS_MM1") ||
             x.name.equals("TPURAM_CONTROL_MM1") ||
             x.name.equals("QSM_MM1") || x.name.equals("TPU_MM1")))
            .allMatch(x->x.details.contains("PDF page 215")),
            "all module proposals carry sourced D-1 metadata");
        check(items.stream().anyMatch(x->x.name.equals("CS7_DEVICE_CANDIDATE") &&
            x.address==0xff8800L && x.length==2048),"CS7 remains candidate");
        check(items.stream().noneMatch(x->x.name.startsWith("CS9") ||
            x.name.startsWith("CS0")||x.name.startsWith("CS1")),
            "overlapping bus windows never auto-proposed as conventional blocks");
        var csWindows=HardwareApplyPlan.chipSelectWindowCandidates(List.of(
            new HardwareApplyPlan.CsbarEvidence("CSBAR0",0xF803,"init_A"),
            new HardwareApplyPlan.CsbarEvidence("CSBAR1",0xF803,"init_A"),
            new HardwareApplyPlan.CsbarEvidence("CSBAR7",0xFF88,"init_A"),
            new HardwareApplyPlan.CsbarEvidence("CSOR0",0x3870,"init_A")));
        check(csWindows.size()==2,"duplicate byte lanes form one CS window");
        check(csWindows.stream().anyMatch(x->x.address==0xF80000L &&
            x.length==65536),"CSBAR0/1 complementary range");
        check(csWindows.stream().anyMatch(x->x.address==0xFF8800L &&
            x.length==2048),"CSBAR7 discovered range");
        var extended=HardwareApplyPlan.mc68332Mm1Candidates(0,List.of(
            new HardwareApplyPlan.CsbarEvidence("CSBAR0",0xF803,"init_A")));
        check(extended.get(extended.size()-1).kind==
            HardwareApplyPlan.Kind.VBR_STRUCTURE,"VBR remains final after CS windows");
        var vbr=items.get(items.size()-1);
        check(vbr.kind==HardwareApplyPlan.Kind.VBR_STRUCTURE && vbr.length==1024,
            "256 entries of four bytes");
        check(HardwareApplyPlan.intersects(items.get(0),
            items.stream().filter(x->x.name.equals("SIMCR"))
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
