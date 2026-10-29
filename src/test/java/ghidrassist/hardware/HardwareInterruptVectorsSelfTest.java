package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;

public final class HardwareInterruptVectorsSelfTest {
    private HardwareInterruptVectorsSelfTest() {}
    private static void ok(boolean value,String message){
        if(!value)throw new AssertionError(message);
    }
    public static void main(String[] args) {
        var input=new ArrayList<HardwareInterruptVectors.Observation>();
        input.add(new HardwareInterruptVectors.Observation(26,0x3000L,true,"isr_timer"));
        input.add(new HardwareInterruptVectors.Observation(2,0x1001L,true,"odd"));
        input.add(new HardwareInterruptVectors.Observation(24,0x2000L,true,"spurious"));
        input.add(new HardwareInterruptVectors.Observation(25,0L,false,null));
        input.add(new HardwareInterruptVectors.Observation(27,0xffffffffL,false,null));
        input.add(new HardwareInterruptVectors.Observation(28,null,false,null));
        input.add(new HardwareInterruptVectors.Observation(32,0xabc000L,false,null));
        input.add(new HardwareInterruptVectors.Observation(35,0x4000L,true,null));
        input.add(new HardwareInterruptVectors.Observation(36,0x5000L,true,"A|B\nname"));
        var s=HardwareInterruptVectors.inspect(0,input,16);
        ok(s.sampledSlots()==9 && s.readable()==8 && s.plausibleMapped()==4 &&
            s.recognizedFunctions()==3 && s.unmapped()==1 &&
            s.odd()==1 && s.absent()==2 && s.unreadable()==1,
            "all input statuses counted independently");
        ok(s.displayed().size()==6 &&
            s.displayed().get(0).vectorNumber()==2 &&
            s.displayed().get(0).classification()==
                HardwareInterruptVectors.Classification.ODD_POINTER,
            "number-sorted vector rows and invalid pointers");
        ok(s.displayed().get(1).label().contains("Spurious") &&
            s.displayed().get(2).label().contains("Autovector level 2"),
            "autovector labels must remain generic CPU family labels");
        ok(s.displayed().get(3).classification()==
            HardwareInterruptVectors.Classification.UNMAPPED_TARGET,
            "unmapped is not a verified handler");
        String md=s.markdown();
        ok(md.contains("runtime VBR UNKNOWN") &&
            md.contains("not proof of") &&
            md.contains("0x00000068") &&
            md.contains("A\\|B name"),
            "table provenance, vector slot, escaping and uncertainty");
        ok(!md.contains("active ISR verified"),"no activity claims");
        var small=HardwareInterruptVectors.inspect(0,input,2);
        ok(small.truncated() && small.displayed().size()==2 &&
            small.plausibleMapped()==4,"display truncation not a scan truncation");
        var empty=HardwareInterruptVectors.inspect(0,List.of(),2);
        ok(empty.displayed().isEmpty() && empty.sampledSlots()==0,
            "empty input must not claim active ISR");
        boolean duplicate=false;
        try {
            HardwareInterruptVectors.inspect(0,List.of(
                new HardwareInterruptVectors.Observation(2,0x1000L,true,null),
                new HardwareInterruptVectors.Observation(2,0x2000L,true,null)),8);
        }catch(IllegalArgumentException expected){duplicate=true;}
        ok(duplicate,"duplicate vector cannot masquerade as two observations");
        boolean bad=false;
        try {
            HardwareInterruptVectors.inspect(0,List.of(
                new HardwareInterruptVectors.Observation(1,0x1000L,true,null)),8);
        }catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"SP and RESET slots excluded from exception list");
        bad=false;
        try{HardwareInterruptVectors.inspect(1,List.of(),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"unaligned candidate VBR rejected");
        bad=false;
        try{HardwareInterruptVectors.inspect(0,List.of(
                new HardwareInterruptVectors.Observation(254,0x1_0000_0000L,true,null)),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"reject pointer outside unsigned 32-bit address range");
        boolean immutable=false;
        try{s.displayed().clear();}catch(UnsupportedOperationException expected){
            immutable=true;
        }
        ok(immutable,"static result immutable");
        System.out.println("HardwareInterruptVectorsSelfTest OK");
    }
}
