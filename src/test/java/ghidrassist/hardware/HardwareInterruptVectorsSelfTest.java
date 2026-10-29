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
        input.add(new HardwareInterruptVectors.Observation(26,0x3000L,true,"isr_timer",true));
        input.add(new HardwareInterruptVectors.Observation(2,0x1001L,true,"odd",false));
        input.add(new HardwareInterruptVectors.Observation(24,0x2000L,true,"spurious",true));
        input.add(new HardwareInterruptVectors.Observation(25,0L,false,null,false));
        input.add(new HardwareInterruptVectors.Observation(27,0xffffffffL,false,null,false));
        input.add(new HardwareInterruptVectors.Observation(28,null,false,null,false));
        input.add(new HardwareInterruptVectors.Observation(32,0xabc000L,false,null,false));
        input.add(new HardwareInterruptVectors.Observation(35,0x4000L,true,null,false));
        input.add(new HardwareInterruptVectors.Observation(36,0x5000L,true,"A|B\nname",true));
        input.add(new HardwareInterruptVectors.Observation(37,0x5002L,true,
            "isr_timer @ 0x5000",false));
        var s=HardwareInterruptVectors.inspect(0,input,16);
        ok(s.sampledSlots()==10 && s.readable()==9 && s.plausibleMapped()==5 &&
            s.recognizedFunctions()==3 && s.interiorFunctionPointers()==1 &&
            s.unmapped()==1 &&
            s.odd()==1 && s.absent()==2 && s.unreadable()==1,
            "all input statuses counted independently");
        ok(s.displayed().size()==7 &&
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
        ok(!md.contains("active ISR verified") &&
            md.contains("pointers inside recognized function bodies") &&
            md.contains("INTERIOR_FUNCTION_POINTER_CANDIDATE"),
            "interior function pointers are not handler entries");
        var small=HardwareInterruptVectors.inspect(0,input,2);
        ok(small.truncated() && small.displayed().size()==2 &&
            small.plausibleMapped()==5,"display truncation not a scan truncation");
        var empty=HardwareInterruptVectors.inspect(0,List.of(),2);
        ok(empty.displayed().isEmpty() && empty.sampledSlots()==0,
            "empty input must not claim active ISR");
        boolean duplicate=false;
        try {
            HardwareInterruptVectors.inspect(0,List.of(
                new HardwareInterruptVectors.Observation(2,0x1000L,true,null,false),
                new HardwareInterruptVectors.Observation(2,0x2000L,true,null,false)),8);
        }catch(IllegalArgumentException expected){duplicate=true;}
        ok(duplicate,"duplicate vector cannot masquerade as two observations");
        boolean bad=false;
        try {
            HardwareInterruptVectors.inspect(0,List.of(
                new HardwareInterruptVectors.Observation(1,0x1000L,true,null,false)),8);
        }catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"SP and RESET slots excluded from exception list");
        bad=false;
        try{HardwareInterruptVectors.inspect(1,List.of(),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"unaligned candidate VBR rejected");
        bad=false;
        try{HardwareInterruptVectors.inspect(0,List.of(
                new HardwareInterruptVectors.Observation(254,0x1_0000_0000L,true,null,false)),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"reject pointer outside unsigned 32-bit address range");
        bad=false;
        try{HardwareInterruptVectors.inspect(0xfffffffCL,List.of(
            new HardwareInterruptVectors.Observation(2,0x1000L,true,null,false)),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"vector slot must not wrap 32-bit candidate table address");
        bad=false;
        try{HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(25,0x1000L,true,
                "interior",true)),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(!bad,"explicit positive entry evidence is accepted with a named function");
        bad=false;
        try{HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(25,0x1001L,true,
                "incorrect",true)),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"odd vector must not claim an exact handler entry");
        bad=false;
        try{HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(25,0x1000L,true,
                null,true)),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"handler-entry proof requires a recognized named function");
        boolean immutable=false;
        try{s.displayed().clear();}catch(UnsupportedOperationException expected){
            immutable=true;
        }
        ok(immutable,"static result immutable");
        System.out.println("HardwareInterruptVectorsSelfTest OK");
    }
}
