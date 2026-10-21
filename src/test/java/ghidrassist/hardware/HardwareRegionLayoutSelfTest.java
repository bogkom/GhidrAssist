package ghidrassist.hardware;

import java.util.List;

/** Synthetic snapshots of the existing blocks seen in user's Memory Map. */
public final class HardwareRegionLayoutSelfTest {
    private static void ok(boolean value,String name){
        if(!value)throw new AssertionError(name);
    }
    private static HardwareRegionLayout.Range r(long first,long last){
        return new HardwareRegionLayout.Range(first,last);
    }
    public static void main(String[] args){
        var qsm=HardwareRegionLayout.missing(0xfffc00L,0xfffdffL,List.of(
            r(0xfffc00L,0xfffc01L),r(0xfffd00L,0xfffd4fL)));
        ok(qsm.size()==2,"QSM has two gaps across old short register/queue blocks");
        ok(qsm.get(0).first==0xfffc02L && qsm.get(0).last==0xfffcffL,
            "QSM gap after 2-byte prior controller block");
        ok(qsm.get(1).first==0xfffd50L && qsm.get(1).last==0xfffdffL,
            "QSM final gap");
        var qsmNew=HardwareRegionLayout.missing(0xfffc00L,0xfffdffL,List.of(
            r(0xfffc00L,0xfffc1fL),r(0xfffd00L,0xfffd4fL)));
        ok(qsmNew.get(0).first==0xfffc20L,"after interim release module blocks");
        var tpu=HardwareRegionLayout.missing(0xfffe00L,0xffffffL,List.of(
            r(0xfffe00L,0xfffe27L),r(0xffff00L,0xffffffL)));
        ok(tpu.size()==1 && tpu.get(0).first==0xfffe28L &&
            tpu.get(0).last==0xfffeffL,"TPU bridge gap");
        ok(HardwareRegionLayout.missing(0xfffa00L,0xfffa7fL,List.of(
            r(0xfffa00L,0xfffa7fL))).isEmpty(),"already mapped SIM");
        ok(HardwareRegionLayout.missing(0xfffb00L,0xfffb3fL,List.of())
            .get(0).length()==64,"new TPURAM module");
        boolean fail=false;
        try{HardwareRegionLayout.missing(0xfffc00L,0xfffdffL,List.of(
            r(0xfffc00L,0xfffc20L),r(0xfffc20L,0xfffc40L)));}
        catch(IllegalArgumentException expected){fail=true;}
        ok(fail,"overlapping fragments rejected");
        System.out.println("HardwareRegionLayoutSelfTest OK");
    }
}
