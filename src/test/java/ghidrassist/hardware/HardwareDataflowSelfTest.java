package ghidrassist.hardware;

import java.util.List;
import java.util.Set;
import java.util.Map;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

public final class HardwareDataflowSelfTest {
    private static void ok(boolean v,String why){if(!v)throw new AssertionError(why);}
    private static HardwareDataflow.Step st(long addr,HardwareDataflow.Kind k,String reg,
            long arg,long disp,Integer imm,int bits,Long... next){
        return new HardwareDataflow.Step(addr,k,reg,arg,disp,imm,bits,List.of(next),"synthetic");
    }
    public static void main(String[] args){
        long simcr=0xfffa00L, cs7=0xfffa68L;
        var straightforward=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"A0",simcr,0,null,0,2L),
            st(2,STORE_INDIRECT,"A0",0,0,0x40ca,16,4L),
            st(4,ADJUST_POINTER,"A0",0x68,0,null,0,6L),
            st(6,STORE_INDIRECT,"A0",0,0,0xff88,16,8L),
            st(8,VBR_FROM_REGISTER,"A0",0,0,null,0)
        ),Set.of(simcr,cs7),100);
        ok(straightforward.snapshots.size()==3,"two stores and VBR");
        ok(straightforward.snapshots.get(0).effectiveAddress==simcr,"A0 indirect SIMCR");
        ok(straightforward.snapshots.get(1).effectiveAddress==cs7,"ADDA-style A0 address");
        ok(straightforward.snapshots.get(1).knownPeripheralWords.get(cs7)==0xff88,"CSBAR7 state");
        ok(straightforward.snapshots.get(2).vbr==cs7,"VBR uses A0 value (not MCU proof)");
        ok(!straightforward.truncated,"should converge");

        // Two divergent branches both write different A0 addresses; the merge
        // must not invent either hardware register as a proven destination.
        var divergent=HardwareDataflow.analyze(0,List.of(
            st(0,OTHER,null,0,0,null,0,2L,4L),
            st(2,SET_POINTER,"A0",simcr,0,null,0,6L),
            st(4,SET_POINTER,"A0",cs7,0,null,0,6L),
            st(6,STORE_INDIRECT,"A0",0,0,0x40ca,16)
        ),Set.of(simcr,cs7),100);
        ok(divergent.snapshots.get(0).effectiveAddress==null,
            "CFG join must invalidate divergent A0 pointer");
        ok(divergent.reachedNodes==4,"all branch nodes reached");

        var same=HardwareDataflow.analyze(0,List.of(
            st(0,OTHER,null,0,0,null,0,2L,4L),
            st(2,SET_POINTER,"A0",simcr,0,null,0,6L),
            st(4,SET_POINTER,"A0",simcr,0,null,0,6L),
            st(6,STORE_INDIRECT,"A0",0,0,0x40ca,16)
        ),Set.of(simcr),100);
        ok(same.snapshots.get(0).effectiveAddress==simcr,"agreeing CFG predecessors");

        var barrier=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"A0",simcr,0,null,0,2L),
            st(2,CALL_BARRIER,null,0,0,null,0,4L),
            st(4,STORE_INDIRECT,"A0",0,0,0x40ca,16)
        ),Set.of(simcr),100);
        ok(barrier.snapshots.get(0).effectiveAddress==null,
            "without call summaries pointers cannot cross calls");

        var loop=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"A0",simcr,0,null,0,2L),
            st(2,OTHER,null,0,0,null,0,4L,6L),
            st(4,CLOBBER_POINTER,"A0",0,0,null,0,2L),
            st(6,STORE_INDIRECT,"A0",0,0,0,16)
        ),Set.of(simcr),100);
        ok(loop.snapshots.get(0).effectiveAddress==null,
            "loop with clobbered pointer must not retain stale constant");
        ok(!loop.truncated,"bounded loop converges");
        var trunc=HardwareDataflow.analyze(0,List.of(
            st(0,OTHER,null,0,0,null,0,2L),
            st(2,OTHER,null,0,0,null,0)
        ),Set.of(),1);
        ok(trunc.truncated,"iteration ceiling surfaced");
        System.out.println("HardwareDataflowSelfTest OK");
    }
}
