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
        var copied=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"D0",simcr,0,null,0,2L),
            new HardwareDataflow.Step(2,COPY_POINTER,"A1","D0",0,0,null,0,
                List.of(4L),"MOVE.L D0,A1"),
            st(4,SET_POINTER,"D2",0x40ca,0,null,0,6L),
            new HardwareDataflow.Step(6,STORE_INDIRECT,"A1","D2",0,0,null,16,
                List.of(),"MOVE.W D2,(A1)")
        ),Set.of(simcr),100);
        ok(copied.snapshots.get(0).effectiveAddress==simcr,
            "D-register to A-register pointer copy");
        ok(copied.snapshots.get(0).writtenWord==0x40ca,
            "register-sourced MOVE.W constant propagation");

        var indexed=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"A0",0xfffa00,0,null,0,2L),
            st(2,SET_POINTER,"D1",0xffff,0,null,0,4L),
            new HardwareDataflow.Step(4,"A0",null,"D1",16,2,
                2,0x1234,16,List.of(6L),"MOVE.W #0x1234,2(A0,D1.W*2)"),
            st(6,SET_POINTER,"D1",0,0,null,0,8L),
            new HardwareDataflow.Step(8,"A0",null,"D1",32,1,
                0x68,0x5678,16,List.of(),"MOVE.W #0x5678,0x68(A0,D1.L)")
        ),Set.of(simcr,cs7),100);
        ok(indexed.snapshots.size()==2,"two indexed writes");
        ok(indexed.snapshots.get(0).effectiveAddress==simcr &&
            indexed.snapshots.get(0).writtenWord==0x1234,
            "signed word index and displacement resolve SIMCR");
        ok(indexed.snapshots.get(1).effectiveAddress==cs7,
            "long index + base + displacement resolves CSBAR7");

        var unknownIndex=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"A0",simcr,0,null,0,2L),
            new HardwareDataflow.Step(2,"A0",null,"D0",16,1,0,
                0x40ca,16,List.of(),"unknown D0")
        ),Set.of(simcr),100);
        ok(unknownIndex.snapshots.get(0).effectiveAddress==null &&
            unknownIndex.snapshots.get(0).knownPeripheralWords.isEmpty(),
            "unknown index is unresolved, not zero");

        var disagreeingIndex=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"A0",simcr,0,null,0,2L),
            st(2,OTHER,null,0,0,null,0,4L,6L),
            st(4,SET_POINTER,"D0",0,0,null,0,8L),
            st(6,SET_POINTER,"D0",2,0,null,0,8L),
            new HardwareDataflow.Step(8,"A0",null,"D0",16,1,0,
                0x40ca,16,List.of(),"branch-dependent index")
        ),Set.of(simcr,simcr+2),100);
        ok(disagreeingIndex.snapshots.get(0).effectiveAddress==null,
            "different predecessors must invalidate index address");

        var repeatedMm=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,simcr,0,0x40ca,16,2L),
            st(2,STORE_DIRECT,null,simcr,0,0x4848,16)
        ),Set.of(simcr),100);
        ok(repeatedMm.snapshots.get(0).priorMmCandidateMin==0 &&
            repeatedMm.snapshots.get(0).priorMmCandidateMax==0,
            "first local candidate has no prior matched writes");
        ok(repeatedMm.snapshots.get(1).priorMmCandidateMin==1 &&
            repeatedMm.snapshots.get(1).priorMmCandidateMax==1,
            "later site has preceding candidate; not proof of MM write success");

        var forkMm=HardwareDataflow.analyze(0,List.of(
            st(0,OTHER,null,0,0,null,0,2L,4L),
            st(2,STORE_DIRECT,null,simcr,0,0x40ca,16,6L),
            st(4,OTHER,null,0,0,null,0,6L),
            st(6,STORE_DIRECT,null,simcr,0,0x4848,16)
        ),Set.of(simcr),100);
        ok(forkMm.snapshots.get(1).priorMmCandidateMin==0 &&
            forkMm.snapshots.get(1).priorMmCandidateMax==1,
            "optional predecessor MM write retained as path range");

        var callMm=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,simcr,0,0x40ca,16,2L),
            st(2,CALL_BARRIER,null,0,0,null,0,4L),
            st(4,STORE_DIRECT,null,simcr,0,0x4848,16)
        ),Set.of(simcr),100);
        ok(callMm.snapshots.get(1).priorMmCandidateMin==1 &&
            callMm.snapshots.get(1).priorUnknownCall,
            "calls make hardware status uncertain, preserving local candidate history");

        var mmLowByte=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,simcr+1,0,0x40,8,2L),
            st(2,STORE_DIRECT,null,simcr,0,0x40ca,16)
        ),Set.of(simcr),100);
        ok(mmLowByte.snapshots.get(1).priorMmCandidateMax==1,
            "byte write to low MM bit must count as prior candidate");

        var otherPeriph=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,cs7,0,0xff88,16,2L),
            st(2,STORE_DIRECT,null,simcr,0,0x40ca,16)
        ),Set.of(simcr,cs7),100);
        ok(otherPeriph.snapshots.get(1).priorMmCandidateMax==0,
            "CSBAR is not SIMCR MM write");

        var unknownStore=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,cs7,0,0xff88,16,2L),
            st(2,STORE_INDIRECT,"A1",0,0,null,16,4L),
            st(4,STORE_DIRECT,null,simcr,0,0x40ca,16)
        ),Set.of(simcr,cs7),100);
        ok(unknownStore.snapshots.get(1).knownPeripheralWords.isEmpty(),
            "unknown-destination memory store invalidates previous CSBAR state");
        ok(unknownStore.snapshots.get(2).priorUnknownStore,
            "later SIMCR carries unknown write alias evidence");

        var partialStore=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,simcr,0,0x40ca,16,2L),
            st(2,STORE_DIRECT,null,simcr+1,0,0x00,8,4L),
            st(4,STORE_DIRECT,null,cs7,0,0xff88,16)
        ),Set.of(simcr,cs7),100);
        ok(!partialStore.snapshots.get(1).knownPeripheralWords.containsKey(simcr),
            "low-byte update invalidates earlier SIMCR word constant");
        ok(partialStore.snapshots.get(2).knownPeripheralWords.containsKey(cs7),
            "unrelated full-width write remains tracked");

        var longOverwrite=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,cs7,0,0x1234,16,2L),
            st(2,STORE_DIRECT,null,cs7-2,0,null,32,4L),
            st(4,STORE_DIRECT,null,simcr,0,0x40ca,16)
        ),Set.of(simcr,cs7),100);
        ok(!longOverwrite.snapshots.get(1).knownPeripheralWords.containsKey(cs7),
            "overlapping 32-bit write invalidates known CSBAR state");
        ok(longOverwrite.snapshots.get(2).knownPeripheralWords.containsKey(simcr),
            "known SIMCR value can be re-established after clobber");

        var postIncrement=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"A0",simcr,0,null,0,2L),
            st(2,STORE_INDIRECT,"A0",0,0,0x40ca,16,4L)
                .withSideEffects(Set.of("A0")),
            st(4,STORE_INDIRECT,"A0",0,0,0x4848,16)
        ),Set.of(simcr),100);
        ok(postIncrement.snapshots.get(0).effectiveAddress==simcr,
            "modeled first store uses pre-update base address");
        ok(postIncrement.snapshots.get(1).effectiveAddress==null,
            "post-increment base cannot be reused without explicit updated value");
        ok(postIncrement.snapshots.get(1).priorUnknownStore==false,
            "unknown second store is a barrier after its own evaluation");

        var inputIncrement=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"A3",simcr,0,null,0,2L),
            st(2,CLOBBER_POINTER,"D0",0,0,null,0,4L)
                .withSideEffects(HardwareAutoUpdateRegisters.changedByOperand("(A3)+")),
            st(4,STORE_INDIRECT,"A3",0,0,0x40ca,16)
        ),Set.of(simcr),100);
        ok(inputIncrement.snapshots.get(0).effectiveAddress==null,
            "source-side pre/post update invalidates A3 even if destination was D0");

        var trunc=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,simcr,0,0x40ca,16,2L),
            st(2,OTHER,null,0,0,null,0)
        ),Set.of(simcr),1);
        ok(trunc.truncated,"iteration ceiling surfaced");
        ok(trunc.snapshots.isEmpty(),"truncated fixed point cannot publish uncertain values");
        java.util.Map<String,Long> memo=java.util.Map.of("A0",0xfffa00L);
        ok(HardwareDataflow.pcodeInputValue(false,0L,memo.get("missing"))==null,
            "unknown varnode remains unknown");
        ok(HardwareDataflow.pcodeInputValue(false,0L,memo.get("A0"))==0xfffa00L,
            "propagated varnode remains known");
        ok(HardwareDataflow.pcodeInputValue(true,0x12345678L,null)==0x12345678L,
            "literal constant remains known");
        System.out.println("HardwareDataflowSelfTest OK");
    }
}
