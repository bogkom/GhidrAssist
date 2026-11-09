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

        // Partial/long static writes can touch the MM low byte without
        // establishing any full 16-bit SIMCR word or executed MM latch.
        ok(HardwareDataflow.mayTouchSimcrMmLowByte(simcr-2,32) &&
            HardwareDataflow.mayTouchSimcrMmLowByte(simcr+1,8) &&
            HardwareDataflow.mayTouchSimcrMmLowByte(0x7ff9feL,32) &&
            !HardwareDataflow.mayTouchSimcrMmLowByte(simcr,8) &&
            !HardwareDataflow.mayTouchSimcrMmLowByte(cs7,32),
            "only source writes touching the MM low byte are candidates");
        var partialMm=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,simcr-2,0,null,32,2L),
            st(2,STORE_DIRECT,null,simcr,0,0x40ca,16)
        ),Set.of(simcr),100);
        ok(partialMm.snapshots.get(0).writtenWord==null &&
            partialMm.snapshots.get(1).priorMmCandidateMin==1 &&
            partialMm.snapshots.get(1).priorMmCandidateMax==1,
            "32-bit spanning STORE is a prior unknown MM candidate");
        var alternateMm=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,0x7ff9feL,0,null,32,2L),
            st(2,STORE_DIRECT,null,0x7ffa00L,0,0x4848,16)
        ),Set.of(0x7ffa00L),100);
        ok(alternateMm.snapshots.get(1).priorMmCandidateMin==1,
            "alternate SIMCR alias mapping has same conservative guard");
        var highByteOnly=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,simcr,0,0x48,8,2L),
            st(2,STORE_DIRECT,null,simcr,0,0x40ca,16)
        ),Set.of(simcr),100);
        ok(highByteOnly.snapshots.get(1).priorMmCandidateMax==0,
            "high byte alone does not contain the MM bit");

        // Complete STORE over the 24-bit address boundary also touches 0.
        var wrapped=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,0L,0,0x1234,16,2L),
            st(2,STORE_DIRECT,null,simcr,0,0x40ca,16,4L),
            st(4,STORE_DIRECT,null,0xfffffeL,0,null,32,6L),
            st(6,STORE_DIRECT,null,cs7,0,0xff88,16)
        ),Set.of(0L,simcr,cs7),100);
        ok(!wrapped.snapshots.get(2).knownPeripheralWords.containsKey(0L),
            "32-bit source STORE at 0xFFFFFE invalidates word at 0x000000");
        ok(wrapped.snapshots.get(2).knownPeripheralWords.get(simcr)==0x40ca &&
            wrapped.snapshots.get(3).knownPeripheralWords.get(cs7)==0xff88,
            "unrelated words survive and fresh whole words can be inferred");

        // ADDQ.W / SUBQ.W on Dn change only 16 low bits; an
        // optimistic 24-bit addition can invent an MMIO address via COPY.
        ok(HardwareDataflow.registerAdjustWidth("D0","ADDQ.W")==16 &&
            HardwareDataflow.registerAdjustWidth("D0","SUBQ.B")==8 &&
            HardwareDataflow.registerAdjustWidth("D0","ADDQ.L")==32 &&
            HardwareDataflow.registerAdjustWidth("A0","ADDQ.W")==32 &&
            HardwareDataflow.registerAdjustWidth("D0","ADDQ")==0,
            "decode arithmetic width without promoting Dn partial writes");
        var wordAdjust=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"D0",0x00feffffL,0,null,0,2L),
            st(2,ADJUST_POINTER,"D0",1,0,null,16,4L),
            new HardwareDataflow.Step(4,COPY_POINTER,"A0","D0",0,0,
                null,0,List.of(6L),"MOVE.L D0,A0"),
            st(6,STORE_INDIRECT,"A0",0,0,0x40ca,16)
        ),Set.of(0x00fe0000L,0x00ff0000L),100);
        ok(wordAdjust.snapshots.get(0).effectiveAddress==0x00fe0000L,
            "ADDQ.W Dn low-word rollover must not carry into upper word");
        var byteAdjust=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"D1",0x00ff12ffL,0,null,0,2L),
            st(2,ADJUST_POINTER,"D1",1,0,null,8,4L),
            new HardwareDataflow.Step(4,COPY_POINTER,"A1","D1",0,0,
                null,0,List.of(6L),"MOVE.L D1,A1"),
            st(6,STORE_INDIRECT,"A1",0,0,0x40ca,16)
        ),Set.of(0x00ff1200L),100);
        ok(byteAdjust.snapshots.get(0).effectiveAddress==0x00ff1200L,
            "ADDQ.B Dn preserves all unaffected high bits");
        var subtraction=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"D2",0x00ff0000L,0,null,0,2L),
            st(2,ADJUST_POINTER,"D2",-1,0,null,16,4L),
            new HardwareDataflow.Step(4,COPY_POINTER,"A2","D2",0,0,
                null,0,List.of(6L),"MOVE.L D2,A2"),
            st(6,STORE_INDIRECT,"A2",0,0,0x40ca,16)
        ),Set.of(0x00ffffffL),100);
        ok(subtraction.snapshots.get(0).effectiveAddress==0x00ffffffL,
            "SUBQ.W Dn underflow does not borrow from preserved upper bits");
        var fullDataAdjust=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"D0",0x00feffffL,0,null,0,2L),
            st(2,ADJUST_POINTER,"D0",1,0,null,32,4L),
            new HardwareDataflow.Step(4,COPY_POINTER,"A0","D0",0,0,
                null,0,List.of(6L),"MOVE.L D0,A0"),
            st(6,STORE_INDIRECT,"A0",0,0,0x40ca,16)
        ),Set.of(0x00ff0000L),100);
        ok(fullDataAdjust.snapshots.get(0).effectiveAddress==0x00ff0000L,
            "ADDQ.L Dn really can carry into higher bits");
        var fullAddressAdjust=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"A0",0x00feffffL,0,null,0,2L),
            st(2,ADJUST_POINTER,"A0",1,0,null,32,4L),
            st(4,STORE_INDIRECT,"A0",0,0,0x40ca,16)
        ),Set.of(0x00ff0000L),100);
        ok(fullAddressAdjust.snapshots.get(0).effectiveAddress==0x00ff0000L,
            "ADDQ.W to An adjusts full address register on 68000");
        var unsizedDataAdjust=HardwareDataflow.analyze(0,List.of(
            st(0,SET_POINTER,"D0",simcr,0,null,0,2L),
            st(2,ADJUST_POINTER,"D0",1,0,null,0,4L),
            new HardwareDataflow.Step(4,COPY_POINTER,"A0","D0",0,0,
                null,0,List.of(6L),"MOVE.L D0,A0"),
            st(6,STORE_INDIRECT,"A0",0,0,0x40ca,16)
        ),Set.of(simcr),100);
        ok(unsizedDataAdjust.snapshots.get(0).effectiveAddress==null,
            "unknown Dn arithmetic width invalidates pointer provenance");

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
        // Worklist iteration caps alone do not bound source adjacency.
        // A single decoded node can contain far more successors than the
        // solver will ever visit. Refuse 200001 references before processing.
        var cappedFanout=new HardwareDataflow.Step(0,OTHER,
            null,0,0,null,0,java.util.Collections.nCopies(
                HardwareDataflow.MAX_SOURCE_EDGES,0L),"BRA");
        var cappedSource=HardwareDataflow.analyze(0,
            List.of(cappedFanout),Set.of(simcr),10);
        ok(!cappedSource.truncated && cappedSource.reachedNodes==1 &&
            cappedSource.snapshots.isEmpty(),
            "exact 200k duplicated successors remain bounded valid input");
        boolean tooManyEdges=false;
        try{
            HardwareDataflow.analyze(0,List.of(
                new HardwareDataflow.Step(0,OTHER,null,0,0,null,0,
                    java.util.Collections.nCopies(
                        HardwareDataflow.MAX_SOURCE_EDGES+1,0L),"BRA")),
                Set.of(simcr),10);
        }catch(IllegalArgumentException expected){tooManyEdges=true;}
        ok(tooManyEdges,
            "200001 source successor edges rejected before a fixed point");
        tooManyEdges=false;
        try{
            HardwareDataflow.analyze(0,List.of(
                new HardwareDataflow.Step(0,OTHER,null,0,0,null,0,
                    java.util.Collections.nCopies(
                        HardwareDataflow.MAX_SOURCE_EDGES/2,2L),"BRA"),
                new HardwareDataflow.Step(2,OTHER,null,0,0,null,0,
                    java.util.Collections.nCopies(
                        HardwareDataflow.MAX_SOURCE_EDGES/2+1,0L),"BRA")),
                Set.of(simcr),10);
        }catch(IllegalArgumentException expected){tooManyEdges=true;}
        ok(tooManyEdges,
            "aggregate source CFG edge count applies across all steps");
        ok(straightforward.snapshots.get(0).effectiveAddress==simcr,
            "rejected oversized CFG does not modify prior MMIO evidence");
        // A caller-supplied indexed Step must obey the same CPU32
        // 32-bit extension limit as parsed actual Ghidra operands.
        // Otherwise 0x100000000 silently wraps on the 24-bit bus and
        // could masquerade as a precise MC68332 SIMCR source.
        var edgePositive=new HardwareDataflow.Step(0,"A1","D0",
            "D1",16,1,0xffffffffL,null,16,List.of(),"MOVE.W");
        var edgeNegative=new HardwareDataflow.Step(0,"A1","D0",
            "D1",16,1,-0x80000000L,null,16,List.of(),"MOVE.W");
        ok(edgePositive.displacement==0xffffffffL &&
            edgeNegative.displacement==-0x80000000L,
            "valid signed/unsigned 32-bit extension bounds unchanged");
        boolean deniedLongDisplacement=false;
        try {
            new HardwareDataflow.Step(0,"A1","D0","D1",16,1,
                0x100000000L,null,16,List.of(),"MOVE.W");
        }catch(IllegalArgumentException expected){deniedLongDisplacement=true;}
        ok(deniedLongDisplacement,
            "synthetic >32-bit displacement cannot become 24-bit MMIO");
        deniedLongDisplacement=false;
        try {
            new HardwareDataflow.Step(0,"A1","D0","D1",16,1,
                -0x80000001L,null,16,List.of(),"MOVE.W");
        }catch(IllegalArgumentException expected){deniedLongDisplacement=true;}
        ok(deniedLongDisplacement,
            "negative below signed 32-bit displacement also fails closed");
        // CPU32 24-bit boundary: each candidate uses the source write
        // width and byte intersection, never a guessed physical map.
        // Byte at FFFFFF does not overlap tracked word 000000..000001;
        // word at FFFFFF does (wrapped second byte), as does a 32-bit
        // write at FFFFFD (wrapped fourth byte).
        var boundary=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,0,0,0x1111,16,2L),
            st(2,STORE_DIRECT,null,0xffffffL,0,null,8,4L),
            st(4,STORE_DIRECT,null,0xffffffL,0,null,16,6L),
            st(6,STORE_DIRECT,null,0,0,0x2222,16,8L),
            st(8,STORE_DIRECT,null,0xfffffdL,0,null,32,10L),
            st(10,STORE_DIRECT,null,0,0,0x3333,16)
        ),Set.of(0L),100);
        ok(boundary.snapshots.size()==6 &&
            Integer.valueOf(0x1111).equals(boundary.snapshots.get(1)
                .knownPeripheralWords.get(0L)) &&
            !boundary.snapshots.get(2).knownPeripheralWords.containsKey(0L) &&
            Integer.valueOf(0x2222).equals(boundary.snapshots.get(3)
                .knownPeripheralWords.get(0L)) &&
            !boundary.snapshots.get(4).knownPeripheralWords.containsKey(0L) &&
            Integer.valueOf(0x3333).equals(boundary.snapshots.get(5)
                .knownPeripheralWords.get(0L)),
            "8/16/32-bit wrap invalidates only intersecting tracked words");
        // A byte at FFFFFF DOES overlap the LOW byte of word FFFFFE.
        var highBoundary=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,0xfffffeL,0,0xaaaa,16,2L),
            st(2,STORE_DIRECT,null,0xffffffL,0,null,8,4L),
            st(4,STORE_DIRECT,null,0xfffffeL,0,0xbbbb,16,6L),
            st(6,STORE_DIRECT,null,0xfffffcL,0,null,32)
        ),Set.of(0xfffffeL),100);
        ok(!highBoundary.snapshots.get(1).knownPeripheralWords
                .containsKey(0xfffffeL) &&
            Integer.valueOf(0xbbbb).equals(
                highBoundary.snapshots.get(2).knownPeripheralWords
                    .get(0xfffffeL)) &&
            !highBoundary.snapshots.get(3).knownPeripheralWords
                .containsKey(0xfffffeL),
            "high-edge byte and 32-bit overlapping write poison full word");
        // Long crossing FFFFFE->000001 invalidates TWO independently
        // tracked words, while an unrelated SIMCR word remains known.
        var doubleWrap=HardwareDataflow.analyze(0,List.of(
            st(0,STORE_DIRECT,null,0xfffffeL,0,0xaaaa,16,2L),
            st(2,STORE_DIRECT,null,0,0,0xbbbb,16,4L),
            st(4,STORE_DIRECT,null,simcr,0,0x40ca,16,6L),
            st(6,STORE_DIRECT,null,0xfffffeL,0,null,32)
        ),Set.of(0xfffffeL,0L,simcr),100);
        ok(!doubleWrap.snapshots.get(3).knownPeripheralWords
                .containsKey(0xfffffeL) &&
            !doubleWrap.snapshots.get(3).knownPeripheralWords
                .containsKey(0L) &&
            Integer.valueOf(0x40ca).equals(
                doubleWrap.snapshots.get(3).knownPeripheralWords.get(simcr)),
            "32-bit wrapped write invalidates both edge words only");
        ok(HardwareDataflow.mayTouchTrackedAddress(
                0xffffffL,16,Set.of(0L)) &&
            HardwareDataflow.mayTouchTrackedAddress(
                0xfffffdL,32,Set.of(0L)) &&
            !HardwareDataflow.mayTouchTrackedAddress(
                0xffffffL,8,Set.of(0L)),
            "tracked byte-level overlap at modulo-24 boundary");
        System.out.println("HardwareDataflowSelfTest OK");
    }
}
