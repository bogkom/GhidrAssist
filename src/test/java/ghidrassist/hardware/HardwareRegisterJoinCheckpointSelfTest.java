package ghidrassist.hardware;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

/**
 * GA-02/03/12: independent A/D register lattice fixed-point validation
 * before publishing a completed, digest-matching durable CFG source.
 * No Ghidra Program, ECU firmware or model/runtime execution involved.
 */
public final class HardwareRegisterJoinCheckpointSelfTest {
    private HardwareRegisterJoinCheckpointSelfTest(){}
    private static final int BUDGET=1000;
    private static final Set<Long> TARGETS=Set.of(0xfffa00L,0xfffa68L);
    private static void ok(boolean b,String why){
        if(!b)throw new AssertionError(why);
    }
    private static HardwareDataflow.Step step(long at,
            HardwareDataflow.Kind kind,String reg,long operand,int bits,
            Long... successors){
        return new HardwareDataflow.Step(at,kind,reg,operand,0,
            null,bits,List.of(successors),"synthetic");
    }
    private static HardwareDataflow.Step write(long at,Long... successors){
        return new HardwareDataflow.Step(at,STORE_INDIRECT,"A0",0L,0,
            0x40ca,16,List.of(successors),"MOVE.W #40ca,(A0)");
    }
    private static HardwareDataflow.Result cold(
            List<HardwareDataflow.Step> steps){
        var result=HardwareDataflow.analyze(0x100L,steps,TARGETS,BUDGET);
        ok(!result.truncated && result.snapshots.size()==1,
            "Complete static CFG fixture with exactly one write");
        return result;
    }
    private static HardwareDurableStageStore.Key full(){
        return new HardwareDurableStageStore.Key(
            HardwareDurableStageStore.hash("synthetic-GA12-branch-project"),
            HardwareDurableStageStore.hash("synthetic-GA12-branch-firmware"),
            HardwareDurableStageStore.hash("synthetic-listing-exact-revision"),
            HardwareDurableStageStore.hash("synthetic-compiled-analyzer"),
            "68000:BE:32:CPU32",true);
    }
    private static HardwareDurableStageStore.Key internal(
            HardwareDurableStageStore.Key full,
            List<HardwareDataflow.Step> steps)throws Exception{
        Method method=HardwareDurableFunctionStages.class
            .getDeclaredMethod("key",HardwareDurableStageStore.Key.class,
                long.class,int.class,java.util.Collection.class,
                java.util.Collection.class);
        method.setAccessible(true);
        return (HardwareDurableStageStore.Key)method.invoke(
            null,full,0x100L,BUDGET,steps,TARGETS);
    }
    private static HardwareDataflow.Result changePointers(
            HardwareDataflow.Result result,long pc,String reg,long value){
        Map<Long,Map<String,Long>> pointers=new LinkedHashMap<>(
            result.knownPointersAtEntry);
        Map<String,Long> row=new LinkedHashMap<>(
            pointers.getOrDefault(pc,Map.of()));
        row.put(reg,value);
        pointers.put(pc,row);
        return HardwareDataflow.Result.restore(result.snapshots,
            result.reachedNodes,result.iterations,pointers);
    }
    private static HardwareDataflow.Result inventStore(
            HardwareDataflow.Result result,long address,int word,
            Map<Long,Map<String,Long>> registers){
        var original=result.snapshots.get(0);
        var lie=HardwareDataflow.Snapshot.restore(
            original.instruction,original.kind,address,word,
            original.writeBits,original.pointerRegister,original.vbr,
            Map.of(address,word),original.indirect,
            original.priorMmCandidateMin,original.priorMmCandidateMax,
            original.priorUnknownCall,original.priorUnknownStore);
        return HardwareDataflow.Result.restore(List.of(lie),
            result.reachedNodes,result.iterations,registers);
    }
    private static void rejectResealed(Path dir,
            HardwareDurableStageStore.Key full,
            List<HardwareDataflow.Step> graph,
            HardwareDataflow.Result valid,
            HardwareDataflow.Result forgery,String caseName)throws Exception{
        var key=internal(full,graph);
        ok(HardwareDurableFunctionStages.save(dir,full,
            0x100L,BUDGET,graph,TARGETS,valid),
            "Cold valid proof must save first: "+caseName);
        ok(!HardwareDurableFunctionStages.save(dir,full,
            0x100L,BUDGET,graph,TARGETS,forgery),
            "Cannot replace correct source with forged branch state: "+caseName);
        ok(HardwareDurableFunctionStages.load(dir,full,
            0x100L,BUDGET,graph,TARGETS).isPresent(),
            "Rejected save preserves old checkpoint: "+caseName);
        // Hostile local re-seal of full typed payload with correct outer
        // SHA-256 and exact graph/project key; do NOT classify this as a
        // checksum failure. The *independent join proof* must reject it.
        HardwareDurableStageStore.save(dir,key,
            HardwareFunctionResultCodec.encode(forgery));
        ok(HardwareDurableFunctionStages.load(dir,full,
            0x100L,BUDGET,graph,TARGETS).isEmpty(),
            "Resealed false CFG join must fail load: "+caseName);
        ok(HardwareDurableFunctionStages.save(dir,full,
            0x100L,BUDGET,graph,TARGETS,valid) &&
            HardwareDurableFunctionStages.load(dir,full,
                0x100L,BUDGET,graph,TARGETS).isPresent(),
            "Valid stage restored after forged checkpoint: "+caseName);
    }
    private static List<HardwareDataflow.Step> diamond(
            long leftValue,long rightValue){
        return List.of(
            step(0x100,OTHER,null,0,0,0x102L,0x110L),
            step(0x102,SET_POINTER,"A0",leftValue,0,0x120L),
            step(0x110,SET_POINTER,"A0",rightValue,0,0x120L),
            write(0x120,0x122L),
            step(0x122,OTHER,null,0,0));
    }
    public static void main(String[] args)throws Exception {
        Path dir=Files.createTempDirectory("ga12-register-join-proof-");
        var full=full();
        try{
            var agreed=diamond(0xfffa00L,0xfffa00L);
            var positive=cold(agreed);
            ok(positive.snapshots.get(0).effectiveAddress==0xfffa00L &&
                positive.knownPointersAtEntry.get(0x120L).get("A0")==0xfffa00L &&
                HardwareDurableFunctionStages.save(dir,full,
                    0x100L,BUDGET,agreed,TARGETS,positive) &&
                HardwareDurableFunctionStages.load(dir,full,
                    0x100L,BUDGET,agreed,TARGETS).isPresent(),
                "Independent cold branch JOIN preserves matching A0 constants");
            rejectResealed(dir,full,agreed,positive,
                changePointers(positive,0x102L,"A0",0xfffa68L),
                "predecessor A0 falsely known before SET_POINTER");

            var conflict=diamond(0xfffa00L,0xfffa68L);
            var uncertain=cold(conflict);
            ok(uncertain.snapshots.get(0).effectiveAddress==null &&
                !uncertain.knownPointersAtEntry.containsKey(0x120L) &&
                HardwareDurableFunctionStages.save(dir,full,
                    0x100L,BUDGET,conflict,TARGETS,uncertain),
                "Disagreeing CFG branch aliases collapse to UNKNOWN");
            // Simultaneously forge predecessor output AND the STORE
            // to make the old per-site source/value audit self-consistent.
            var falseRegs=new LinkedHashMap<>(
                uncertain.knownPointersAtEntry);
            falseRegs.put(0x120L,Map.of("A0",0xfffa00L));
            rejectResealed(dir,full,conflict,uncertain,
                inventStore(uncertain,0xfffa00L,0x40ca,falseRegs),
                "full fake SIMCR MMIO write across contradictory predecessors");

            var clobbered=List.of(
                step(0x100,SET_POINTER,"A0",0xfffa00L,0,0x102L),
                step(0x102,OTHER,null,0,0,0x104L,0x110L),
                step(0x104,CLOBBER_POINTER,"A0",0,0,0x120L),
                step(0x110,OTHER,null,0,0,0x120L),
                write(0x120,0x122L),
                step(0x122,OTHER,null,0,0));
            var noPointer=cold(clobbered);
            ok(noPointer.snapshots.get(0).effectiveAddress==null &&
                HardwareDurableFunctionStages.save(dir,full,
                    0x100L,BUDGET,clobbered,TARGETS,noPointer),
                "One clobber predecessor makes joined A0 unknown");
            var clobberLie=new LinkedHashMap<>(
                noPointer.knownPointersAtEntry);
            clobberLie.put(0x120L,Map.of("A0",0xfffa00L));
            rejectResealed(dir,full,clobbered,noPointer,
                inventStore(noPointer,0xfffa00L,0x40ca,clobberLie),
                "clobbered branch cannot keep stale A0");

            var returnProof=new HardwareDataflow.Step(
                0x104,CALL_BARRIER,null,0,0,null,0,
                List.of(0x120L),"JSR leaf")
                .withSideEffects(Set.of("A0","A7"))
                .withVerifiedCallReturns(Map.of("A0",0xfffa00L));
            var calls=List.of(
                step(0x100,OTHER,null,0,0,0x102L,0x110L),
                step(0x102,OTHER,null,0,0,0x104L),
                returnProof,
                step(0x110,SET_POINTER,"A0",0xfffa00L,0,0x120L),
                write(0x120,0x122L),
                step(0x122,OTHER,null,0,0));
            var returned=cold(calls);
            ok(returned.snapshots.get(0).effectiveAddress==0xfffa00L &&
                HardwareDurableFunctionStages.save(dir,full,
                    0x100L,BUDGET,calls,TARGETS,returned),
                "Input-independent verified leaf A0 survives a matching branch JOIN");
            rejectResealed(dir,full,calls,returned,
                changePointers(returned,0x104L,"A0",0xfffa00L),
                "CALL pre-RTS pointer is UNKNOWN even when leaf returns a value");

            var loop=List.of(
                step(0x100,SET_POINTER,"A0",0xfffa00L,0,0x110L),
                step(0x110,OTHER,null,0,0,0x112L,0x120L),
                step(0x112,CLOBBER_POINTER,"A0",0,0,0x110L),
                write(0x120,0x122L),
                step(0x122,OTHER,null,0,0));
            var fixed=cold(loop);
            ok(fixed.snapshots.get(0).effectiveAddress==null &&
                !fixed.knownPointersAtEntry.containsKey(0x110L) &&
                HardwareDurableFunctionStages.save(dir,full,
                    0x100L,BUDGET,loop,TARGETS,fixed),
                "Bounded cyclic worklist drops A0 at back-edge fixed point");
            var loopLie=new LinkedHashMap<>(
                fixed.knownPointersAtEntry);
            loopLie.put(0x110L,Map.of("A0",0xfffa00L));
            loopLie.put(0x120L,Map.of("A0",0xfffa00L));
            rejectResealed(dir,full,loop,fixed,
                inventStore(fixed,0xfffa00L,0x40ca,loopLie),
                "loop back-edge unknown cannot publish false SIMCR");

            // Full 24-bit model Dn partial adjustment: the branch with
            // .B increments a low byte while .W can carry into high byte.
            var adjusted=List.of(
                step(0x100,SET_POINTER,"D0",0x12ffL,0,0x102L),
                step(0x102,SET_POINTER,"A0",0xfffa00L,0,
                    0x104L,0x110L),
                step(0x104,ADJUST_POINTER,"D0",1L,8,0x120L),
                step(0x110,ADJUST_POINTER,"D0",1L,16,0x120L),
                new HardwareDataflow.Step(0x120,STORE_INDIRECT,
                    "A0","D0",0,0,null,16,List.of(0x122L),
                    "MOVE.W D0,(A0)"),
                step(0x122,OTHER,null,0,0));
            var noWord=cold(adjusted);
            ok(noWord.snapshots.get(0).effectiveAddress==0xfffa00L &&
                noWord.snapshots.get(0).writtenWord==null &&
                HardwareDurableFunctionStages.save(dir,full,0x100L,
                    BUDGET,adjusted,TARGETS,noWord),
                "Different D0 .B/.W updates collapse joined STORE word");
            var changedD0=new LinkedHashMap<>(
                noWord.knownPointersAtEntry);
            var d0join=new LinkedHashMap<>(changedD0.get(0x120L));
            d0join.put("D0",0x1300L);
            changedD0.put(0x120L,d0join);
            var before=noWord.snapshots.get(0);
            var forged=HardwareDataflow.Snapshot.restore(
                before.instruction,before.kind,before.effectiveAddress,
                0x1300,before.writeBits,before.pointerRegister,before.vbr,
                Map.of(0xfffa00L,0x1300),before.indirect,
                before.priorMmCandidateMin,before.priorMmCandidateMax,
                before.priorUnknownCall,before.priorUnknownStore);
            rejectResealed(dir,full,adjusted,noWord,
                HardwareDataflow.Result.restore(List.of(forged),
                    noWord.reachedNodes,noWord.iterations,changedD0),
                "conflicting D0 partial arithmetic cannot yield known word");

            System.out.println(
                "HardwareRegisterJoinCheckpointSelfTest OK: synthetic A/D branch, CALL and cyclic JOIN receipts");
        }finally {
            try(var files=Files.list(dir)){
                for(Path p:files.toList())Files.deleteIfExists(p);
            }
            Files.deleteIfExists(dir);
        }
    }
}
