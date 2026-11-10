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
 * GA-02/03/12/18: read-only, deterministic, adversarial checkpoint
 * proofs for MMIO/VBR fixed-point joins, unknown CALL/STORE barriers,
 * SIMCR first-candidate counts and a cyclic VBR back-edge. Each graph
 * is synthetic CPU32; no firmware is executed or edited.
 */
public final class HardwareMmioVbrJoinCheckpointSelfTest {
    private HardwareMmioVbrJoinCheckpointSelfTest(){}
    private static final int BUDGET=1000;
    private static final Set<Long> TARGETS=Set.of(0xfffa00L,0xfffa68L);
    private static void ok(boolean condition,String explanation){
        if(!condition)throw new AssertionError(explanation);
    }
    private static HardwareDataflow.Step step(long pc,HardwareDataflow.Kind kind,
            String reg,long value,int bits,Long... next){
        return new HardwareDataflow.Step(pc,kind,reg,value,0,null,bits,
            List.of(next),"synthetic");
    }
    private static HardwareDataflow.Step store(long pc,long address,
            Integer word,int bits,Long... next){
        return new HardwareDataflow.Step(pc,STORE_DIRECT,null,address,0,
            word,bits,List.of(next),"synthetic STORE");
    }
    private static HardwareDataflow.Step indirect(long pc,String base,
            int word,int bits,Long... next){
        return new HardwareDataflow.Step(pc,STORE_INDIRECT,base,0,0,
            word,bits,List.of(next),"synthetic indirect");
    }
    private static HardwareDataflow.Result cold(
            List<HardwareDataflow.Step> steps){
        var result=HardwareDataflow.analyze(0x100L,steps,TARGETS,BUDGET);
        ok(!result.truncated && result.snapshots.size()>0,
            "Synthetic source must have completed hardware evidence");
        return result;
    }
    private static HardwareDataflow.Snapshot site(
            HardwareDataflow.Result result,long pc){
        return result.snapshots.stream()
            .filter(s->s.instruction==pc).findFirst().orElseThrow();
    }
    private static HardwareDataflow.Snapshot edit(
            HardwareDataflow.Snapshot s,Long vbr,
            Map<Long,Integer> peripheral,int min,int max,
            boolean unknownCall,boolean unknownStore){
        return HardwareDataflow.Snapshot.restore(
            s.instruction,s.kind,s.effectiveAddress,s.writtenWord,
            s.writeBits,s.pointerRegister,vbr,peripheral,s.indirect,
            min,max,unknownCall,unknownStore);
    }
    private static HardwareDataflow.Result change(
            HardwareDataflow.Result source,long pc,
            HardwareDataflow.Snapshot altered){
        var snapshots=new ArrayList<>(source.snapshots);
        boolean found=false;
        for(int i=0;i<snapshots.size();i++)
            if(snapshots.get(i).instruction==pc){
                snapshots.set(i,altered);
                found=true;break;
            }
        ok(found,"Requested synthetic source PC");
        return HardwareDataflow.Result.restore(snapshots,
            source.reachedNodes,source.iterations,
            source.knownPointersAtEntry);
    }
    private static HardwareDurableStageStore.Key full(){
        return new HardwareDurableStageStore.Key(
            HardwareDurableStageStore.hash("ga12-mmio-vbr-join-project"),
            HardwareDurableStageStore.hash("ga12-mmio-vbr-join-bin"),
            HardwareDurableStageStore.hash("ga12-mmio-vbr-join-listing"),
            HardwareDurableStageStore.hash("ga12-mmio-vbr-join-ext-jar"),
            "68000:BE:32:CPU32",true);
    }
    private static HardwareDurableStageStore.Key derived(
            HardwareDurableStageStore.Key full,
            List<HardwareDataflow.Step> steps)throws Exception{
        Method key=HardwareDurableFunctionStages.class.getDeclaredMethod(
            "key",HardwareDurableStageStore.Key.class,long.class,int.class,
            java.util.Collection.class,java.util.Collection.class);
        key.setAccessible(true);
        return (HardwareDurableStageStore.Key)key.invoke(null,
            full,0x100L,BUDGET,steps,TARGETS);
    }
    private static void rejectResealed(Path temp,
            HardwareDurableStageStore.Key key,
            List<HardwareDataflow.Step> graph,
            HardwareDataflow.Result correct,
            HardwareDataflow.Result forged,String label)throws Exception{
        ok(HardwareDurableFunctionStages.save(temp,key,0x100L,BUDGET,
                graph,TARGETS,correct) &&
            HardwareDurableFunctionStages.load(temp,key,0x100L,BUDGET,
                graph,TARGETS).isPresent(),
            "Valid cold/complete per-function checkpoint: "+label);
        ok(!HardwareDurableFunctionStages.save(temp,key,0x100L,BUDGET,
                graph,TARGETS,forged),
            "No overwrite of good MMIO/VBR state: "+label);
        ok(HardwareDurableFunctionStages.load(temp,key,0x100L,BUDGET,
                graph,TARGETS).isPresent(),
            "Bad save leaves valid checkpoint intact: "+label);
        // Force the local disk envelope to hold attacker-modified typed
        // bytes with an *exact, correctly recomputed* SHA-256. It must be
        // refused by source-state semantics, not digest mismatch.
        HardwareDurableStageStore.save(temp,derived(key,graph),
            HardwareFunctionResultCodec.encode(forged));
        ok(HardwareDurableFunctionStages.load(temp,key,0x100L,BUDGET,
                graph,TARGETS).isEmpty(),
            "Resealed exact-key false CFG hardware state refused: "+label);
        ok(HardwareDurableFunctionStages.save(temp,key,0x100L,BUDGET,
                graph,TARGETS,correct) &&
            HardwareDurableFunctionStages.load(temp,key,0x100L,BUDGET,
                graph,TARGETS).isPresent(),
            "Good checkpoint recovers from locally resealed lie: "+label);
    }
    private static List<HardwareDataflow.Step> mmDiamond(
            int left,int right){
        return List.of(
            step(0x100,OTHER,null,0,0,0x102L,0x110L),
            store(0x102,0xfffa68L,left,16,0x120L),
            store(0x110,0xfffa68L,right,16,0x120L),
            store(0x120,0xfffa00L,0x40ca,16,0x122L),
            step(0x122,OTHER,null,0,0));
    }
    private static List<HardwareDataflow.Step> vbrDiamond(
            long left,long right){
        return List.of(
            step(0x100,OTHER,null,0,0,0x102L,0x110L),
            step(0x102,VBR_CONSTANT,null,left,0,0x120L),
            step(0x110,VBR_CONSTANT,null,right,0,0x120L),
            store(0x120,0xfffa00L,0x40ca,16,0x122L),
            step(0x122,OTHER,null,0,0));
    }
    public static void main(String[] args)throws Exception{
        Path temp=Files.createTempDirectory("ga12-mmio-vbr-join-");
        var key=full();
        try{
            var sameMm=mmDiamond(0x1234,0x1234);
            var same=cold(sameMm);
            ok(site(same,0x120L).knownPeripheralWords.equals(
                    Map.of(0xfffa00L,0x40ca,0xfffa68L,0x1234)) &&
                HardwareDurableFunctionStages.save(temp,key,0x100L,
                    BUDGET,sameMm,TARGETS,same),
                "Matching 16-bit peripheral values survive two CFG branches");

            var differentMm=mmDiamond(0x1234,0x5678);
            var disagreed=cold(differentMm);
            var merge=site(disagreed,0x120L);
            ok(merge.knownPeripheralWords.equals(
                    Map.of(0xfffa00L,0x40ca)) &&
                HardwareDurableFunctionStages.save(temp,key,0x100L,
                    BUDGET,differentMm,TARGETS,disagreed),
                "Conflicting CSBAR-like words collapse to UNKNOWN");
            var fakeMm=new LinkedHashMap<>(merge.knownPeripheralWords);
            fakeMm.put(0xfffa68L,0x1234);
            rejectResealed(temp,key,differentMm,disagreed,
                change(disagreed,0x120L,edit(merge,merge.vbr,fakeMm,
                    merge.priorMmCandidateMin,merge.priorMmCandidateMax,
                    merge.priorUnknownCall,merge.priorUnknownStore)),
                "conflicting branch peripheral word");

            var sameVbr=vbrDiamond(0x5000L,0x5000L);
            var verifiedVbr=cold(sameVbr);
            ok(site(verifiedVbr,0x120L).vbr==0x5000L &&
                HardwareDurableFunctionStages.save(temp,key,0x100L,
                    BUDGET,sameVbr,TARGETS,verifiedVbr),
                "Identical MOVEC/VBR base survives divergent control flow");
            var differentVbr=vbrDiamond(0x5000L,0x6000L);
            var unknownVbr=cold(differentVbr);
            var afterVbr=site(unknownVbr,0x120L);
            ok(afterVbr.vbr==null &&
                HardwareDurableFunctionStages.save(temp,key,0x100L,
                    BUDGET,differentVbr,TARGETS,unknownVbr),
                "Distinct MOVEC/VBR candidates remain UNKNOWN at join");
            rejectResealed(temp,key,differentVbr,unknownVbr,
                change(unknownVbr,0x120L,edit(afterVbr,0x5000L,
                    afterVbr.knownPeripheralWords,
                    afterVbr.priorMmCandidateMin,afterVbr.priorMmCandidateMax,
                    afterVbr.priorUnknownCall,afterVbr.priorUnknownStore)),
                "single-VBR false certainty at branch merge");

            var call=List.of(
                store(0x100,0xfffa68L,0x1234,16,0x102L),
                step(0x102,VBR_CONSTANT,null,0x5000L,0,0x104L),
                new HardwareDataflow.Step(0x104,CALL_BARRIER,
                    null,0,0,null,0,List.of(0x106L),"JSR leaf")
                    .withVerifiedCallReturns(Map.of("A0",0xfffa00L)),
                indirect(0x106,"A0",0x40ca,16,0x108L),
                step(0x108,OTHER,null,0,0));
            var postCall=cold(call);
            var afterCall=site(postCall,0x106L);
            ok(afterCall.knownPeripheralWords.equals(
                    Map.of(0xfffa00L,0x40ca)) &&
                afterCall.vbr==null && afterCall.priorUnknownCall &&
                HardwareDurableFunctionStages.save(temp,key,0x100L,
                    BUDGET,call,TARGETS,postCall),
                "CALL clears peripheral/VBR while verified A0 may return");
            var falselySaved=new LinkedHashMap<>(
                afterCall.knownPeripheralWords);
            falselySaved.put(0xfffa68L,0x1234);
            rejectResealed(temp,key,call,postCall,
                change(postCall,0x106L,edit(afterCall,0x5000L,
                    falselySaved,afterCall.priorMmCandidateMin,
                    afterCall.priorMmCandidateMax,false,
                    afterCall.priorUnknownStore)),
                "post-CALL forged peripheral, VBR and UNKNOWN call provenance");

            var unknownStore=List.of(
                store(0x100,0xfffa68L,0x1234,16,0x102L),
                indirect(0x102,"A1",0xabcd,16,0x104L),
                store(0x104,0xfffa00L,0x40ca,16,0x106L),
                step(0x106,OTHER,null,0,0));
            var unknown=cold(unknownStore);
            var recovered=site(unknown,0x104L);
            ok(recovered.knownPeripheralWords.equals(
                    Map.of(0xfffa00L,0x40ca)) &&
                recovered.priorUnknownStore &&
                HardwareDurableFunctionStages.save(temp,key,0x100L,
                    BUDGET,unknownStore,TARGETS,unknown),
                "Unknown indirect alias clears older tracked MMIO words");
            rejectResealed(temp,key,unknownStore,unknown,
                change(unknown,0x104L,edit(recovered,recovered.vbr,
                    Map.of(0xfffa00L,0x40ca,0xfffa68L,0x1234),
                    recovered.priorMmCandidateMin,
                    recovered.priorMmCandidateMax,
                    recovered.priorUnknownCall,false)),
                "UNKNOWN indirect STORE cannot keep stale CSBAR or suppress barrier");

            var partial=List.of(
                store(0x100,0xfffa68L,0x1234,16,0x102L),
                store(0x102,0xfffa69L,0x56,8,0x104L),
                store(0x104,0xfffa00L,0x40ca,16,0x106L),
                step(0x106,OTHER,null,0,0));
            var byteResult=cold(partial);
            var afterByte=site(byteResult,0x104L);
            ok(afterByte.knownPeripheralWords.equals(
                    Map.of(0xfffa00L,0x40ca)) &&
                HardwareDurableFunctionStages.save(temp,key,0x100L,
                    BUDGET,partial,TARGETS,byteResult),
                "Overlapping byte STORE invalidates earlier 16-bit whole word");
            rejectResealed(temp,key,partial,byteResult,
                change(byteResult,0x104L,edit(afterByte,afterByte.vbr,
                    Map.of(0xfffa00L,0x40ca,0xfffa68L,0x1234),
                    afterByte.priorMmCandidateMin,
                    afterByte.priorMmCandidateMax,
                    afterByte.priorUnknownCall,afterByte.priorUnknownStore)),
                "partial-width previous STORE cannot restore old whole word");

            var counter=List.of(
                store(0x100,0xfffa00L,0x40ca,16,0x102L),
                step(0x102,OTHER,null,0,0,0x104L,0x110L),
                store(0x104,0xfffa00L,0x4848,16,0x120L),
                step(0x110,OTHER,null,0,0,0x120L),
                store(0x120,0xfffa68L,0x1234,16,0x122L),
                step(0x122,OTHER,null,0,0));
            var counted=cold(counter);
            var count=site(counted,0x120L);
            ok(count.priorMmCandidateMin==1 &&
                count.priorMmCandidateMax==2 &&
                HardwareDurableFunctionStages.save(temp,key,0x100L,
                    BUDGET,counter,TARGETS,counted),
                "Per-path saturated first SIMCR candidate 1..2 at branch join");
            rejectResealed(temp,key,counter,counted,
                change(counted,0x120L,edit(count,count.vbr,
                    count.knownPeripheralWords,0,2,
                    count.priorUnknownCall,count.priorUnknownStore)),
                "falsified first-source MMIO epoch min counter");

            var cycle=List.of(
                step(0x100,VBR_CONSTANT,null,0x5000L,0,0x102L),
                step(0x102,OTHER,null,0,0,0x104L,0x120L),
                step(0x104,VBR_CONSTANT,null,0x6000L,0,0x102L),
                store(0x120,0xfffa00L,0x40ca,16,0x122L),
                step(0x122,OTHER,null,0,0));
            var loop=cold(cycle);
            var loopSite=site(loop,0x120L);
            ok(loopSite.vbr==null &&
                HardwareDurableFunctionStages.save(temp,key,0x100L,
                    BUDGET,cycle,TARGETS,loop),
                "VBR candidate is UNKNOWN after a conflicting CFG back edge");
            rejectResealed(temp,key,cycle,loop,
                change(loop,0x120L,edit(loopSite,0x5000L,
                    loopSite.knownPeripheralWords,
                    loopSite.priorMmCandidateMin,
                    loopSite.priorMmCandidateMax,
                    loopSite.priorUnknownCall,loopSite.priorUnknownStore)),
                "loop back-edge VBR choice cannot be treated as current VBR");

            System.out.println(
                "HardwareMmioVbrJoinCheckpointSelfTest OK: synthetic MMIO/VBR, loop and unknown barriers");
        }finally{
            try(var files=Files.list(temp)){
                for(Path file:files.toList())Files.deleteIfExists(file);
            }
            Files.deleteIfExists(temp);
        }
    }
}
