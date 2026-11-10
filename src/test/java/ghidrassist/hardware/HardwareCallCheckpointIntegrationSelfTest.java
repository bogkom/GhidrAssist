package ghidrassist.hardware;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

/**
 * GA-02/03 + GA-12: changing ONLY a callee's proved post-RTS register
 * constants MUST invalidate both process-local and durable CFG checkpoints.
 */
public final class HardwareCallCheckpointIntegrationSelfTest {
    private HardwareCallCheckpointIntegrationSelfTest(){}
    private static void check(boolean ok,String message) {
        if(!ok)throw new AssertionError(message);
    }
    private static List<HardwareDataflow.Step> graph(Map<String,Long> outputs) {
        List<HardwareDataflow.Step> steps=new ArrayList<>();
        steps.add(new HardwareDataflow.Step(0x100,CALL_BARRIER,null,
            0,0,null,0,List.of(0x106L),"JSR")
            .withSideEffects(Set.of("D0","A0","A7"))
            .withVerifiedCallReturns(outputs));
        steps.add(new HardwareDataflow.Step(0x106,STORE_INDIRECT,
            "A0","D0",0,0,null,16,List.of(0x108L),"MOVE.W D0,(A0)"));
        for(long pc=0x108;pc<0x150;pc+=2)
            steps.add(new HardwareDataflow.Step(pc,OTHER,
                null,0,0,null,0,
                List.of(pc+2),"NOP"));
        steps.add(new HardwareDataflow.Step(0x150,OTHER,
            null,0,0,null,0,List.of(),"RTS"));
        return steps;
    }
    private static HardwareDurableStageStore.Key key(String inputSha) {
        return new HardwareDurableStageStore.Key(
            HardwareDurableStageStore.hash("isolated-Ghidra-project"),
            HardwareDurableStageStore.hash("source-synthetic-MC68332"),
            HardwareDurableStageStore.hash(inputSha),
            HardwareDurableStageStore.hash("exact-compiled-GhidrAssist-JAR"),
            "68000:BE:32:CPU32",true);
    }
    public static void main(String[] args)throws Exception {
        Map<String,Long> outputs=Map.of("A0",0xfffa00L,"D0",0x40caL);
        Map<String,Long> altered=Map.of("A0",0xfffa68L,"D0",0x40caL);
        List<HardwareDataflow.Step> positive=graph(outputs),
            negative=graph(altered),
            unknown=graph(Map.of());
        Set<Long> targets=Set.of(0xfffa00L,0xfffa68L);
        String digest=HardwareFunctionStageCache.signature(positive,targets);
        String changed=HardwareFunctionStageCache.signature(negative,targets);
        String noSummary=HardwareFunctionStageCache.signature(unknown,targets);
        check(digest!=null && !digest.equals(changed) &&
            !digest.equals(noSummary) && !changed.equals(noSummary),
            "Post-CALL summary changes MUST change the translated CFG SHA");
        Map<String,Long> differentOrder=new LinkedHashMap<>();
        differentOrder.put("D0",0x40caL);
        differentOrder.put("A0",0xfffa00L);
        check(digest.equals(HardwareFunctionStageCache.signature(
            graph(differentOrder),targets)),
            "Function-cache hash of equivalent map outputs is order-independent");
        var result=HardwareDataflow.analyze(0x100,positive,targets,1000);
        check(!result.truncated && result.snapshots.size()==1 &&
            Long.valueOf(0xfffa00L).equals(result.snapshots.get(0).effectiveAddress) &&
            Integer.valueOf(0x40ca).equals(result.snapshots.get(0).writtenWord) &&
            result.snapshots.get(0).priorUnknownCall,
            "Proved callee constants survive CALL ABI clobber without clearing hazards");
        var different=HardwareDataflow.analyze(0x100,negative,targets,1000);
        check(different.snapshots.size()==1 &&
            Long.valueOf(0xfffa68L).equals(different.snapshots.get(0).effectiveAddress),
            "Changing only the callee post-return A0 changes downstream MMIO");
        var unproved=HardwareDataflow.analyze(0x100,unknown,targets,1000);
        check(unproved.snapshots.get(0).effectiveAddress==null &&
            unproved.snapshots.get(0).writtenWord==null,
            "No proven callee returns never inherit caller register constants");
        Object program=new Object();
        var cache=new HardwareFunctionStageCache<Object>();
        long generation=cache.begin(program);
        var scope=new HardwareFunctionStageCache.Scope(
            7,"68000:BE:32:CPU32","synthetic-import-sha",true);
        check(cache.put(program,generation,scope,0x100,1000,
            positive,targets,result),"Save bounded completed leaf/caller fixed point");
        check(cache.get(program,generation,scope,0x100,1000,
            positive,targets)==result,"Same exact proof may reuse fixed point");
        check(cache.get(program,generation,scope,0x100,1000,
            negative,targets)==null && cache.get(program,generation,scope,
            0x100,1000,unknown,targets)==null,
            "Neither changed nor withdrawn proof may reuse stale CFG cache");
        var slice=HardwareDataflow.analyzeSlice(
            0x100,positive,targets,1000,null,16);
        check(slice.complete()==null && slice.progress()!=null,
            "Mid-function progress is not a published completed result");
        var decoded=HardwareFunctionProgressCodec.decode(
            HardwareFunctionProgressCodec.encode(slice.progress())).orElseThrow();
        var resumed=HardwareDataflow.analyzeSlice(
            0x100,positive,targets,1000,decoded,1000);
        check(resumed.complete()!=null && !resumed.complete().truncated &&
            resumed.complete().snapshots.size()==result.snapshots.size() &&
            resumed.complete().snapshots.get(0).effectiveAddress.equals(
                result.snapshots.get(0).effectiveAddress) &&
            resumed.complete().snapshots.get(0).writtenWord.equals(
                result.snapshots.get(0).writtenWord) &&
            resumed.complete().knownPointersAtEntry.equals(
                result.knownPointersAtEntry),
            "Cross-CALL sliced fixed-point restart preserves cold source evidence");
        Path dir=Files.createTempDirectory("ga02-ga12-join-");
        try {
            check(HardwareDurableFunctionStages.save(
                dir,key("full-original-program"),0x100,1000,
                positive,targets,result),"Persist complete function under exact hash");
            check(HardwareDurableFunctionStages.load(
                dir,key("full-original-program"),0x100,1000,
                positive,targets).isPresent(),"Exact proven results may reopen");
            check(HardwareDurableFunctionStages.load(
                dir,key("full-original-program"),0x100,1000,
                negative,targets).isEmpty(),
                "Changed callee output MUST invalidate durable completed checkpoint");
            check(HardwareDurableFunctionStages.load(
                dir,key("full-original-program"),0x100,1000,
                unknown,targets).isEmpty(),
                "Lost callee proof MUST invalidate durable checkpoint");
            check(HardwareDurableFunctionStages.saveProgress(
                dir,key("full-original-program"),0x100,1000,
                positive,targets,decoded),
                "Finished disk slot may store pending work only for isolated test");
            check(HardwareDurableFunctionStages.loadProgress(
                dir,key("full-original-program"),0x100,1000,
                negative,targets).isEmpty(),
                "Changed callee evidence must not resume stale queued CFG state");
            check(HardwareDurableFunctionStages.loadProgress(
                dir,key("edited-Ghidra-Listing"),0x100,1000,
                positive,targets).isEmpty(),
                "Program edit makes old partial worklist unusable");
            check(HardwareDurableFunctionStages.loadProgress(
                dir,key("full-original-program"),0x100,1000,
                positive,targets).isPresent(),
                "Identical source/JAR/function and proof can resume pending state");
        }finally{
            try(var files=Files.list(dir)){
                for(Path entry:files.toList())Files.deleteIfExists(entry);
            }
            Files.deleteIfExists(dir);
        }
        // A source-matching disk envelope is an integrity check, NOT
        // semantic proof of its decoded contents. Even locally rehashed
        // binary snapshots must be checked against CURRENT translated
        // CALL/CFG nodes before restoring or overwriting a valid slot.
        Path adversarial=Files.createTempDirectory("ga02-ga12-source-gate-");
        try {
            var full=key("full-original-program");
            var site=result.snapshots.get(0);
            var changedKind=HardwareDataflow.Snapshot.restore(
                site.instruction,VBR_CONSTANT,site.effectiveAddress,
                site.writtenWord,site.writeBits,site.pointerRegister,site.vbr,
                site.knownPeripheralWords,false,site.priorMmCandidateMin,
                site.priorMmCandidateMax,site.priorUnknownCall,
                site.priorUnknownStore);
            var wrongKind=HardwareDataflow.Result.restore(
                List.of(changedKind),result.reachedNodes,result.iterations,
                result.knownPointersAtEntry);
            check(!HardwareDurableFunctionStages.save(adversarial,full,
                0x100,1000,positive,targets,wrongKind),
                "Cross-CALL STORE cannot be replaced by forged VBR evidence");
            var changedWidth=HardwareDataflow.Snapshot.restore(
                site.instruction,site.kind,site.effectiveAddress,
                site.writtenWord,8,site.pointerRegister,site.vbr,
                site.knownPeripheralWords,site.indirect,
                site.priorMmCandidateMin,site.priorMmCandidateMax,
                site.priorUnknownCall,site.priorUnknownStore);
            var wrongWidth=HardwareDataflow.Result.restore(
                List.of(changedWidth),result.reachedNodes,result.iterations,
                result.knownPointersAtEntry);
            check(!HardwareDurableFunctionStages.save(adversarial,full,
                0x100,1000,positive,targets,wrongWidth),
                "Saved STORE width must match the actual 16-bit source Step");
            var moved=HardwareDataflow.Snapshot.restore(
                0x900L,site.kind,site.effectiveAddress,site.writtenWord,
                site.writeBits,site.pointerRegister,site.vbr,
                site.knownPeripheralWords,site.indirect,
                site.priorMmCandidateMin,site.priorMmCandidateMax,
                site.priorUnknownCall,site.priorUnknownStore);
            var foreignPc=HardwareDataflow.Result.restore(
                List.of(moved),result.reachedNodes,result.iterations,
                result.knownPointersAtEntry);
            check(!HardwareDurableFunctionStages.save(adversarial,full,
                0x100,1000,positive,targets,foreignPc),
                "Off-graph MMIO source cannot be smuggled into a completed checkpoint");
            var partialCount=HardwareDataflow.Result.restore(
                result.snapshots,result.reachedNodes-1,result.iterations,
                result.knownPointersAtEntry);
            check(!HardwareDurableFunctionStages.save(adversarial,full,
                0x100,1000,positive,targets,partialCount),
                "Forgeable visited-node count must match closed source CFG");
            var roguePointers=new LinkedHashMap<>(
                result.knownPointersAtEntry);
            roguePointers.put(0x900L,Map.of("A0",0xfffa00L));
            var rogueState=HardwareDataflow.Result.restore(
                result.snapshots,result.reachedNodes,result.iterations,
                roguePointers);
            check(!HardwareDurableFunctionStages.save(adversarial,full,
                0x100,1000,positive,targets,rogueState),
                "Unreachable register state cannot authorize downstream SIMCR evidence");
            var highPointer=new LinkedHashMap<>(
                result.knownPointersAtEntry);
            highPointer.put(0x106L,Map.of("A0",0x1000000L));
            var impossiblePointer=HardwareDataflow.Result.restore(
                result.snapshots,result.reachedNodes,result.iterations,
                highPointer);
            check(!HardwareDurableFunctionStages.save(adversarial,full,
                0x100,1000,positive,targets,impossiblePointer),
                "Persisted A0 values must fit the explicitly modeled 24-bit source");
            var badPeripherals=new LinkedHashMap<>(
                site.knownPeripheralWords);
            badPeripherals.put(0x1000000L,1);
            var bogusMmio=HardwareDataflow.Snapshot.restore(
                site.instruction,site.kind,site.effectiveAddress,
                site.writtenWord,site.writeBits,site.pointerRegister,
                site.vbr,badPeripherals,site.indirect,
                site.priorMmCandidateMin,site.priorMmCandidateMax,
                site.priorUnknownCall,site.priorUnknownStore);
            var bogusMmioResult=HardwareDataflow.Result.restore(
                List.of(bogusMmio),result.reachedNodes,result.iterations,
                result.knownPointersAtEntry);
            check(!HardwareDurableFunctionStages.save(adversarial,full,
                0x100,1000,positive,targets,bogusMmioResult),
                "High 32-bit peripheral state cannot be restored as MC68332 evidence");

            check(HardwareDurableFunctionStages.save(adversarial,full,
                0x100,1000,positive,targets,result) &&
                HardwareDurableFunctionStages.load(adversarial,full,
                    0x100,1000,positive,targets).isPresent(),
                "Valid complete verified CALL result survives strict source-bound restore");

            // Test a correct outer SHA-256 and matching full-input envelope
            // containing a *semantic* lie. Reflection is limited to the
            // pure-Java test to derive the private exact key; no real
            // Program/firmware/authorization object is accessed.
            var keyMethod=HardwareDurableFunctionStages.class
                .getDeclaredMethod("key",
                    HardwareDurableStageStore.Key.class,long.class,
                    int.class,java.util.Collection.class,java.util.Collection.class);
            keyMethod.setAccessible(true);
            var derived=(HardwareDurableStageStore.Key)keyMethod.invoke(
                null,full,0x100L,1000,positive,targets);
            HardwareDurableStageStore.save(adversarial,derived,
                HardwareFunctionResultCodec.encode(wrongKind));
            check(HardwareDurableFunctionStages.load(adversarial,full,
                    0x100,1000,positive,targets).isEmpty(),
                "Rehashed matching disk envelope cannot launder VBR-for-STORE");
            HardwareDurableStageStore.save(adversarial,derived,
                HardwareFunctionResultCodec.encode(foreignPc));
            check(HardwareDurableFunctionStages.load(adversarial,full,
                    0x100,1000,positive,targets).isEmpty(),
                "Rehashed matching envelope cannot launder a foreign MMIO PC");

            var extraNodes=new LinkedHashMap<>(decoded.atEntry());
            extraNodes.put(0x900L,new HardwareDataflow.EntryState(
                Map.of("A0",0xfffa00L),Map.of(),null,0,0,false,false));
            var alienProgress=new HardwareDataflow.Progress(
                0x100L,1000,decoded.iterations(),
                extraNodes,decoded.pending());
            check(!HardwareDurableFunctionStages.saveProgress(
                adversarial,full,0x100,1000,positive,targets,alienProgress),
                "Cannot overwrite valid disk slot with off-CFG saved CALL worklist");
            HardwareDurableStageStore.save(adversarial,derived,
                HardwareFunctionProgressCodec.encode(alienProgress));
            check(HardwareDurableFunctionStages.loadProgress(
                adversarial,full,0x100,1000,positive,targets).isEmpty(),
                "Rehashed off-graph partial checkpoint must be refused on restart");

            check(HardwareDurableFunctionStages.saveProgress(
                    adversarial,full,0x100,1000,positive,targets,decoded) &&
                HardwareDurableFunctionStages.loadProgress(
                    adversarial,full,0x100,1000,positive,targets).isPresent(),
                "Legitimate incomplete verified-CALL source worklist still resumes");

            var unreachableStep=new ArrayList<>(positive);
            unreachableStep.add(new HardwareDataflow.Step(
                0x900L,STORE_DIRECT,null,0xfffa00L,0,
                0x40ca,16,List.of(),"unreachable synthetic MMIO"));
            var bogusReachable=new LinkedHashMap<>(decoded.atEntry());
            bogusReachable.put(0x900L,new HardwareDataflow.EntryState(
                Map.of(),Map.of(),null,0,0,false,false));
            var graphOrphan=new HardwareDataflow.Progress(
                0x100L,1000,decoded.iterations(),
                bogusReachable,decoded.pending());
            check(!HardwareDurableFunctionStages.saveProgress(
                adversarial,full,0x100,1000,unreachableStep,targets,graphOrphan),
                "Declared but UNREACHABLE source Step must not revive forged MMIO progress");
            check(!HardwareDurableFunctionStages.save(adversarial,full,
                0x100,1000,unreachableStep,targets,foreignPc),
                "Declared disconnected source cannot satisfy a saved MMIO write witness");
        }finally{
            try(var files=Files.list(adversarial)) {
                for(Path entry:files.toList())Files.deleteIfExists(entry);
            }
            Files.deleteIfExists(adversarial);
        }
        check(HardwareDataflow.mayTouchSimcrMmLowByte(0xfffa00L,16) &&
              HardwareDataflow.mayTouchSimcrMmLowByte(0xfff9ffL,32) &&
              !HardwareDataflow.mayTouchSimcrMmLowByte(0xfffa02L,16),
            "MC68332 overlapping SIMCR MM source guard survives GA-12 integration");
        System.out.println("HardwareCallCheckpointIntegrationSelfTest OK");
    }
}
