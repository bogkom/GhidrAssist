package ghidrassist.hardware;

import java.nio.file.*;
import java.util.*;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

public final class HardwareDataflowSliceSelfTest {
    private HardwareDataflowSliceSelfTest(){}
    private static void check(boolean ok,String message){
        if(!ok)throw new AssertionError(message);
    }
    private static List<HardwareDataflow.Step> graph(){
        List<HardwareDataflow.Step> steps=new ArrayList<>();
        steps.add(new HardwareDataflow.Step(0x100L,SET_POINTER,
            "A0",0xfffa00L,0,null,0,List.of(0x106L),"MOVEA.L"));
        steps.add(new HardwareDataflow.Step(0x106L,SET_POINTER,
            "D0",0x40caL,0,null,0,List.of(0x10cL),"MOVE.L"));
        for(long pc=0x10cL;pc<0x184L;pc+=2)
            steps.add(new HardwareDataflow.Step(pc,OTHER,null,
                0,0,null,0,List.of(pc+2),"NOP"));
        steps.add(new HardwareDataflow.Step(0x184L,STORE_INDIRECT,
            "A0","D0",0,0,null,16,List.of(0x186L),"MOVE.W D0,(A0)"));
        steps.add(new HardwareDataflow.Step(0x186L,OTHER,null,
            0,0,null,0,List.of(),"RTS"));
        return steps;
    }
    public static void main(String[] args)throws Exception{
        var steps=graph();
        Set<Long> targets=Set.of(0xfffa00L,0xfffa68L);
        var cold=HardwareDataflow.analyze(0x100,steps,targets,1000);
        check(!cold.truncated && cold.snapshots.size()==1 &&
            cold.snapshots.get(0).effectiveAddress==0xfffa00L &&
            Integer.valueOf(0x40ca).equals(cold.snapshots.get(0).writtenWord),
            "cold fixed-point reference");
        HardwareDataflow.Progress progress=null;
        int slices=0;
        while(true){
            var slice=HardwareDataflow.analyzeSlice(
                0x100,steps,targets,1000,progress,7);
            if(slice.complete()!=null){
                var resumed=slice.complete();
                check(!resumed.truncated &&
                    resumed.iterations==cold.iterations &&
                    resumed.reachedNodes==cold.reachedNodes &&
                    resumed.knownPointersAtEntry.equals(cold.knownPointersAtEntry) &&
                    resumed.snapshots.size()==cold.snapshots.size() &&
                    resumed.snapshots.get(0).effectiveAddress.equals(
                        cold.snapshots.get(0).effectiveAddress) &&
                    resumed.snapshots.get(0).writtenWord.equals(
                        cold.snapshots.get(0).writtenWord) &&
                    resumed.snapshots.get(0).priorMmCandidateMin==
                        cold.snapshots.get(0).priorMmCandidateMin &&
                    resumed.snapshots.get(0).priorMmCandidateMax==
                        cold.snapshots.get(0).priorMmCandidateMax,
                    "sliced and original complete fixed point must be identical");
                break;
            }
            check(slice.progress()!=null && ++slices<50,
                "each bounded quantum is pending, not finished evidence");
            byte[] encoded=HardwareFunctionProgressCodec.encode(slice.progress());
            progress=HardwareFunctionProgressCodec.decode(encoded).orElseThrow();
            check(Arrays.equals(encoded,HardwareFunctionProgressCodec.encode(progress)),
                "worklist roundtrip preserves exact queue and state");
            check(HardwareFunctionProgressCodec.decode(
                Arrays.copyOf(encoded,encoded.length-1)).isEmpty(),
                "truncated worklist is never a valid progress checkpoint");
            check(HardwareFunctionProgressCodec.decode(
                Arrays.copyOf(encoded,encoded.length+1)).isEmpty(),
                "unknown trailing fields fail closed");
        }
        check(slices>=2,"must cross more than one independent quantum");
        var capped=HardwareDataflow.analyzeSlice(0x100,steps,targets,4,null,4);
        check(capped.complete()!=null && capped.complete().truncated &&
            capped.complete().snapshots.isEmpty() && capped.progress()==null,
            "exhausted iteration budget never leaks partial source evidence");
        Path privateDir=Files.createTempDirectory("ga12-progress-test-");
        try{
            var identity=new HardwareDurableStageStore.Key(
                HardwareDurableStageStore.hash("synthetic-project"),
                HardwareDurableStageStore.hash("synthetic-BIN"),
                HardwareDurableStageStore.hash("synthetic-Ghidra-input"),
                HardwareDurableStageStore.hash("synthetic-JAR"),
                "68000:BE:32:CPU32",true);
            var partial=HardwareDataflow.analyzeSlice(
                0x100,steps,targets,1000,null,7).progress();
            check(HardwareDurableFunctionStages.saveProgress(
                privateDir,identity,0x100,1000,steps,targets,partial),
                "completed quantum can persist without claiming full completion");
            check(HardwareDurableFunctionStages.load(
                privateDir,identity,0x100,1000,steps,targets).isEmpty(),
                "partial worklist must NEVER decode as finished function");
            check(HardwareDurableFunctionStages.loadProgress(
                privateDir,identity,0x100,1000,steps,targets).isPresent(),
                "same isolated input and Step signature restores worklist");
            var differentStep=new ArrayList<>(steps);
            differentStep.set(0,new HardwareDataflow.Step(0x100L,
                SET_POINTER,"A0",0x7ffa00L,0,null,0,List.of(0x106L),"MOVEA.L"));
            check(HardwareDurableFunctionStages.loadProgress(privateDir,
                identity,0x100,1000,differentStep,targets).isEmpty(),
                "modified translated CFG invalidates partial queue");
            var changedInput=new HardwareDurableStageStore.Key(
                identity.programIdSha256(),identity.importedSha256(),
                HardwareDurableStageStore.hash("edited Listing"),identity.analyzerSha256(),
                identity.language(),true);
            check(HardwareDurableFunctionStages.loadProgress(privateDir,
                changedInput,0x100,1000,steps,targets).isEmpty(),
                "modified Ghidra Listing must reject partial progress");
            check(HardwareDurableFunctionStages.loadProgress(privateDir,
                identity,0x100,1001,steps,targets).isEmpty(),
                "iteration budget change invalidates partial worklist");
            var otherMCU=new HardwareDurableStageStore.Key(
                identity.programIdSha256(),identity.importedSha256(),
                identity.inputSha256(),identity.analyzerSha256(),
                identity.language(),false);
            check(HardwareDurableFunctionStages.loadProgress(privateDir,
                otherMCU,0x100,1000,steps,targets).isEmpty(),
                "generic CPU32 cannot load MC68332 checkpoint");
            HardwareDurableFunctionStages.save(privateDir,identity,0x100,
                1000,steps,targets,cold);
            check(HardwareDurableFunctionStages.loadProgress(
                privateDir,identity,0x100,1000,steps,targets).isEmpty() &&
                HardwareDurableFunctionStages.load(
                privateDir,identity,0x100,1000,steps,targets).isPresent(),
                "complete fixed point replaces pending worklist, never vice versa");
        }finally{
            try(var list=Files.list(privateDir))
                {for(Path entry:list.toList())Files.deleteIfExists(entry);}
            Files.deleteIfExists(privateDir);
        }
        System.out.println("HardwareDataflowSliceSelfTest OK");
    }
}
