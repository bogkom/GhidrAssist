package ghidrassist.hardware;

import java.nio.file.*;
import java.util.*;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

public final class HardwareDurableFunctionStagesSelfTest {
    private HardwareDurableFunctionStagesSelfTest(){}
    private static void check(boolean yes,String reason){
        if(!yes)throw new AssertionError(reason);
    }
    private static HardwareDataflow.Step step(long at,HardwareDataflow.Kind kind,
            String reg,long operand,int bits,Long... next){
        return new HardwareDataflow.Step(at,kind,reg,operand,0,
            kind==STORE_INDIRECT?0x40ca:null,bits,List.of(next),"synthetic");
    }
    public static void main(String[] args)throws Exception{
        Path temp=Files.createTempDirectory("ga12-func-durable-");
        try{
            String id=HardwareDurableStageStore.hash("isolated-project");
            String imported=HardwareDurableStageStore.hash("original-synthetic-bin");
            String listing=HardwareDurableStageStore.hash("full-Ghidra-Listing-v1");
            String jar=HardwareDurableStageStore.hash("extension-JAR-v1");
            var key=new HardwareDurableStageStore.Key(id,imported,listing,
                jar,"68000:BE:32:CPU32",true);
            var steps=List.of(
                step(0x100,SET_POINTER,"A0",0xfffa00L,0,0x102L),
                step(0x102,STORE_INDIRECT,"A0",0,16,0x104L),
                step(0x104,OTHER,null,0,0));
            Set<Long> targets=Set.of(0xfffa00L,0xfffa68L);
            var computed=HardwareDataflow.analyze(0x100,steps,targets,100);
            check(!computed.truncated && computed.snapshots.size()==1 &&
                computed.snapshots.get(0).effectiveAddress==0xfffa00L,
                "source-only function precondition");
            byte[] encoded=HardwareFunctionResultCodec.encode(computed);
            var loaded=HardwareFunctionResultCodec.decode(encoded).orElseThrow();
            check(Arrays.equals(HardwareFunctionResultCodec.encode(loaded),encoded),
                "typed codec roundtrip must preserve all fixed-point fields");
            check(loaded.snapshots.get(0).priorMmCandidateMin==
                    computed.snapshots.get(0).priorMmCandidateMin &&
                loaded.snapshots.get(0).priorMmCandidateMax==
                    computed.snapshots.get(0).priorMmCandidateMax &&
                loaded.snapshots.get(0).knownPeripheralWords.equals(
                    computed.snapshots.get(0).knownPeripheralWords) &&
                loaded.knownPointersAtEntry.equals(computed.knownPointersAtEntry),
                "MM candidate epoch, peripherals and predecessor registers survive");
            check(HardwareFunctionResultCodec.decode(
                Arrays.copyOf(encoded,encoded.length-2)).isEmpty(),
                "truncated fixed point fails closed");
            byte[] trailing=Arrays.copyOf(encoded,encoded.length+1);
            check(HardwareFunctionResultCodec.decode(trailing).isEmpty(),
                "trailing unrecognized fields fail closed");
            check(HardwareDurableFunctionStages.load(
                temp,key,0x100,100,steps,targets).isEmpty(),
                "first Ghidra process must compute");
            check(HardwareDurableFunctionStages.save(
                temp,key,0x100,100,steps,targets,computed),
                "a complete fixed point can be saved to isolated directory");
            check(HardwareDurableFunctionStages.load(
                temp,key,0x100,100,steps,targets).isPresent(),
                "independent pure-Java load uses exact key");
            check(HardwareDurableFunctionStages.load(
                temp,key,0x100,101,steps,targets).isEmpty(),
                "fixed-point iteration budget affects digest");
            var editedStep=List.of(
                step(0x100,SET_POINTER,"A0",0xfffa02L,0,0x102L),
                steps.get(1),steps.get(2));
            check(HardwareDurableFunctionStages.load(
                temp,key,0x100,100,editedStep,targets).isEmpty(),
                "changed translated CFG must not restore stale result");
            var changedListing=new HardwareDurableStageStore.Key(
                id,imported,HardwareDurableStageStore.hash("edited Ghidra bytes"),
                jar,"68000:BE:32:CPU32",true);
            check(HardwareDurableFunctionStages.load(
                temp,changedListing,0x100,100,steps,targets).isEmpty(),
                "edited Listing with unchanged original import SHA fails closed");
            var differentEngine=new HardwareDurableStageStore.Key(
                id,imported,listing,
                HardwareDurableStageStore.hash("new analyzer JAR"),
                "68000:BE:32:CPU32",true);
            check(HardwareDurableFunctionStages.load(
                temp,differentEngine,0x100,100,steps,targets).isEmpty(),
                "changed installed extension invalidates function results");
            var generic=new HardwareDurableStageStore.Key(id,imported,listing,
                jar,"68000:BE:32:CPU32",false);
            check(HardwareDurableFunctionStages.load(
                temp,generic,0x100,100,steps,targets).isEmpty(),
                "generic CPU32 never reuses MC68332 stage");
            var changedProject=new HardwareDurableStageStore.Key(
                HardwareDurableStageStore.hash("another-project"),imported,
                listing,jar,"68000:BE:32:CPU32",true);
            check(HardwareDurableFunctionStages.load(
                temp,changedProject,0x100,100,steps,targets).isEmpty(),
                "same BIN from another project is a distinct identity");
            var truncated=HardwareDataflow.analyze(0x100,steps,targets,1);
            check(truncated.truncated && !HardwareDurableFunctionStages.save(
                temp,key,0x100,1,steps,targets,truncated),
                "unfinished fixed point cannot persist");
            check(!HardwareDurableFunctionStages.save(
                temp,key,0x100,100,null,targets,computed),
                "missing translated Steps are never a checkpoint key");
            Path path;
            try(var files=Files.list(temp)){path=files.findFirst().orElseThrow();}
            byte[] snapshot=Files.readAllBytes(path);
            byte[] corrupt=snapshot.clone();corrupt[corrupt.length-40]^=0x7f;
            Files.write(path,corrupt);
            check(HardwareDurableFunctionStages.load(
                temp,key,0x100,100,steps,targets).isEmpty(),
                "tampered bytes never decoded as completed function");
            Files.write(path,snapshot);
            check(HardwareDurableFunctionStages.load(
                temp,key,0x100,100,steps,targets).isPresent(),
                "repaired complete checkpoint remains available");
            // The disk slot is stable for (project,function), but its
            // embedded signature must distinguish UNKNOWN from signed -1.
            // Old GA12 signature v2 encoded BOTH as the integer -1.
            var missingWord=List.of(steps.get(0),
                new HardwareDataflow.Step(0x102,STORE_INDIRECT,
                    "A0",0,0,null,16,List.of(0x104L),"synthetic"),
                steps.get(2));
            var signedMinusOne=List.of(steps.get(0),
                new HardwareDataflow.Step(0x102,STORE_INDIRECT,
                    "A0",0,0,-1,16,List.of(0x104L),"synthetic"),
                steps.get(2));
            var unknownProof=HardwareDataflow.analyze(
                0x100,missingWord,targets,100);
            var knownProof=HardwareDataflow.analyze(
                0x100,signedMinusOne,targets,100);
            check(unknownProof.snapshots.get(0).writtenWord==null &&
                knownProof.snapshots.get(0).writtenWord==0xffff,
                "disk-cache collision fixtures differ in hardware evidence");
            check(HardwareDurableFunctionStages.save(
                temp,key,0x100,100,missingWord,targets,unknownProof),
                "save missing-literal proof in stable per-function slot");
            check(HardwareDurableFunctionStages.load(
                temp,key,0x100,100,signedMinusOne,targets).isEmpty(),
                "signed -1 must NOT read UNKNOWN-source disk checkpoint");
            check(HardwareDurableFunctionStages.save(
                temp,key,0x100,100,signedMinusOne,targets,knownProof),
                "save signed -1 proof in the same stable function slot");
            check(HardwareDurableFunctionStages.load(
                temp,key,0x100,100,missingWord,targets).isEmpty(),
                "UNKNOWN source must NOT read concrete 0xFFFF checkpoint");
            check(HardwareDurableFunctionStages.load(
                temp,key,0x100,100,signedMinusOne,targets).isPresent(),
                "current exact signed-source checkpoint can be restored");
            System.out.println("HardwareDurableFunctionStagesSelfTest OK");
        }finally{
            try(var files=Files.list(temp)){
                for(Path entry:files.toList())Files.deleteIfExists(entry);
            }
            Files.delete(temp);
        }
    }
}
