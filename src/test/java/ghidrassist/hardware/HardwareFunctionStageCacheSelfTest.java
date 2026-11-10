package ghidrassist.hardware;

import java.util.List;
import java.util.Set;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

public final class HardwareFunctionStageCacheSelfTest {
    private HardwareFunctionStageCacheSelfTest(){}
    private static void check(boolean yes,String message){
        if(!yes)throw new AssertionError(message);
    }
    private static HardwareDataflow.Step step(long at,HardwareDataflow.Kind kind,
            String register,long operand,long displacement,Integer word,
            int bits,Long... targets){
        return new HardwareDataflow.Step(at,kind,register,operand,displacement,
            word,bits,List.of(targets),"synthetic");
    }
    public static void main(String[] args){
        Object first=new Object(),second=new Object();
        var cache=new HardwareFunctionStageCache<Object>();
        var scope=new HardwareFunctionStageCache.Scope(
            3,"68000:BE:32:CPU32","synthetic-import",true);
        List<HardwareDataflow.Step> graph=List.of(
            step(0x100,SET_POINTER,"A0",0xfffa00,0,null,0,0x102L),
            step(0x102,STORE_INDIRECT,"A0",0,0,0x40ca,16,0x104L),
            step(0x104,OTHER,null,0,0,null,0));
        Set<Long> targets=Set.of(0xfffa00L);
        long generation=cache.begin(first);
        check(cache.get(first,generation,scope,0x100,100,graph,targets)==null,
            "first function must compute");
        var computed=HardwareDataflow.analyze(0x100,graph,targets,100);
        check(computed.snapshots.size()==1 &&
            computed.snapshots.get(0).effectiveAddress==0xfffa00L,
            "synthetic source-level SIMCR site");
        check(cache.put(first,generation,scope,0x100,100,graph,targets,computed),
            "completed function gets a checkpoint");
        check(cache.get(first,generation,scope,0x100,100,graph,targets)==computed,
            "same Program/revision/input can reuse completed fixed point");
        check(cache.get(second,cache.begin(second),scope,0x100,100,graph,targets)==null,
            "separate Program instance cannot reuse a stage");
        // A partially decoded peripheral target list must never throw
        // from TreeSet(Collection) or overwrite an otherwise valid stage.
        var unknownTargets=java.util.Arrays.asList(0xfffa00L,(Long)null);
        check(HardwareFunctionStageCache.signature(graph,unknownTargets)==null,
            "null tracked target must be uncached, not a sort exception");
        check(cache.get(first,generation,scope,0x100,100,graph,
            unknownTargets)==null,
            "incomplete target identity cannot reuse complete CFG evidence");
        check(!cache.put(first,generation,scope,0x100,100,graph,
            unknownTargets,computed),
            "unknown tracked target must not publish completed evidence");
        check(cache.get(first,generation,scope,0x100,100,graph,targets)==computed,
            "rejected unknown input preserves already validated cache stage");
        var bounded=new java.util.ArrayList<Long>();
        for(long address=0;address<HardwareFunctionStageCache.MAX_TRACKED_ADDRESSES;
                address++)bounded.add(address);
        check(HardwareFunctionStageCache.signature(graph,bounded)!=null,
            "the documented tracked-target boundary remains eligible");
        bounded.add((long)HardwareFunctionStageCache.MAX_TRACKED_ADDRESSES);
        check(HardwareFunctionStageCache.signature(graph,bounded)==null,
            "oversized tracked-target source rejects without hashing/sorting");
        check(!cache.put(first,generation,scope,0x100,100,graph,
            bounded,computed),
            "oversized target input cannot persist a function checkpoint");

        Object equalA=new String("equal-owner"),equalB=new String("equal-owner");
        check(equalA!=equalB && equalA.equals(equalB),
            "synthetic equal-but-distinct owner precondition");
        long firstToken=cache.begin(equalA);
        check(cache.put(equalA,firstToken,scope,0x100,100,graph,targets,computed),
            "equal-owner identity test installed first Program's stage");
        long secondToken=cache.begin(equalB);
        check(cache.get(equalB,secondToken,scope,0x100,100,graph,targets)==null &&
            cache.completed(equalB)==0,
            "equal-but-distinct owners must never share a fixed-point snapshot");
        check(cache.get(first,generation,scope,0x100,101,graph,targets)==null,
            "iteration budget is part of fixed-point identity");
        check(cache.get(first,generation,scope,0x130,100,graph,targets)==null,
            "another function entry never inherits an unrelated fixed point");
        check(cache.get(first,generation,scope,0x100,100,graph,
            Set.of(0xfffa00L,0xfffa68L))==null,
            "changed peripheral target set invalidates previous result");
        var changed=List.of(
            step(0x100,SET_POINTER,"A0",0x7ffa00,0,null,0,0x102L),
            graph.get(1),graph.get(2));
        check(cache.get(first,generation,scope,0x100,100,changed,targets)==null,
            "different function instruction value invalidates cache");
        var changedEdges=List.of(
            step(0x100,SET_POINTER,"A0",0xfffa00,0,null,0,0x104L),
            graph.get(1),graph.get(2));
        check(cache.get(first,generation,scope,0x100,100,changedEdges,targets)==null,
            "different CFG edge invalidates cache");
        var sideEffects=List.of(graph.get(0),
            graph.get(1).withSideEffects(Set.of("A0")),graph.get(2));
        check(cache.get(first,generation,scope,0x100,100,sideEffects,targets)==null,
            "implicit register mutation participates in input fingerprint");
        // Regression: the old -1 sentinel made an absent STORE literal
        // hash-identical to the valid signed immediate -1 (MOVE.W #$FFFF).
        // Both have the same entry, CFG and successors but different proof.
        var unknownLiteral=List.of(graph.get(0),
            new HardwareDataflow.Step(0x102,STORE_INDIRECT,"A0",
                0,0,null,16,List.of(0x104L),"synthetic"),graph.get(2));
        var negativeLiteral=List.of(graph.get(0),
            new HardwareDataflow.Step(0x102,STORE_INDIRECT,"A0",
                0,0,-1,16,List.of(0x104L),"synthetic"),graph.get(2));
        check(!HardwareFunctionStageCache.signature(unknownLiteral,targets)
            .equals(HardwareFunctionStageCache.signature(negativeLiteral,targets)),
            "missing literal and valid signed -1 must have distinct CFG SHA");
        var unknownProof=HardwareDataflow.analyze(
            0x100,unknownLiteral,targets,100);
        var signedProof=HardwareDataflow.analyze(
            0x100,negativeLiteral,targets,100);
        check(unknownProof.snapshots.get(0).writtenWord==null &&
            signedProof.snapshots.get(0).writtenWord==0xffff,
            "UNKNOWN source and concrete 0xFFFF have different evidence");
        var isolated=new HardwareFunctionStageCache<Object>();
        Object isolatedProgram=new Object();
        long isolatedEpoch=isolated.begin(isolatedProgram);
        check(isolated.put(isolatedProgram,isolatedEpoch,scope,0x100,100,
            unknownLiteral,targets,unknownProof),
            "UNKNOWN-source function may be separately checkpointed");
        check(isolated.get(isolatedProgram,isolatedEpoch,scope,0x100,100,
            negativeLiteral,targets)==null,
            "known signed literal must never reuse UNKNOWN-source cache");
        check(isolated.put(isolatedProgram,isolatedEpoch,scope,0x100,100,
            negativeLiteral,targets,signedProof),
            "known signed literal may be separately checkpointed");
        check(isolated.get(isolatedProgram,isolatedEpoch,scope,0x100,100,
            unknownLiteral,targets)==null,
            "UNKNOWN source must never inherit the known 0xFFFF cache");
        var differentProfile=new HardwareFunctionStageCache.Scope(
            3,"68000:BE:32:CPU32","synthetic-import",false);
        check(cache.get(first,generation,differentProfile,0x100,100,graph,targets)==null,
            "MCU profile change invalidates prior partial results");
        check(cache.completed(first)==0,
            "scope mismatch must clear all previous function results");
        check(cache.put(first,generation,scope,0x100,100,graph,targets,computed),
            "same Program can compute afresh after profile switch");
        var changedRevision=new HardwareFunctionStageCache.Scope(
            4,"68000:BE:32:CPU32","synthetic-import",true);
        check(cache.get(first,generation,changedRevision,0x100,100,graph,targets)==null,
            "edit/Undo/Redo invalidates old function result");
        check(cache.completed(first)==0,
            "new Program modification counter must not keep stale stages");
        var incomplete=HardwareDataflow.analyze(0x100,graph,targets,1);
        check(incomplete.truncated && !cache.put(
            first,generation,scope,0x100,1,graph,targets,incomplete),
            "truncated fixed-point cannot become an eligible checkpoint");
        cache.put(first,generation,scope,0x100,100,graph,targets,computed);
        cache.invalidate(first);
        check(cache.completed(first)==0 && cache.get(
            first,generation,scope,0x100,100,graph,targets)==null,
            "explicit invalidation clears cached stages and their generation");
        check(!cache.put(first,generation,scope,0x100,100,graph,targets,computed),
            "old cancelled worker cannot republish after invalidation");
        long fresh=cache.begin(first);
        check(fresh!=generation && cache.put(first,fresh,scope,
            0x100,100,graph,targets,computed),
            "new valid work can create a fresh stage");
        for(int i=0;i<HardwareFunctionStageCache.MAX_FUNCTIONS+12;i++){
            long entry=0x200L+i*16;
            cache.put(first,fresh,scope,entry,100,graph,targets,computed);
        }
        check(cache.completed(first)==HardwareFunctionStageCache.MAX_FUNCTIONS,
            "per-Program bound prevents unbounded function checkpoint memory");
        check(cache.get(first,fresh,scope,0x100,100,graph,targets)==computed,
            "first completed functions stay reusable after cache reaches cap");
        long last=0x200L+(HardwareFunctionStageCache.MAX_FUNCTIONS+11L)*16;
        check(cache.get(first,fresh,scope,last,100,graph,targets)==null,
            "overflow functions recompute instead of displacing earlier work");
        // Weak or hostile import identities are not a durable source
        // witness. Do not replay a complete function fixed point on the
        // basis of a missing/UNKNOWN profile import label alone.
        var weak=new HardwareFunctionStageCache.Scope(
            3,"68000:BE:32:CPU32",null,true);
        var unknown=new HardwareFunctionStageCache.Scope(
            3,"68000:BE:32:CPU32","UNKNOWN",true);
        var blank=new HardwareFunctionStageCache.Scope(
            3,"68000:BE:32:CPU32","  ",true);
        long weakEpoch=cache.begin(first);
        for(var invalidScope:List.of(weak,unknown,blank)) {
            check(!cache.put(first,weakEpoch,invalidScope,0x100,100,
                    graph,targets,computed) &&
                cache.get(first,weakEpoch,invalidScope,0x100,100,
                    graph,targets)==null,
                "weak source identity cannot publish or reuse function checkpoint");
        }
        check(cache.get(first,weakEpoch,scope,0x100,100,graph,targets)==computed,
            "rejected weak scope must not evict a valid source checkpoint");
        var newScope=new HardwareFunctionStageCache.Scope(
            3,"68000:BE:32:CPU32","new-import-source",true);
        check(cache.get(first,weakEpoch,newScope,0x100,100,graph,targets)==null,
            "changed nonempty import source invalidates completed function");
        check(cache.completed(first)==0,
            "changed import identity removes stale in-memory source evidence");
        for(String forbiddenLabel:List.of(
                "68000:BE:32:CPU32\nSPOOF","68000:BE:32:CPU32\u202e",
                "x".repeat(129))) {
            boolean rejected=false;
            try {new HardwareFunctionStageCache.Scope(
                3,forbiddenLabel,"synthetic-import",true);}
            catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"invalid language metadata cannot spoof checkpoint identity");
        }
        for(String forbiddenImport:List.of(
                "source\rSPOOF","source\u2066", "x".repeat(257))) {
            boolean rejected=false;
            try {new HardwareFunctionStageCache.Scope(
                3,"68000:BE:32:CPU32",forbiddenImport,true);}
            catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"unsafe import label cannot define a resumable checkpoint");
        }
        System.out.println("HardwareFunctionStageCacheSelfTest OK");
    }
}
