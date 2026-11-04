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
        check(cache.get(first,fresh,scope,0x100,100,graph,targets)==null,
            "oldest completed stages are evicted deterministically");
        System.out.println("HardwareFunctionStageCacheSelfTest OK");
    }
}
