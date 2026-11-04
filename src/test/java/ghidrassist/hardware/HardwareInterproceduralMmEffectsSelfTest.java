package ghidrassist.hardware;

import java.util.List;

public final class HardwareInterproceduralMmEffectsSelfTest {
    private HardwareInterproceduralMmEffectsSelfTest(){}
    private static void ok(boolean b,String why){if(!b)throw new AssertionError(why);}
    private static HardwareInterproceduralMmEffects.FunctionNode node(
            long id,boolean mm,boolean alias,boolean unknown,Long... calls){
        return new HardwareInterproceduralMmEffects.FunctionNode(
            id,mm,alias,unknown,List.of(calls));
    }
    private static HardwareInterproceduralMmEffects.CallSite call(
            long caller,long pc,Long callee){
        return new HardwareInterproceduralMmEffects.CallSite(caller,pc,callee);
    }
    private static HardwareInterproceduralMmEffects.Report run(
            List<HardwareInterproceduralMmEffects.FunctionNode> graph,
            List<HardwareInterproceduralMmEffects.CallSite> sites,
            int depth,int count,int maxRows){
        return HardwareInterproceduralMmEffects.analyze(
            graph,sites,List.of(0x100L),depth,count,maxRows);
    }
    public static void main(String[] ignored){
        var diamond=List.of(
            node(0x100,false,false,false,0x130L,0x160L),
            node(0x130,false,false,false,0x190L),
            node(0x160,false,false,false,0x190L),
            node(0x190,true,false,false));
        var calls=List.of(call(0x100,0x108,0x130L),
            call(0x100,0x110,0x160L));
        var evidence=run(diamond,calls,4,20,20);
        ok(evidence.rows().size()==2 &&
            evidence.rows().get(0).summary().mayMm() &&
            evidence.rows().get(0).summary().visited()==2 &&
            !evidence.rows().get(0).summary().cycle() &&
            !evidence.rows().get(0).summary().unknownControl(),
            "convergent static CALL paths expose shared may-MM site");
        ok(evidence.markdown().contains("NOT execution") &&
            evidence.markdown().contains("latched MM"),
            "no runtime/latched-MM inference");
        var missing=run(List.of(node(0x100,false,false,false)),
            List.of(calls.get(0)),4,20,20);
        ok(missing.rows().get(0).summary().unknownControl(),
            "missing callee must not be interpreted as pure");
        var alias=run(List.of(node(0x130,false,true,false)),
            List.of(calls.get(0)),4,20,20);
        ok(alias.rows().get(0).summary().unknownAlias() &&
            alias.rows().get(0).summary().uncertainOrMm(),
            "unknown effective STORE address may alias SIMCR");
        var indirect=run(diamond,List.of(call(0x100,0x108,null)),4,20,20);
        ok(indirect.rows().get(0).summary().unknownControl(),
            "indirect unresolved CALL remains unknown");
        var cycle=run(List.of(node(0x130,false,false,false,0x160L),
            node(0x160,false,false,false,0x130L)),
            List.of(calls.get(0)),4,20,20);
        ok(cycle.rows().get(0).summary().cycle() &&
            cycle.rows().get(0).summary().unknownControl(),
            "cyclic call graph not classified closed");
        var depth=run(diamond,List.of(calls.get(0)),0,20,20);
        ok(depth.rows().get(0).summary().limited() &&
            !depth.rows().get(0).summary().mayMm() &&
            depth.rows().get(0).summary().uncertainOrMm(),
            "depth budget must prevent negative effect claims");
        ok(run(diamond,List.of(calls.get(0)),4,1,20)
            .rows().get(0).summary().limited(),"node cap explicit");
        var closed=run(List.of(node(0x130,false,false,false)),
            List.of(calls.get(0)),4,20,20);
        ok(!closed.rows().get(0).summary().uncertainOrMm(),
            "closed modeled callee has no observed MM source");
        var capped=run(diamond,calls,4,20,1);
        ok(capped.rows().size()==1 && capped.omitted()==1,
            "row cap reports omitted call sites");
        boolean fail=false;
        try{call(0x100,0x108,-1L);}
        catch(IllegalArgumentException expected){fail=true;}
        ok(fail,"reject negative target");
        fail=false;
        try{run(List.of(node(0x130,false,false,false),
            node(0x130,false,false,false)),List.of(calls.get(0)),4,20,20);}
        catch(IllegalArgumentException expected){fail=true;}
        ok(fail,"reject duplicate functions");
        System.out.println("HardwareInterproceduralMmEffectsSelfTest OK");
    }
}
