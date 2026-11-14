package ghidrassist.hardware;

import java.util.List;

public final class HardwareDecodedEffectSitesSelfTest {
    private static void check(boolean ok,String what) {
        if(!ok)throw new AssertionError(what);
    }
    private static void reject(Runnable action) {
        try {action.run();throw new AssertionError("Expected rejection");}
        catch(IllegalArgumentException | IllegalStateException expected) {}
    }
    private static HardwareCallEffects.FunctionNode n(long entry,boolean store,boolean vbr,Long... calls) {
        return new HardwareCallEffects.FunctionNode(entry,store,vbr,false,List.of(calls));
    }
    public static void main(String[] args) {
        var decoded=List.of(
            new HardwareDecodedEffectSites.Decoded(0x160,0x166,false,true),
            new HardwareDecodedEffectSites.Decoded(0x100,0x100,false,false),
            new HardwareDecodedEffectSites.Decoded(0x130,0x134,true,false),
            new HardwareDecodedEffectSites.Decoded(0x130,0x138,true,true));
        var result=HardwareDecodedEffectSites.collect(decoded,false);
        check(result.sites().size()==4 && result.inspected()==4 &&
                !result.incomplete() && result.omitted()==0,"typed extraction");
        check(result.sites().get(0).instructionPc()==0x134 &&
                result.sites().get(2).instructionPc()==0x138 &&
                result.sites().get(3).instructionPc()==0x166,"stable sorted coordinates");
        var graph=List.of(n(0x100,false,false,0x130L,0x160L),
                n(0x130,true,true),n(0x160,false,true));
        var witness=HardwareResetHandlerWitness.inspect(0x100,false,graph,List.of());
        var report=result.correlate(witness,graph);
        check(report.rows().size()==4 &&
                report.rows().stream().allMatch(r->
                    r.status()==HardwareResetEffectSites.Status.STATIC_CALL_CHAIN),
                "independent decoder to RESET witness join");
        check(report.markdown().contains("STATIC ONLY"),"static caveat");
        reject(()->HardwareDecodedEffectSites.collect(
                List.of(decoded.get(0),decoded.get(0)),false));
        reject(()->HardwareDecodedEffectSites.collect(java.util.Arrays.asList((HardwareDecodedEffectSites.Decoded)null),false));
        reject(()->new HardwareDecodedEffectSites.Decoded(0x100,0x101,true,false));
        reject(()->HardwareDecodedEffectSites.collect(decoded,true).correlate(witness,graph));
        try {result.sites().clear();throw new AssertionError("mutable sites");}
        catch(UnsupportedOperationException expected) {}
        System.out.println("DECODED_EFFECT_SITES_SOURCE_PASS");
    }
}
