package ghidrassist.hardware;

import java.util.List;

public final class HardwareResetEffectSitesSelfTest {
    private static void check(boolean ok,String what) {
        if(!ok)throw new AssertionError(what);
    }
    private static void bad(Runnable r) {
        try {r.run();throw new AssertionError("Expected rejection");}
        catch(IllegalArgumentException expected) {}
    }
    private static HardwareCallEffects.FunctionNode n(long entry,boolean store,
            boolean vbr,Long... calls) {
        return new HardwareCallEffects.FunctionNode(entry,store,vbr,false,List.of(calls));
    }
    public static void main(String[] args) {
        var graph=List.of(n(0x100,false,false,0x130L,0x160L),
                n(0x130,true,false),n(0x160,false,true),
                n(0x200,true,false));
        var witness=HardwareResetHandlerWitness.inspect(0x100,false,graph,List.of());
        var sites=List.of(new HardwareResetEffectSites.Site(0x160,0x166,
                HardwareResetEffectSites.Kind.MOVEC_VBR),
                new HardwareResetEffectSites.Site(0x130,0x134,
                HardwareResetEffectSites.Kind.MEMORY_STORE),
                new HardwareResetEffectSites.Site(0x200,0x204,
                HardwareResetEffectSites.Kind.MEMORY_STORE),
                new HardwareResetEffectSites.Site(0x300,0x304,
                HardwareResetEffectSites.Kind.MOVEC_VBR));
        var report=HardwareResetEffectSites.correlate(witness,graph,sites);
        check(report.rows().get(0).status()==HardwareResetEffectSites.Status.STATIC_CALL_CHAIN &&
                report.rows().get(0).chain().equals(List.of(0x100L,0x130L)),
                "STORE site chain");
        check(report.rows().get(1).status()==HardwareResetEffectSites.Status.STATIC_CALL_CHAIN &&
                report.rows().get(1).chain().equals(List.of(0x100L,0x160L)),
                "MOVEC site chain");
        check(report.rows().get(2).status()==HardwareResetEffectSites.Status.NOT_OBSERVED_WITHIN_BOUND &&
                report.rows().get(3).status()==HardwareResetEffectSites.Status.UNKNOWN_FUNCTION_INVENTORY,
                "negative site evidence");
        check(report.markdown().contains("0x00000134") &&
                report.markdown().contains("STATIC ONLY"),"site coordinates and caveat");
        var reversed=HardwareResetEffectSites.correlate(witness,graph,
                List.of(sites.get(3),sites.get(2),sites.get(1),sites.get(0)));
        check(report.equals(reversed),"deterministic site order");
        var incomplete=HardwareResetHandlerWitness.inspect(0x100,true,graph,List.of());
        check(HardwareResetEffectSites.correlate(incomplete,graph,sites).rows().get(2)
                .status()==HardwareResetEffectSites.Status.UNKNOWN_FRONTIER,
                "incomplete traversal cannot prove negative");
        bad(()->HardwareResetEffectSites.correlate(witness,graph,
                List.of(sites.get(0),sites.get(0))));
        bad(()->HardwareResetEffectSites.correlate(witness,graph,
                List.of(new HardwareResetEffectSites.Site(0x130,0x134,
                        HardwareResetEffectSites.Kind.MOVEC_VBR))));
        bad(()->new HardwareResetEffectSites.Site(0x130,0x12e,
                HardwareResetEffectSites.Kind.MEMORY_STORE));
        bad(()->new HardwareResetEffectSites.Site(0x130,0x135,
                HardwareResetEffectSites.Kind.MEMORY_STORE));
        try {report.rows().add(report.rows().get(0));throw new AssertionError("Mutable report");}
        catch(UnsupportedOperationException expected) {}
        System.out.println("RESET_EFFECT_SITES_SOURCE_PASS");
    }
}
