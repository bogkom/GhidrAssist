package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * GA-02/03/11: deterministic MAY-only indirect-call effect annotations.
 * No Ghidra Program, real firmware, model, API, or user data.
 */
public final class HardwareIndirectMayEffectsSelfTest {
    private static int assertions;
    private HardwareIndirectMayEffectsSelfTest() {}
    private static void check(boolean v,String reason) {
        assertions++;
        if(!v)throw new AssertionError(reason);
    }
    private static void rejects(Runnable op,String reason) {
        boolean rejected=false;
        try{op.run();}catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,reason);
    }
    private static HardwareCallEffects.FunctionNode node(long entry,
            boolean store,boolean vbr,boolean unknown,Long... callees) {
        return new HardwareCallEffects.FunctionNode(
            entry,store,vbr,unknown,List.of(callees));
    }
    private static HardwareIndirectCallEvidence.Site witness(
            long caller,long callPc,long target) {
        return new HardwareIndirectCallEvidence.Site(
            caller,caller,callPc,target);
    }
    public static void main(String[] unused) {
        // A real byte-verifier supplied MAY-source does NOT upgrade the
        // parent COMPUTED_CALL to a global direct CALL/RESET/ISR edge.
        var site=witness(0x600,0x606,0x700);
        var graph=List.of(
            node(0x600,false,false,true),
            node(0x700,true,true,false),
            node(0x720,false,false,false),
            node(0x730,false,false,true),
            node(0x740,false,false,false,0x742L),
            node(0x742,false,true,false,0x740L));
        var may=HardwareIndirectMayEffects.analyze(List.of(site),graph,16);
        check(may.sourceSites()==1 && may.examinedSites()==1 &&
            may.omittedSites()==0 && may.rows().size()==1,
            "one bounded candidate remains one display-only row");
        var effects=may.rows().get(0).effects();
        check(effects.possibleMemoryStore() && effects.possibleVbrWrite() &&
            !effects.unresolved() && effects.visited()==1,
            "witnessed target's local memory STORE/VBR are MAY effects");
        String md=may.markdown();
        check(md.contains("DISPLAY ONLY") &&
            md.contains("NEVER EXECUTION") &&
            md.contains("not a proven MMIO access") &&
            md.contains("direct CALL edge") &&
            md.contains("No Apply/Undo") &&
            md.contains("STATIC_MAY_CANDIDATE"),
            "witnessed call effects must never become execution/MMIO/Apply");
        var reset=HardwareResetFlow.trace(0x600,graph,
            Set.of(0x700L),6,30,10);
        check(reset.visitedEntries().equals(Set.of(0x600L)) &&
            reset.unresolved() && reset.evidence().isEmpty(),
            "indirect MAY target must not be inserted into RESET graph");

        var noEffect=HardwareIndirectMayEffects.analyze(
            List.of(witness(0x610,0x616,0x720)),graph,16);
        check(noEffect.markdown().contains("NOT_OBSERVED_IN_BOUNDED_SOURCE") &&
            !noEffect.rows().get(0).effects().unresolved(),
            "negative bounded evidence is NOT hardware no-effect proof");
        var unknown=HardwareIndirectMayEffects.analyze(
            List.of(witness(0x610,0x616,0x730)),graph,16);
        check(unknown.markdown().contains("| UNKNOWN | UNKNOWN | true |") &&
            unknown.rows().get(0).effects().unresolved(),
            "unknown inner CALL flow prevents negative effect classification");
        var missing=HardwareIndirectMayEffects.analyze(
            List.of(witness(0x610,0x616,0x7f0)),graph,16);
        check(missing.rows().get(0).effects().visited()==0 &&
            missing.rows().get(0).effects().unresolved() &&
            missing.markdown().contains("| UNKNOWN | UNKNOWN | true |"),
            "missing recognized function target remains UNKNOWN");
        var recursion=HardwareIndirectMayEffects.analyze(
            List.of(witness(0x610,0x616,0x740)),graph,16);
        check(recursion.rows().get(0).effects().recursive() &&
            recursion.rows().get(0).effects().possibleVbrWrite() &&
            recursion.rows().get(0).effects().unresolved() &&
            recursion.markdown().contains("STATIC_MAY_CANDIDATE"),
            "cyclic source subtree may have VBR, still uncertain");
        var depthGraph=List.of(
            node(0x100,false,false,false,0x110L),
            node(0x110,false,false,false,0x120L),
            node(0x120,false,false,false,0x130L),
            node(0x130,false,false,false,0x140L),
            node(0x140,false,false,false,0x150L),
            node(0x150,true,true,false));
        var capped=HardwareIndirectMayEffects.analyze(
            List.of(witness(0x200,0x206,0x100)),depthGraph,16);
        check(capped.rows().get(0).effects().truncated() &&
            capped.rows().get(0).effects().unresolved() &&
            !capped.rows().get(0).effects().possibleMemoryStore() &&
            capped.markdown().contains("| UNKNOWN | UNKNOWN | true |"),
            "MAY effects beyond max depth must NOT become a false negative");

        var two=List.of(witness(0x610,0x616,0x700),site);
        var joined=HardwareIndirectMayEffects.analyze(two,graph,16);
        check(joined.rows().size()==2 &&
            joined.rows().get(0).source().caller()==0x600 &&
            joined.rows().get(1).source().caller()==0x610 &&
            joined.rows().get(0).effects()
                .equals(joined.rows().get(1).effects()),
            "two witnesses to same target reuse only read-only local effect");
        var reversed=new ArrayList<>(two);
        Collections.reverse(reversed);
        check(joined.equals(HardwareIndirectMayEffects.analyze(reversed,graph,16)),
            "stable source order independently of caller ordering");
        boolean immutable=false;
        try {joined.rows().clear();}
        catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"report rows immutable");

        var many=new ArrayList<HardwareIndirectCallEvidence.Site>();
        for(int i=0;i<17;i++)
            many.add(witness(0x900L+i*16,0x906L+i*16,0x700));
        var truncated=HardwareIndirectMayEffects.analyze(many,graph,16);
        check(truncated.sourceSites()==17 &&
            truncated.examinedSites()==16 &&
            truncated.omittedSites()==1 &&
            truncated.rows().size()==16 &&
            truncated.markdown().contains("INCOMPLETE MAY EFFECT COVERAGE"),
            "independent 16-row effect cap preserves exact omission");
        check(HardwareIndirectMayEffects.analyze(many,graph,1).omittedSites()==16,
            "stricter requested cap cannot pretend complete effects");
        var absent=HardwareIndirectMayEffects.analyze(List.of(),graph,16);
        check(absent.rows().isEmpty() &&
            absent.markdown().contains("NOT proof of no CALL"),
            "unproven computed XREF is not an indirect MAY witness");

        rejects(()->HardwareIndirectMayEffects.analyze(
            Arrays.asList(site,null),graph,16),
            "null unverified candidate refused");
        rejects(()->HardwareIndirectMayEffects.analyze(
            List.of(site,site),graph,16),
            "duplicate indirect CALL PC refused");
        rejects(()->HardwareIndirectMayEffects.analyze(
            List.of(site),graph,0),
            "zero budget refused");
        rejects(()->HardwareIndirectMayEffects.analyze(
            List.of(site),graph,17),
            "unbounded row budget refused");
        rejects(()->HardwareIndirectMayEffects.analyze(
            Collections.nCopies(HardwareIndirectCallEvidence.MAX_SITES+1,site),
            graph,16),"excess untrusted source records refused");
        rejects(()->HardwareIndirectMayEffects.analyze(
            List.of(site),List.of(node(0x700,false,false,false),
                node(0x700,true,false,false)),16),
            "duplicate graph entries cannot determine may-effects");
        System.out.println("HardwareIndirectMayEffectsSelfTest PASS: assertions="+assertions);
    }
}
