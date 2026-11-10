package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/** Pure-Java21 bounded vector/MC68332 MM evidence, not a hardware trace. */
public final class HardwareVectorMmMayCorrelationSelfTest {
    private HardwareVectorMmMayCorrelationSelfTest() {}
    private static int assertions;
    private static void ok(boolean condition,String why) {
        assertions++;
        if(!condition)throw new AssertionError(why);
    }
    private static void bad(Runnable action,String why) {
        boolean rejected=false;
        try {action.run();}catch(IllegalArgumentException expected){rejected=true;}
        ok(rejected,why);
    }
    private static HardwareInterproceduralMmEffects.FunctionNode node(
            long entry,boolean mm,boolean alias,boolean unknown,Long... callees) {
        return new HardwareInterproceduralMmEffects.FunctionNode(
            entry,mm,alias,unknown,List.of(callees));
    }
    private static HardwareVectorResetCorrelation.Target vector(
            int slot,long pointer,long entry,boolean exact) {
        return new HardwareVectorResetCorrelation.Target(slot,pointer,entry,exact);
    }
    public static void main(String[] args) {
        var graph=List.of(
            node(0x130,false,false,false,0x160L,0x140L,0x150L,0x130L),
            node(0x140,true,false,false),
            node(0x150,false,true,false),
            node(0x160,false,false,true),
            node(0x300,false,false,false),
            node(0x400,false,false,false,0x402L),
            node(0x402,false,false,false,0x404L),
            node(0x404,false,false,false,0x406L),
            node(0x406,false,false,false,0x408L),
            node(0x408,false,false,false,0x40AL),
            node(0x40A,true,false,false));
        var targets=List.of(
            vector(9,0x400L,0x400L,true),
            vector(7,0x300L,0x300L,true),
            vector(4,0x132L,0x130L,false),
            vector(6,0x200L,0x200L,true),
            vector(3,0x130L,0x130L,true),
            vector(2,0x130L,0x130L,true));
        var report=HardwareVectorMmMayCorrelation.inspect(false,0,
            true,false,Set.of(0x100L,0x130L),targets,graph,4);
        ok(report.recognizedTargets()==6 && report.exactEntries()==5 &&
            report.interiorPointers()==1 && report.rows().size()==4 &&
            report.distinctShownRoots()==3 && report.displayTruncated(),
            "bounded exact-entry display has independent full numeric counts");
        var row=report.rows().get(0);
        ok(row.vectorNumber()==2 && row.pointer()==0x130L &&
            row.mmLowByte().equals("STATIC_MAY_MM_LOW_BYTE") &&
            row.resetRelation()==
                HardwareVectorResetCorrelation.Relation.IN_RESET_STATIC_CALL_SUBSET &&
            row.mmSource().equals(
                "MM_SOURCE -> 0x00000130 -> 0x00000140") &&
            row.aliasSource().equals(
                "STORE_ALIAS -> 0x00000130 -> 0x00000150") &&
            row.observedUnknownSource().equals(
                "UNKNOWN_FLOW -> 0x00000130 -> 0x00000160") &&
            row.frontierSource().equals("NONE") &&
            row.cycle() && row.unknownControl() && row.unknownAlias() &&
            !row.limited(),
            "exact handler root preserves typed MM, alias, inspected unknown and cycle");
        ok(report.rows().get(1).vectorNumber()==3 &&
            report.rows().get(1).mmSource().equals(row.mmSource()),
            "two vector slots share one canonical source-only function root");
        ok(report.rows().get(2).vectorNumber()==6 &&
            report.rows().get(2).mmLowByte().equals("UNKNOWN") &&
            report.rows().get(2).observedUnknownSource().equals(
                "MISSING_TARGET -> 0x00000200") &&
            report.rows().get(2).frontierSource().equals("NONE"),
            "exact entry missing from analysis inventory is not a closed MM negative");
        ok(report.rows().get(3).vectorNumber()==7 &&
            report.rows().get(3).mmLowByte().equals(
                "NOT_OBSERVED_IN_BOUNDED_SOURCE") &&
            report.rows().get(3).resetRelation()==
                HardwareVectorResetCorrelation.Relation.OUTSIDE_OBSERVED_RESET_SUBSET &&
            !report.rows().get(3).resetRelationUncertain(),
            "closed local non-MM source remains a bounded negative, not ISR proof");
        ok(report.markdown().contains("explicit MC68332 profile required") &&
            report.markdown().contains("MM0/MM1 are") &&
            report.markdown().contains("No vector pointer is added as a CALL edge") &&
            report.markdown().contains("INCOMPLETE VECTOR DISPLAY") &&
            report.markdown().contains("undisplayed exact rows: 1"),
            "static/report scope, source priority and omitted roots are explicit");
        var full=HardwareVectorMmMayCorrelation.inspect(false,0,
            true,false,Set.of(0x130L),targets,graph,8);
        ok(full.rows().size()==5 && !full.displayTruncated() &&
            full.distinctShownRoots()==4 &&
            full.rows().get(4).frontierSource().equals(
                "DEPTH_CUTOFF -> 0x00000400 -> 0x00000402 -> "+
                    "0x00000404 -> 0x00000406 -> 0x00000408 -> 0x0000040A") &&
            full.rows().get(4).mmLowByte().equals("UNKNOWN") &&
            full.rows().get(4).mmSource().equals("NONE"),
            "true uninspected fifth-hop MM leaf retains typed depth uncertainty");
        var reversed=new ArrayList<>(targets);
        Collections.reverse(reversed);
        var graphReversed=new ArrayList<>(graph);
        Collections.reverse(graphReversed);
        ok(report.equals(HardwareVectorMmMayCorrelation.inspect(
            false,0,true,false,Set.of(0x100L,0x130L),
            reversed,graphReversed,4)),
            "target and function inventory order cannot change capped source evidence");
        var relocated=HardwareVectorMmMayCorrelation.inspect(
            true,0x800L,false,true,Set.of(0x130L),targets,graph,3);
        ok(relocated.relocated() && relocated.tableBase()==0x800L &&
            relocated.rows().size()==3 &&
            relocated.rows().stream().allMatch(r->
                r.resetRelation()==
                    HardwareVectorResetCorrelation.Relation.RESET_ROOT_UNKNOWN &&
                r.resetRelationUncertain()) &&
            relocated.rows().get(0).mmSource().equals(row.mmSource()) &&
            relocated.markdown().contains("relocated MOVEC-to-VBR source-image") &&
            relocated.markdown().contains("not proof of an active VBR"),
            "candidate relocated VBR table cannot promote to runtime ISR or MM latch");
        var interiorOnly=HardwareVectorMmMayCorrelation.inspect(
            false,0,true,false,Set.of(0x130L),
            List.of(vector(2,0x132L,0x130L,false)),graph,2);
        ok(interiorOnly.exactEntries()==0 &&
            interiorOnly.interiorPointers()==1 &&
            interiorOnly.rows().isEmpty() &&
            interiorOnly.distinctShownRoots()==0,
            "interior vector pointer cannot borrow whole-function MM source");
        var missingGraph=HardwareVectorMmMayCorrelation.inspect(
            false,0,true,false,Set.of(0x130L),
            List.of(vector(3,0x130L,0x130L,true)),List.of(),2);
        ok(missingGraph.rows().get(0).mmLowByte().equals("UNKNOWN") &&
            missingGraph.rows().get(0).observedUnknownSource().equals(
                "MISSING_TARGET -> 0x00000130"),
            "an empty truncated scanner never implies no SIMCR source");

        // Verify public entry-root solver validates the *whole* source
        // graph, canonicalizes roots and cannot manufacture CALL sites.
        var roots=HardwareInterproceduralMmEffects.inspectRoots(
            graph,List.of(0x300L,0x130L,0x200L),4,100);
        ok(new ArrayList<>(roots.keySet())
                .equals(List.of(0x130L,0x200L,0x300L)) &&
            roots.get(0x130L).mmWitness().chain()
                .equals(List.of(0x130L,0x140L)) &&
            roots.get(0x200L).unknownWitness().kind()==
                HardwareInterproceduralMmEffects.WitnessKind.MISSING_TARGET,
            "direct function-entry roots are sorted and inspected without fake CALL PCs");
        boolean immutable=false;
        try {roots.clear();}catch(UnsupportedOperationException expected){
            immutable=true;
        }
        ok(immutable,"root summary map is immutable, scoped to one source inventory");
        bad(()->HardwareInterproceduralMmEffects.inspectRoots(
            graph,List.of(0x130L,0x130L),4,100),
            "duplicate inspected roots are not silently made ambiguous");
        bad(()->HardwareInterproceduralMmEffects.inspectRoots(
            graph,java.util.Arrays.asList(0x130L,null),4,100),
            "null synthetic CALL-free root rejected");
        bad(()->HardwareInterproceduralMmEffects.inspectRoots(
            List.of(node(0x130,false,false,false),
                    node(0x130,true,false,false)),
            List.of(0x130L),4,100),
            "duplicate function source cannot manufacture MM witness");
        bad(()->HardwareVectorMmMayCorrelation.inspect(false,0,true,false,
            Set.of(0x130L),List.of(targets.get(4),targets.get(4)),graph,8),
            "duplicate vector slot rejected");
        bad(()->HardwareVectorMmMayCorrelation.inspect(false,0,true,false,
            Set.of(0x130L),List.of(vector(10,0x1000000L,0x1000000L,true)),
            graph,8),"32-bit CPU32 pointer never aliases MC68332 24-bit handler");
        bad(()->HardwareVectorMmMayCorrelation.inspect(false,0,true,false,
            Set.of(0x1000000L),targets,graph,8),
            "wide RESET source cannot confer MCU24 relation");
        bad(()->HardwareVectorMmMayCorrelation.inspect(true,0xfffffcL,
            true,false,Set.of(),targets,graph,8),
            "relocated table crossing MCU24 top rejected");
        bad(()->HardwareVectorMmMayCorrelation.inspect(false,0,
            true,false,Set.of(),targets,graph,33),
            "display cap prevents unbounded vector source audits");
        var oversized=new ArrayList<HardwareVectorResetCorrelation.Target>();
        for(int i=2;i<=255;i++)
            oversized.add(vector(i,0x130L,0x130L,true));
        oversized.add(vector(2,0x130L,0x130L,true));
        bad(()->HardwareVectorMmMayCorrelation.inspect(false,0,
            true,false,Set.of(),oversized,graph,2),
            "source inventory max recognized slots enforced before sorting");
        boolean immReport=false;
        try {full.rows().clear();}catch(UnsupportedOperationException expected){
            immReport=true;
        }
        ok(immReport,"source report immutable and detached from input lists");
        System.out.println("HardwareVectorMmMayCorrelationSelfTest PASS: assertions="+
            assertions);
    }
}
