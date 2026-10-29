package ghidrassist.hardware;

import java.util.List;
import java.util.Set;

/**
 * Tests the actual GA-01 reset candidate traversal -> GA-02/03
 * static configuration alternatives contract, without Ghidra or ECU bytes.
 */
public final class HardwareStartupResetIntegrationSelfTest {
    private HardwareStartupResetIntegrationSelfTest(){}
    private static void ok(boolean b,String reason){
        if(!b)throw new AssertionError(reason);
    }
    public static void main(String[] args){
        var graph=List.of(
            new HardwareCallEffects.FunctionNode(0x2bc0,true,false,false,
                List.of(0x2f00L,0x3000L)),
            new HardwareCallEffects.FunctionNode(0x2f00,true,true,true,
                List.of(0x4000L)),
            new HardwareCallEffects.FunctionNode(0x3000,false,false,false,
                List.of()),
            new HardwareCallEffects.FunctionNode(0x4000,true,false,false,
                List.of(0x2bc0L)));
        var trace=HardwareResetFlow.trace(0x2bc0,graph,
            Set.of(0x2bc0L,0x2f00L,0x4000L),6,32,30);
        ok(trace.rootRecognized() && trace.visitedEntries().containsAll(
            Set.of(0x2bc0L,0x2f00L,0x3000L,0x4000L)),
            "bounded reset direct-call reachability");
        ok(trace.unresolved() && trace.recursive(),
            "unresolved branches and recursion not silently cleared");
        var sourceSites=List.of(
            new HardwareStartupConfig.Site(0x2bc0,0x2bca,"SIMCR",true,0x40ca),
            new HardwareStartupConfig.Site(0x2f00,0x2f10,"CSBAR0",true,0x1234),
            new HardwareStartupConfig.Site(0x4000,0x4010,"CSOR0",true,0x7c30),
            new HardwareStartupConfig.Site(0x9000,0x9020,"SIMCR",true,0x4848));
        var evidence=HardwareStartupConfig.analyze(true,trace.rootRecognized(),
            trace.visitedEntries(),trace.unresolved()||trace.truncated(),sourceSites);
        ok(evidence.callGraphIncomplete() && evidence.groups().size()==4,
            "RESET + history status preserves graph uncertainty");
        ok(evidence.groups().stream().filter(g->g.function()==0x9000)
            .allMatch(g->g.path()==HardwareStartupConfig.Path.OUTSIDE_OR_UNRESOLVED),
            "unresolved outside graph is not proof of impossible execution");
        ok(evidence.groups().stream().filter(g->g.function()==0x4000)
            .allMatch(g->g.path()==HardwareStartupConfig.Path.STATIC_RESET_CALL_CANDIDATE),
            "cycle included as possible call candidate, not executed");
        ok(evidence.markdown().contains("No cross-function register state is combined"),
            "CSBAR and CSOR in separate functions cannot create an active CS state");
        var budget=HardwareResetFlow.trace(0x2bc0,graph,
            Set.of(0x4000L),1,2,1);
        ok(budget.truncated() && budget.unresolved(),
            "depth or visit cap cannot be treated as complete reset graph");
        var unidentified=HardwareResetFlow.trace(0x9999,graph,
            Set.of(0x2bc0L),4,16,8);
        ok(!unidentified.rootRecognized() && unidentified.visitedEntries().isEmpty(),
            "unknown reset vector cannot certify any function");
        System.out.println("HardwareStartupResetIntegrationSelfTest OK");
    }
}
