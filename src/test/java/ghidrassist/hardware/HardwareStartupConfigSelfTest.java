package ghidrassist.hardware;

import java.util.*;
public final class HardwareStartupConfigSelfTest {
    private static void ok(boolean result,String why){if(!result)throw new AssertionError(why);}
    private static HardwareStartupConfig.Site at(long fn,long pc,String reg,boolean write,Integer word){
        return new HardwareStartupConfig.Site(fn,pc,reg,write,word);
    }
    public static void main(String[] args){
        var observations=List.of(
            at(0x2bc0,0x2bca,"SIMCR",true,0x40ca),
            at(0x2bc0,0x2bcc,"SIMCR",true,0x4848),
            at(0x2bc0,0x2bd0,"CSBAR0",true,0x1200),
            at(0x2bc0,0x2bd2,"CSOR0",true,null),
            at(0x9000,0x9000,"SIMCR",true,0x40ca),
            at(0x9000,0x9002,"CSPAR0",false,null));
        var result=HardwareStartupConfig.analyze(true,true,Set.of(0x2bc0L),true,observations);
        ok(result.sites()==6 && result.writes()==5 && result.unknownWrites()==1,
            "read, write and unknown evidence counted separately");
        var sim=result.groups().stream().filter(g->g.function()==0x2bc0 &&
            g.register().equals("SIMCR")).findFirst().orElseThrow();
        ok(sim.alternatives()==HardwareStartupConfig.Alternatives.MULTIPLE_LITERAL_ALTERNATIVES &&
            sim.simcrMmCandidate()==null,"alternative SIMCR values cannot prove first latch");
        ok(sim.path()==HardwareStartupConfig.Path.STATIC_RESET_CALL_CANDIDATE,
            "reset path is a possible static direct-call path only");
        ok(result.groups().stream().anyMatch(g->g.function()==0x9000 &&
            g.path()==HardwareStartupConfig.Path.OUTSIDE_OR_UNRESOLVED),
            "no false unreachable proof");
        ok(result.markdown().contains("NOT EXECUTION") &&
            result.markdown().contains("NOT the first executed write") &&
            result.markdown().contains("NOT one simultaneous active CS map"),
            "report never asserts dynamic configuration");
        var single=HardwareStartupConfig.analyze(true,true,Set.of(0x2bc0L),false,
            List.of(at(0x2bc0,0x2bca,"SIMCR",true,0x40ca)));
        ok(single.groups().get(0).simcrMmCandidate()==1,"MM literal bit decode");
        ok(HardwareStartupConfig.analyze(false,true,Set.of(0x2bc0L),false,
            List.of(at(0x2bc0,0x2bca,"SIMCR",true,0x40ca)))
            .groups().get(0).simcrMmCandidate()==null,
            "generic CPU32 cannot assert MC68332 MM");
        ok(HardwareStartupConfig.analyze(true,false,Set.of(0x2bc0L),true,
            List.of(at(0x2bc0,0x2bca,"SIMCR",true,0x40ca)))
            .groups().get(0).path()==HardwareStartupConfig.Path.OUTSIDE_OR_UNRESOLVED,
            "unrecognized reset root");
        boolean readonly=false;try{result.groups().clear();}
        catch(UnsupportedOperationException e){readonly=true;}
        ok(readonly,"immutable output");
        System.out.println("HardwareStartupConfigSelfTest OK");
    }
}
