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
        var withBarrier=HardwareStartupConfig.analyze(true,true,Set.of(0x2bc0L),
            false,List.of(new HardwareStartupConfig.Site(
                0x2bc0,0x2bca,"SIMCR",true,0x40ca,true)));
        ok(withBarrier.groups().get(0).alternatives()==
            HardwareStartupConfig.Alternatives.UNKNOWN_WRITE_VALUE &&
            withBarrier.groups().get(0).simcrMmCandidate()==null &&
            withBarrier.unknownWrites()==1,
            "known literal after unknown call/alias stays source only");
        ok(!HardwareStartupConfig.analyze(false,true,Set.of(0x2bc0L),false,
            List.of(new HardwareStartupConfig.Site(
                0x2bc0,0x2bca,"SIMCR",true,0x40ca))).markdown().contains("| SIMCR |"),
            "generic CPU32 report hides selected-MCU register names");
        boolean readonly=false;try{result.groups().clear();}
        catch(UnsupportedOperationException e){readonly=true;}
        ok(readonly,"immutable output");
        // Adversarial Ghidra register labels are retained as raw evidence,
        // but cannot inject Markdown rows, HTML or unbounded text.
        String forged="SIMCR\n| ACTIVE_MM <script>"+"X".repeat(100000);
        var hostile=HardwareStartupConfig.analyze(true,true,Set.of(0x2bc0L),
            false,List.of(at(0x2bc0,0x2bca,forged,true,0x40ca)));
        String safe=hostile.markdown();
        ok(hostile.groups().get(0).register().equals(forged) &&
            safe.contains("[U+000A]") && safe.contains("[U+007C]") &&
            safe.contains("[U+003C]") && safe.contains("[ABBREVIATED LABEL]") &&
            !safe.contains("<script>") && !safe.contains("| ACTIVE_MM") &&
            safe.length()<2100,"source label display is bounded; raw evidence retained");
        ok(!HardwareStartupConfig.analyze(false,true,Set.of(0x2bc0L),
            false,List.of(at(0x2bc0,0x2bca,forged,true,0x40ca)))
            .markdown().contains("[U+007C]"),
            "generic CPU32 hides all unverified MCU register names");
        var unicode=HardwareStartupConfig.analyze(true,true,Set.of(0x2bc0L),
            false,List.of(at(0x2bc0,0x2bca,"A"+new String(Character.toChars(0x202e))+
                "B"+new String(Character.toChars(0x1f600)),true,0x40ca)));
        ok(unicode.markdown().contains("[U+202E]") &&
            unicode.markdown().contains("[U+1F600]"),
            "Unicode bidi and supplementary code points are encoded atomically");
        var alternatives=new ArrayList<HardwareStartupConfig.Site>();
        for(int i=0;i<40;i++)
            alternatives.add(at(0x2bc0,0x2bca+2L*i,"SIMCR",true,i));
        var bounded=HardwareStartupConfig.analyze(true,true,Set.of(0x2bc0L),
            false,alternatives);
        String boundedText=bounded.markdown();
        ok(bounded.groups().get(0).possibleWords().size()==40 &&
            bounded.groups().get(0).alternatives()==
                HardwareStartupConfig.Alternatives.MULTIPLE_LITERAL_ALTERNATIVES &&
            boundedText.contains("[24 MORE LITERAL ALTERNATIVES OMITTED]") &&
            boundedText.contains("0x000F") && !boundedText.contains("0x0010") &&
            boundedText.length()<2000,
            "sorted literal alternatives display capped without losing source");
        for(HardwareStartupConfig.Site bad:new HardwareStartupConfig.Site[]{
                null,at(-1,10,"SIMCR",true,1),at(10,-1,"SIMCR",true,1),
                at(10,12," ",true,1)
        }) {
            boolean refused=false;
            try{HardwareStartupConfig.analyze(true,true,Set.of(),false,
                java.util.Arrays.asList(bad));}
            catch(IllegalArgumentException expected){refused=true;}
            ok(refused,"invalid input cannot silently disappear from complete report");
        }
        boolean limit=false;
        try {HardwareStartupConfig.analyze(true,false,Set.of(),false,
            java.util.Collections.nCopies(HardwareStartupConfig.MAX_SOURCE_SITES+1,
                at(0,2,"SIMCR",true,0x40ca)));}
        catch(IllegalArgumentException expected){limit=true;}
        ok(limit,"oversized startup evidence fails before partial counting");
        System.out.println("HardwareStartupConfigSelfTest OK");
    }
}
