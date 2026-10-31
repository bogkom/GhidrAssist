package ghidrassist.hardware;

import java.util.List;
public final class HardwareStaticWordConsensusSelfTest {
    private HardwareStaticWordConsensusSelfTest(){}
    private static void check(boolean truth,String label){
        if(!truth)throw new AssertionError(label);
    }
    private static HardwareStaticWordConsensus.Observation site(String name,
            boolean write,Integer value){
        return new HardwareStaticWordConsensus.Observation(name,write,value);
    }
    public static void main(String[] args){
        var observations=List.of(
            site("SIMCR",true,0x40ca),
            site("SIMCR",true,0x4848), // alternative branch, NOT a last-write-wins value
            site("CSBAR0",true,0xf803),
            site("CSBAR0",true,0xf803),
            site("CSOR0",true,0x7c30),
            site("CSOR0",true,null), // unmodeled later write could affect same word
            site("CSPAR0",false,null),
            site("CSBAR1",true,0xf803));
        var res=HardwareStaticWordConsensus.inspect(observations);
        check(res.singleLiteralCandidates().size()==2 &&
            res.singleLiteralCandidates().get("CSBAR0")==0xf803 &&
            res.singleLiteralCandidates().get("CSBAR1")==0xf803,
            "only repeated agreeing literals may enter conditional sketch");
        check(!res.singleLiteralCandidates().containsKey("SIMCR") &&
            !res.singleLiteralCandidates().containsKey("CSOR0") &&
            !res.singleLiteralCandidates().containsKey("CSPAR0"),
            "branch alternatives, unknown writes and references excluded");
        check(res.conflictedRegisters()==1 &&
            res.registersWithUnknownWrites()==1,
            "conflicts and unknowns reported separately");
        check(res.description().contains("NOT execution order"),
            "static source sequence cannot assert hardware state");
        var blank=HardwareStaticWordConsensus.inspect(List.of(site("SIMCR",false,null)));
        check(blank.singleLiteralCandidates().isEmpty(),
            "reference-only is not a write");
        boolean immutable=false;
        try{res.singleLiteralCandidates().clear();}
        catch(UnsupportedOperationException e){immutable=true;}
        check(immutable,"immutable output");
        boolean invalid=false;
        try{HardwareStaticWordConsensus.inspect(null);}
        catch(IllegalArgumentException e){invalid=true;}
        check(invalid,"missing evidence fails closed");
        System.out.println("HardwareStaticWordConsensusSelfTest OK");
    }
}
