package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
public final class HardwareStartupEvidenceMergeSelfTest {
    private HardwareStartupEvidenceMergeSelfTest(){}
    private static void ok(boolean condition,String label) {
        if(!condition)throw new AssertionError(label);
    }
    private static HardwareStartupEvidenceMerge.Observation site(long pc,long address,
            String register,HardwareStartupEvidenceMerge.Source source,
            boolean write,int width,Integer word,boolean uncertain){
        return new HardwareStartupEvidenceMerge.Observation(0x2bc0,pc,address,
            register,source,write,width,word,uncertain);
    }
    public static void main(String[] args) {
        var direct=HardwareStartupEvidenceMerge.Source.LISTING_REFERENCE;
        var cfg=HardwareStartupEvidenceMerge.Source.CFG_PCODE;
        var examples=new ArrayList<HardwareStartupEvidenceMerge.Observation>();
        examples.add(site(0x2bca,0xfffa00,"SIMCR",direct,true,16,0x40ca,false));
        examples.add(site(0x2bca,0xfffa00,"SIMCR",cfg,true,16,0x40ca,false));
        examples.add(site(0x2bd0,0xfffa4c,"CSBAR0",cfg,true,16,0xf803,true));
        examples.add(site(0x2bd4,0xfffa4e,"CSOR0",direct,true,8,null,false));
        examples.add(site(0x2bd4,0xfffa4e,"CSOR0",cfg,true,16,0x7c30,false));
        examples.add(site(0x2bd8,0xfffa50,"CSBAR1",direct,false,0,null,false));
        examples.add(site(0x2bde,-1,"UNRESOLVED_ALIAS",cfg,true,0,null,true));
        var r=HardwareStartupEvidenceMerge.reconcile(examples);
        ok(r.rawSites()==7 && r.rows().size()==4 &&
            r.duplicateSources()==2 && r.unboundAliasStores()==1,
            "same instruction/address deduplicated; unknown aliases separate");
        var sim=r.rows().stream().filter(x->x.candidateRegister().equals("SIMCR"))
            .findFirst().orElseThrow();
        ok(sim.sources().size()==2 && sim.status()==
            HardwareStartupEvidenceMerge.Status.FULL_WORD_LITERAL_CANDIDATE &&
            sim.literalWord()==0x40ca,"two matching sources one known literal");
        var csor=r.rows().stream().filter(x->x.candidateRegister().equals("CSOR0"))
            .findFirst().orElseThrow();
        ok(csor.status()==HardwareStartupEvidenceMerge.Status.CONFLICTING_EVIDENCE &&
            csor.forStartup().word()==null,
            "mixed byte and word at same PC cannot establish register word");
        ok(r.markdown(true).contains("not be counted as two events") &&
            r.markdown(true).contains("remain UNKNOWN"),
            "no false runtime epoch, MM latch or CS physical map");
        ok(!r.markdown(false).contains("| SIMCR |") &&
            r.markdown(false).contains("UNVERIFIED_MCU_REGISTER"),
            "generic CPU32 does not assert MCU identity");
        var conflict=HardwareStartupEvidenceMerge.reconcile(List.of(
            site(10,0xfffa00,"SIMCR",direct,true,16,0x40ca,false),
            site(10,0xfffa00,"SIMCR",cfg,true,16,0x4848,false)));
        ok(conflict.conflicts()==1 &&
            conflict.rows().get(0).literalWord()==null &&
            conflict.rows().get(0).status()==
                HardwareStartupEvidenceMerge.Status.CONFLICTING_EVIDENCE,
            "contradicting literals fail closed");
        var unresolved=HardwareStartupEvidenceMerge.reconcile(List.of(
            site(30,0xfffa00,"SIMCR",direct,false,0,null,false),
            site(30,0xfffa00,"SIMCR",cfg,true,16,0x40ca,false)));
        ok(unresolved.rows().get(0).status()==
            HardwareStartupEvidenceMerge.Status.FULL_WORD_LITERAL_CANDIDATE,
            "reference-only XREF does not disprove actual CFG candidate write");
        var unknown=HardwareStartupEvidenceMerge.reconcile(List.of(
            site(40,0xfffa00,"SIMCR",direct,true,16,null,false),
            site(40,0xfffa00,"SIMCR",cfg,true,16,0x40ca,false)));
        ok(unknown.rows().get(0).status()==
            HardwareStartupEvidenceMerge.Status.UNKNOWN_VALUE_OR_WIDTH,
            "unknown candidate literal not silently overwritten");
        boolean immutable=false;
        try{r.rows().clear();}catch(UnsupportedOperationException ex){immutable=true;}
        ok(immutable,"read-only immutable result");
        boolean rejected=false;
        try{HardwareStartupEvidenceMerge.reconcile(null);}
        catch(IllegalArgumentException expected){rejected=true;}
        ok(rejected,"null not empty success");
        System.out.println("HardwareStartupEvidenceMergeSelfTest OK");
    }
}
