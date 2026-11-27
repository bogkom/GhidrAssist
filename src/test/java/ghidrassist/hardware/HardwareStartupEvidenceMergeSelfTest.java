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
        ok(r.functionsWithUnknownAlias().contains(0x2bc0L) &&
            sim.forStartup(true).uncertain(),
            "same-function unbound alias blocks confident startup word inference");
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
        // The reconciliation must preserve original source strings while
        // preventing newlines, pipe cells, HTML and oversized names from
        // being published as hardware evidence.
        String label="SIMCR\r\n| CLAIM_ACTIVE <b>"+"Z".repeat(100000);
        var unsafe=HardwareStartupEvidenceMerge.reconcile(List.of(
            site(0x2bca,0xfffa00,label,cfg,true,16,0x40ca,false)));
        String safe=unsafe.markdown(true);
        ok(unsafe.rows().get(0).candidateRegister().equals(label) &&
            safe.contains("[U+000D]") && safe.contains("[U+000A]") && safe.contains("[U+007C]") &&
            safe.contains("[U+003C]") && safe.contains("[ABBREVIATED LABEL]") &&
            !safe.contains("<b>") && !safe.contains("| CLAIM_ACTIVE") &&
            safe.length()<1900,
            "raw merged source preserved, static report label sanitized");
        ok(!unsafe.markdown(false).contains("[U+007C]") &&
            unsafe.markdown(false).contains("UNVERIFIED_MCU_REGISTER"),
            "generic CPU32 report never leaks selected MCU register claim");
        var many=new ArrayList<HardwareStartupEvidenceMerge.Observation>();
        for(int i=0;i<106;i++)
            many.add(site(0x2bca+2L*i,0xfffa00+2L*i,"SIMCR",
                cfg,true,16,0x40ca,false));
        var capped=HardwareStartupEvidenceMerge.reconcile(many);
        ok(capped.rows().size()==106 &&
            capped.markdown(true).lines().filter(l->l.startsWith("| 0x")).count()==100 &&
            capped.markdown(true).contains("6 more sites omitted by display cap"),
            "bounded 100-row publication retains all reconciled source records");
        boolean oversized=false;
        try{HardwareStartupEvidenceMerge.reconcile(
            java.util.Collections.nCopies(
                HardwareStartupEvidenceMerge.MAX_SOURCE_OBSERVATIONS+1,
                site(0x2bca,0xfffa00,"SIMCR",cfg,true,16,0x40ca,false)));}
        catch(IllegalArgumentException expected){oversized=true;}
        ok(oversized,"oversized Listing/CFG input cannot publish partial summary");
        System.out.println("HardwareStartupEvidenceMergeSelfTest OK");
    }
}
