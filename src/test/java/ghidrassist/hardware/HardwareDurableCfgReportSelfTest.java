package ghidrassist.hardware;

import java.util.*;
import static ghidrassist.hardware.HardwareDurableCfgReport.*;

public final class HardwareDurableCfgReportSelfTest {
    private HardwareDurableCfgReportSelfTest(){}
    private static void ok(boolean b,String message){
        if(!b)throw new AssertionError(message);
    }
    public static void main(String[] args)throws Exception{
        var original=new Snapshot("## bounded CFG\nsynthetic only",
            "fn,pc,register\n0x100,0x102,SIMCR\n",
            2,1,0,1,42,false,true,true,false,
            7L,8L,
            List.of(new Site(0x100,0x102,"SIMCR",0xfffa00L,
                true,16,0x40ca,0,1,true,false,false),
                new Site(0x130,0x134,"UNRESOLVED_ALIAS",-1L,
                true,0,null,0,2,true,true,true)),
            List.of(new Role(0x100,"FUN_100","A0","SIM",
                1,2,3,"PATH_UNCERTAIN","")),
            List.of(0x100L,0x130L));
        byte[] data=encode(original);
        ok(decode(data).orElseThrow().equals(original),
            "full report fields survive roundtrip without Java object deserialization");
        byte[] damaged=data.clone();
        damaged[2]^=0x30;
        ok(decode(damaged).isEmpty(),"schema change rejects snapshot");
        ok(decode(Arrays.copyOf(data,data.length-2)).isEmpty(),
            "truncation rejects partially read roles/reset entries");
        byte[] extra=Arrays.copyOf(data,data.length+1);
        ok(decode(extra).isEmpty(),"extra trailing fields rejected");
        ok(decode(new byte[0]).isEmpty(),"missing snapshot rejected");
        ok(decode(new byte[8]).isEmpty(),"untrusted tiny binary rejected");
        boolean failed=false;
        try{new Snapshot("x","x",-1,0,0,0,0,false,false,false,
            false,0,0,List.of(),List.of(),List.of());}
        catch(IllegalArgumentException e){failed=true;}
        ok(failed,"negative counters rejected");
        var none=new Snapshot("## no sites","",0,0,0,0,0,
            true,false,true,false,0,0,List.of(),List.of(),List.of());
        ok(decode(encode(none)).orElseThrow().equals(none),
            "empty lists and incomplete markers preserved");
        // GA-12: even schema-valid, checksum-protected payloads are NOT
        // eligible as "completed" checkpoints when evidence was omitted.
        var complete=new Snapshot("## complete real synthetic CFG", "fn,pc\n",
            2,0,0,0,2,false,true,false,true,0,0,
            List.of(),List.of(),List.of(0x100L));
        ok(eligibleForCompletedRestore(complete) &&
            eligibleForCompletedRestore(decode(encode(complete)).orElseThrow()),
            "completed source set is eligible after strict binary roundtrip");
        var omitted=new Snapshot(complete.markdown(),complete.csv(),
            complete.functions(),complete.indirect(),complete.vbr(),
            complete.unresolved(),complete.visited(),false,true,false,true,
            1,0,complete.sites(),complete.roles(),complete.resetFunctions());
        ok(decode(encode(omitted)).isPresent() &&
            !eligibleForCompletedRestore(omitted) &&
            !eligibleForCompletedRestore(decode(encode(omitted)).orElseThrow()),
            "valid checksum with missing CFG sites must not restore as complete");
        var omittedPointers=new Snapshot(complete.markdown(),complete.csv(),
            complete.functions(),complete.indirect(),complete.vbr(),
            complete.unresolved(),complete.visited(),false,true,false,true,
            0,1,complete.sites(),complete.roles(),complete.resetFunctions());
        ok(!eligibleForCompletedRestore(omittedPointers),
            "omitted pointer provenance cannot be certified completed");
        var stopped=new Snapshot(complete.markdown(),complete.csv(),
            complete.functions(),complete.indirect(),complete.vbr(),
            complete.unresolved(),complete.visited(),true,true,false,true,
            0,0,complete.sites(),complete.roles(),complete.resetFunctions());
        ok(!eligibleForCompletedRestore(stopped) &&
            !eligibleForCompletedRestore(original) &&
            !eligibleForCompletedRestore(none),
            "partial analysis and interrupted checkpoint never restored complete");
        ok(!eligibleForCompletedRestore(null),
            "null checkpoint is not evidence");
        // V2 persists only bounded immutable typed source witnesses, not
        // a Markdown-parsed approximation or an Apply/GUI authorization.
        var sources=new HardwareResetIndirectVbrCorrelation.SourceInventory(
            List.of(new HardwareResetIndirectVbrCorrelation.Indirect(
                0x130L,0x138L,0x180L,true,false),
                new HardwareResetIndirectVbrCorrelation.Indirect(
                0x200L,0x206L,0x180L,true,false)),
            List.of(new HardwareResetIndirectVbrCorrelation.Vbr(
                0x130L,0x144L,null,true),
                new HardwareResetIndirectVbrCorrelation.Vbr(
                0x200L,0x208L,null,true)),
            Set.of(0x100L,0x130L),true,false,1,2);
        var typed=new Snapshot(complete.markdown(),complete.csv(),
            complete.functions(),complete.indirect(),complete.vbr(),
            complete.unresolved(),complete.visited(),
            complete.limited(),complete.resetRecognized(),
            complete.resetIncomplete(),complete.cfgReviewComplete(),
            complete.cfgOmitted(),complete.pointersOmitted(),
            complete.sites(),complete.roles(),List.of(0x100L,0x130L),sources);
        var decoded=decode(encode(typed)).orElseThrow();
        ok(decoded.equals(typed) &&
            decoded.sourceInventory()!=null &&
            decoded.sourceInventory().page(0,1).colocatedPairs()==2 &&
            decoded.sourceInventory().page(1,1).rows().size()==1 &&
            decoded.sourceInventory().page(2,1).rows().isEmpty() &&
            decoded.sourceInventory().omittedIndirect()==1 &&
            decoded.sourceInventory().omittedVbr()==2,
            "V2 typed JSR/MOVEC full source inventory survives binary roundtrip");
        ok(eligibleForCompletedRestore(decoded),
            "V2 complete CFG keeps strict original restore eligibility");
        byte[] v2=encode(complete); // No optional source inventory.
        byte[] v1=Arrays.copyOf(v2,v2.length-1);
        byte[] schema=SCHEMA.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        v1[4+schema.length-1]=(byte)'1';
        var old=decode(v1).orElseThrow();
        ok(old.sourceInventory()==null && old.markdown().equals(complete.markdown()) &&
            eligibleForCompletedRestore(old),
            "Legacy GA12-CFG-REPORT-1 decodes as CFG only without fabricated JSR sources");
        ok(decode(Arrays.copyOf(encode(typed),encode(typed).length-1)).isEmpty(),
            "Truncated V2 typed sources must never decode as complete");
        byte[] corrupt=encode(typed);
        corrupt[4+schema.length-1]='3';
        ok(decode(corrupt).isEmpty(),
            "Unknown future report schema must fail closed");
        byte[] v1Extra=Arrays.copyOf(v1,v1.length+1);
        ok(decode(v1Extra).isEmpty(),"V1 extra fields refused");
        // GA-12 adversarial V1/V2 payloads: disk-store SHA-256
        // authenticates bytes against accidental corruption, but a checksum
        // of semantically malformed content must still fail closed.
        byte[] noncanonicalV2=encode(complete);
        noncanonicalV2[noncanonicalV2.length-1]=2;
        ok(decode(noncanonicalV2).isEmpty(),
            "V2 optional inventory flag 2 is not a canonical Boolean");
        // The schema and markdown are length-prefixed UTF-8. A malformed
        // text witness must not silently become replacement characters.
        byte[] invalidUtf8=encode(complete);
        int mark=4+SCHEMA.getBytes(java.nio.charset.StandardCharsets.UTF_8).length+4;
        invalidUtf8[mark]=(byte)0xff;
        ok(decode(invalidUtf8).isEmpty(),
            "Malformed UTF-8 in a provenance report is refused");
        byte[] legacyUtf8=v1.clone();
        legacyUtf8[mark]=(byte)0xff;
        ok(decode(legacyUtf8).isEmpty(),
            "V1 legacy decode refuses invalid UTF-8 without migration loss");
        boolean rejectedMismatch=false;
        try {
            new Snapshot(typed.markdown(),typed.csv(),typed.functions(),
                typed.indirect(),typed.vbr(),typed.unresolved(),typed.visited(),
                typed.limited(),false,typed.resetIncomplete(),
                typed.cfgReviewComplete(),typed.cfgOmitted(),typed.pointersOmitted(),
                typed.sites(),typed.roles(),typed.resetFunctions(),sources);
        }catch(IllegalArgumentException expected){rejectedMismatch=true;}
        ok(rejectedMismatch,
            "Conflicting RESET root summary and V2 typed sources refused");
        rejectedMismatch=false;
        try {
            new Snapshot(typed.markdown(),typed.csv(),typed.functions(),
                typed.indirect(),typed.vbr(),typed.unresolved(),typed.visited(),
                typed.limited(),typed.resetRecognized(),true,
                typed.cfgReviewComplete(),typed.cfgOmitted(),typed.pointersOmitted(),
                typed.sites(),typed.roles(),typed.resetFunctions(),sources);
        }catch(IllegalArgumentException expected){rejectedMismatch=true;}
        ok(rejectedMismatch,
            "Conflicting RESET incomplete summary and V2 sources refused");
        // A byte-valid but semantically impossible MCU call witness must be
        // rejected by the typed V2 decoder, not published as a source row.
        byte[] impossiblePc=encode(typed);
        byte[] witness=new byte[]{
            0,0,0,0,0,0,1,0x30,
            0,0,0,0,0,0,1,0x38,
            0,0,0,0,0,0,1,(byte)0x80};
        int at=-1;
        outer:for(int i=0;i<=impossiblePc.length-witness.length;i++){
            for(int j=0;j<witness.length;j++)
                if(impossiblePc[i+j]!=witness[j])continue outer;
            at=i;break;
        }
        ok(at>=0,"typed JSR byte witness found in V2 serialization");
        impossiblePc[at+15]=(byte)0x39;
        ok(decode(impossiblePc).isEmpty(),
            "Odd untrusted indirect JSR PC refused despite valid payload format");
        // V2 omits one unknown JSR and two MOVEC sources; this is
        // INCOMPLETE SOURCE INVENTORY, never promoted to no missing sites.
        ok(decoded.sourceInventory().omittedIndirect()==1 &&
            decoded.sourceInventory().omittedVbr()==2 &&
            decoded.sourceInventory().page(0,32).markdown()
                .contains("INCOMPLETE SOURCE INVENTORY/DISPLAY"),
            "Partial observed source inventory remains explicitly UNKNOWN");
        // The two independent V2 collections of RESET functions MUST agree.
        // A valid disk SHA does not authenticate contradictory evidence.
        boolean mismatchedReset=false;
        try {
            new Snapshot(typed.markdown(),typed.csv(),typed.functions(),
                typed.indirect(),typed.vbr(),typed.unresolved(),typed.visited(),
                typed.limited(),typed.resetRecognized(),typed.resetIncomplete(),
                typed.cfgReviewComplete(),typed.cfgOmitted(),typed.pointersOmitted(),
                typed.sites(),typed.roles(),List.of(0x100L),sources);
        }catch(IllegalArgumentException expected){mismatchedReset=true;}
        ok(mismatchedReset,"V2 CFG and source RESET sets must be identical");
        boolean repeatedReset=false;
        try {
            new Snapshot(typed.markdown(),typed.csv(),typed.functions(),
                typed.indirect(),typed.vbr(),typed.unresolved(),typed.visited(),
                typed.limited(),typed.resetRecognized(),typed.resetIncomplete(),
                typed.cfgReviewComplete(),typed.cfgOmitted(),typed.pointersOmitted(),
                typed.sites(),typed.roles(),List.of(0x100L,0x130L,0x130L),sources);
        }catch(IllegalArgumentException expected){repeatedReset=true;}
        ok(repeatedReset,"Duplicated CFG RESET counter must be refused");
        byte[] sourceSetTamper=encode(typed);
        // V2's canonical sorted sourceVisited set is the final array of
        // 64-bit addresses. Change a valid even 0x130 into even 0x132.
        ok(sourceSetTamper[sourceSetTamper.length-1]==0x30,
            "Real typed V2 source RESET record ends in 0x130");
        sourceSetTamper[sourceSetTamper.length-1]=(byte)0x32;
        ok(decode(sourceSetTamper).isEmpty(),
            "Byte-valid, checksum-resealable but different RESET sets denied");
        ok(eligibleForCompletedRestore(decoded) &&
            !eligibleForCompleteSourceInventory(decoded),
            "CFG completed does not certify omitted or uncertain JSR/MOVEC");
        ok(eligibleForCompletedRestore(old) &&
            !eligibleForCompleteSourceInventory(old),
            "Legacy V1 CFG-only restore cannot certify any source inventory");
        var confident=new HardwareResetIndirectVbrCorrelation.SourceInventory(
            List.of(new HardwareResetIndirectVbrCorrelation.Indirect(
                0x130L,0x138L,0x180L,true,false)),
            List.of(new HardwareResetIndirectVbrCorrelation.Vbr(
                0x130L,0x144L,0L,false)),
            Set.of(0x100L,0x130L),true,false,0,0);
        var confidentlyObserved=new Snapshot(
            typed.markdown(),typed.csv(),typed.functions(),typed.indirect(),
            typed.vbr(),typed.unresolved(),typed.visited(),typed.limited(),
            typed.resetRecognized(),typed.resetIncomplete(),
            typed.cfgReviewComplete(),typed.cfgOmitted(),typed.pointersOmitted(),
            typed.sites(),typed.roles(),typed.resetFunctions(),confident);
        ok(eligibleForCompleteSourceInventory(confidentlyObserved) &&
            eligibleForCompleteSourceInventory(
                decode(encode(confidentlyObserved)).orElseThrow()),
            "Fully retained bounded source inputs survive strictly typed V2");
        // SHA-256 of a disk blob is not authorship or a fresh source
        // re-extraction. Even a structurally complete V2 SOURCE inventory
        // must be stripped before a restored CFG is published to GUI/API.
        var fromDisk=restoredForReadOnlyDisplay(
            decode(encode(confidentlyObserved)).orElseThrow());
        ok(eligibleForCompletedRestore(fromDisk) &&
            !eligibleForCompleteSourceInventory(fromDisk) &&
            fromDisk.sourceInventory()==null &&
            fromDisk.markdown().contains("SOURCE INVENTORY UNVERIFIED") &&
            fromDisk.markdown().contains(confidentlyObserved.markdown()) &&
            fromDisk.resetFunctions().equals(confidentlyObserved.resetFunctions()) &&
            confidentlyObserved.sourceInventory()!=null,
            "Exact typed V2 source must not revive as a live source-page cursor");
        var incompleteSources=restoredForReadOnlyDisplay(decoded);
        ok(incompleteSources.sourceInventory()==null &&
            incompleteSources.resetIncomplete()==decoded.resetIncomplete() &&
            incompleteSources.cfgReviewComplete() &&
            !eligibleForCompleteSourceInventory(incompleteSources),
            "Omitted and uncertain JSR/MOVEC paths stay unpublished on restore");
        var legacy=restoredForReadOnlyDisplay(old);
        ok(legacy.sourceInventory()==null &&
            legacy.markdown().contains("SOURCE INVENTORY UNVERIFIED") &&
            legacy.cfgReviewComplete(),
            "Legacy V1 also carries explicit cache provenance warning");
        boolean incompleteRestore=false;
        try{restoredForReadOnlyDisplay(stopped);}
        catch(IllegalArgumentException expected){incompleteRestore=true;}
        ok(incompleteRestore,
            "Interrupted CFG cannot be sanitized into a publishable completed report");
        boolean unrooted=false;
        try {
            new Snapshot("only structure","",2,0,0,0,2,false,
                false,false,true,0,0,List.of(),List.of(),List.of(),
                new HardwareResetIndirectVbrCorrelation.SourceInventory(
                    List.of(),List.of(),Set.of(),false,false,0,0));
        }catch(IllegalArgumentException expected){unrooted=true;}
        ok(unrooted,
            "V2 cannot claim a complete RESET set without a recognized root");
        unrooted=false;
        try {
            new Snapshot("only structure","",2,0,0,0,2,false,
                true,false,true,0,0,List.of(),List.of(),List.of(),
                new HardwareResetIndirectVbrCorrelation.SourceInventory(
                    List.of(),List.of(),Set.of(),true,false,0,0));
        }catch(IllegalArgumentException expected){unrooted=true;}
        ok(unrooted,
            "V2 cannot claim a recognized RESET root with no source functions");
        var interrupted=new Snapshot(
            confidentlyObserved.markdown(),confidentlyObserved.csv(),
            confidentlyObserved.functions(),confidentlyObserved.indirect(),
            confidentlyObserved.vbr(),confidentlyObserved.unresolved(),
            confidentlyObserved.visited(),true,
            confidentlyObserved.resetRecognized(),
            confidentlyObserved.resetIncomplete(),true,0,0,
            confidentlyObserved.sites(),confidentlyObserved.roles(),
            confidentlyObserved.resetFunctions(),confident);
        ok(!eligibleForCompletedRestore(interrupted) &&
            !eligibleForCompleteSourceInventory(interrupted),
            "Limited CFG cannot be revived as a complete source report");
        System.out.println("HardwareDurableCfgReportSelfTest OK");
    }
}
