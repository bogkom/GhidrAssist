package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** GA-13 deterministic, Ghidra-free saved operation consistency audit. */
public final class HardwareFunctionRenameAuditSelfTest {
    private HardwareFunctionRenameAuditSelfTest(){}
    private static int assertions;
    private static void check(boolean yes,String detail){
        assertions++;
        if(!yes)throw new AssertionError(detail);
    }
    private static void rejects(Runnable action,String why){
        boolean bad=false;
        try{action.run();}
        catch(IllegalArgumentException expected){bad=true;}
        check(bad,why);
    }
    private static HardwareFunctionRenameAudit.Observation row(long entry,
            String current,String source) {
        var receipt=new HardwareFunctionRenameReceipt.Entry(entry,12L,
            "a".repeat(64),"FUN_"+String.format("%08X",entry),
            "HW_MC68332_CONFIGURE_CHIP_SELECTS_CANDIDATE_"+
                String.format("%08X",entry),
            "CONFIGURE_CHIP_SELECTS","CSBAR0|CSOR0|CSPAR0",3);
        return new HardwareFunctionRenameAudit.Observation(
            HardwareFunctionRenameReceipt.optionKey(entry),
            HardwareFunctionRenameReceipt.encode(receipt),current,source);
    }
    public static void main(String[] args){
        var original=row(0x640,
            "HW_MC68332_CONFIGURE_CHIP_SELECTS_CANDIDATE_00000640",
            "USER_DEFINED");
        var older=row(0x5a0,
            "HW_MC68332_CONFIGURE_CHIP_SELECTS_CANDIDATE_000005A0",
            "USER_DEFINED");
        var audit=HardwareFunctionRenameAudit.inspect(
            List.of(original,older),43L,"a".repeat(64));
        check(audit.rows().size()==2 &&
            audit.rows().get(0).receipt().entry()==0x5a0 &&
            audit.rows().get(1).receipt().entry()==0x640,
            "audit must be deterministically ordered by function address");
        check(audit.count(HardwareFunctionRenameAudit.State.CURRENT_APPROVED_NAME)==2 &&
            audit.count(HardwareFunctionRenameAudit.State.NAME_CHANGED_AFTER_APPROVAL)==0,
            "current approved function names explicitly matched");
        String csv=audit.csv();
        check(csv.startsWith("function_entry,before_name,approved_name,current_name,") &&
            csv.contains("ghidra_source_type,audit_state,operation_origin") &&
            csv.contains("actor UNKNOWN") &&
            csv.contains("CURRENT_APPROVED_NAME") &&
            csv.lines().count()==3,
            "read-only CSV identifies operator, original/current name and state");
        check(!csv.contains("author VERIFIED"),
            "SourceType USER_DEFINED cannot prove a human or model actor");
        // Source-only revision guards around a CSV snapshot. This is a
        // read-only audit, not new Apply authorization or durable Undo log.
        Object sameProgram=new Object();
        var captured=HardwareAnalysisRevision.capture(sameProgram,43L,
            "68000:BE:32:CPU32","a".repeat(64),true);
        var current=HardwareAnalysisRevision.capture(sameProgram,43L,
            "68000:BE:32:CPU32","a".repeat(64),true);
        var changed=HardwareAnalysisRevision.capture(sameProgram,44L,
            "68000:BE:32:CPU32","a".repeat(64),true);
        var otherOwner=HardwareAnalysisRevision.capture(new Object(),43L,
            "68000:BE:32:CPU32","a".repeat(64),true);
        var otherProfile=HardwareAnalysisRevision.capture(sameProgram,43L,
            "68000:BE:32:CPU32","a".repeat(64),false);
        check(audit.csvRevisionBound(captured,()->current).equals(csv),
            "Same Program/analysis snapshot exports the exact original CSV");
        for(var invalid:List.of(changed,otherOwner,otherProfile)){
            boolean refused=false;
            try{audit.csvRevisionBound(captured,()->invalid);}
            catch(IllegalStateException expected){refused=true;}
            check(refused,"Changed revision/owner/profile must not export stale CSV");
        }
        AtomicInteger reads=new AtomicInteger();
        boolean raceRefused=false;
        try{audit.csvRevisionBound(captured,
            ()->reads.getAndIncrement()==0?current:changed);}
        catch(IllegalStateException expected){raceRefused=true;}
        check(raceRefused && reads.get()==2,
            "Revision edit during CSV building discards the entire report");
        rejects(()->audit.csvRevisionBound(null,()->current),
            "Missing source revision token rejected");
        rejects(()->audit.csvRevisionBound(captured,null),
            "Missing current Program revision supplier rejected");
        var wrongSnapshot=HardwareAnalysisRevision.capture(sameProgram,42L,
            "68000:BE:32:CPU32","a".repeat(64),true);
        rejects(()->audit.csvRevisionBound(wrongSnapshot,()->wrongSnapshot),
            "Capture from different audit revision cannot legitimize snapshot");
        var wrongSha=HardwareAnalysisRevision.capture(sameProgram,43L,
            "68000:BE:32:CPU32","b".repeat(64),true);
        rejects(()->audit.csvRevisionBound(wrongSha,()->wrongSha),
            "Source checksum mismatch cannot legitimize audit export");

        var diverged=HardwareFunctionRenameAudit.inspect(
            List.of(row(0x5a0,"MANUAL_EDIT","USER_DEFINED")),44,"a".repeat(64));
        check(diverged.count(
            HardwareFunctionRenameAudit.State.NAME_CHANGED_AFTER_APPROVAL)==1,
            "external name change must never remain approved-current");
        var missing=HardwareFunctionRenameAudit.inspect(
            List.of(row(0x5a0,null,null)),45,"a".repeat(64));
        check(missing.count(HardwareFunctionRenameAudit.State.FUNCTION_MISSING)==1 &&
            missing.csv().contains("(function missing)"),
            "deleted function retains stored receipt but not fictional current name");
        check(HardwareFunctionRenameAudit.inspect(
            List.of(row(0x5a0,"HW_MC68332_CONFIGURE_CHIP_SELECTS_CANDIDATE_000005A0",
                "ANALYSIS")),46,"a".repeat(64)).count(
            HardwareFunctionRenameAudit.State.SOURCE_TYPE_CHANGED)==1,
            "SourceType divergence prevents false accepted-current label");
        check(HardwareFunctionRenameAudit.inspect(
            List.of(older),47,"b".repeat(64)).count(
            HardwareFunctionRenameAudit.State.SOURCE_CHANGED)==1,
            "different executable source SHA prevents false import agreement");
        check(HardwareFunctionRenameAudit.inspect(
            List.of(older),48,"UNKNOWN").count(
            HardwareFunctionRenameAudit.State.SOURCE_UNVERIFIED)==1,
            "unknown import SHA cannot be presented as a verified identity");
        check(HardwareFunctionRenameAudit.inspect(List.of(),50,"UNKNOWN").rows().isEmpty(),
            "Undo removes receipt; absent record is not invented history");
        var unsafe=row(0x5a0,"=HYPERLINK(\"https://evil.invalid\")",
            "USER_DEFINED");
        String safe=HardwareFunctionRenameAudit.inspect(
            List.of(unsafe),51,"a".repeat(64)).csv();
        check(safe.contains("\"'=HYPERLINK(\"\"https://evil.invalid\"\")\""),
            "untrusted name CSV formula/quotes must be escaped");
        var longName=row(0x5a0,"+1".repeat(240),"USER_DEFINED");
        String bounded=HardwareFunctionRenameAudit.inspect(
            List.of(longName),52,"a".repeat(64)).csv();
        check(bounded.length()<3000 && bounded.contains("NAME_CHANGED_AFTER_APPROVAL"),
            "bounded untrusted displayed name preserves explicit divergence");
        boolean immutable=false;
        try{audit.rows().clear();}
        catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"stored audit snapshot is immutable");
        rejects(()->HardwareFunctionRenameAudit.inspect(null,0,"UNKNOWN"),
            "null observation inventory must fail closed");
        rejects(()->HardwareFunctionRenameAudit.inspect(List.of(original,original),0,
            "UNKNOWN"),"duplicate Options keys rejected");
        rejects(()->HardwareFunctionRenameAudit.inspect(
            java.util.Arrays.asList(original,null),0,"UNKNOWN"),
            "null Options entry rejected");
        rejects(()->HardwareFunctionRenameAudit.inspect(
            List.of(new HardwareFunctionRenameAudit.Observation(
                "FN_000005A0",original.serialized(),null,null)),0,"UNKNOWN"),
            "Options key versus entry mismatch must fail");
        rejects(()->HardwareFunctionRenameAudit.inspect(
            List.of(new HardwareFunctionRenameAudit.Observation(
                "FN_00000640",original.serialized()+"X",null,null)),0,"UNKNOWN"),
            "tampered checksum must fail");
        rejects(()->HardwareFunctionRenameAudit.inspect(
            List.of(new HardwareFunctionRenameAudit.Observation(
                "FN_00000640",original.serialized().replace(
                    "GA13-FUNCTION-RENAME-1","GA13-FUNCTION-RENAME-2"),
                null,null)),0,"UNKNOWN"),
            "unsupported schema must fail");
        List<HardwareFunctionRenameAudit.Observation> oversized=new ArrayList<>();
        for(int i=0;i<=HardwareFunctionRenameAudit.MAX_ROWS;i++)oversized.add(original);
        rejects(()->HardwareFunctionRenameAudit.inspect(oversized,0,"UNKNOWN"),
            "audit size limit fails closed without truncating entries");
        System.out.println("HardwareFunctionRenameAuditSelfTest PASS assertions="+assertions);
    }
}
