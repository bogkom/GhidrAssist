package ghidrassist.hardware;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** GA-08/13 deterministic serialized receipt integrity and guarded audit. */
public final class HardwareScopedVariableReceiptSelfTest {
    private HardwareScopedVariableReceiptSelfTest(){}
    private static int checks;
    private static void ok(boolean condition,String label){
        checks++;if(!condition)throw new AssertionError(label);
    }
    private static void rejects(Runnable action,String label){
        boolean refused=false;
        try{action.run();}catch(IllegalArgumentException expected){refused=true;}
        ok(refused,label);
    }
    private static void stale(Runnable action,String label){
        boolean refused=false;
        try{action.run();}catch(IllegalStateException expected){refused=true;}
        ok(refused,label);
    }
    public static void main(String[] args) {
        var kind=HardwareScopedVariableReview.Kind.PARAMETER;
        var original=new HardwareScopedVariableReceipt.Entry(0x5a0L,kind,0,
            "stack:00000008:4","param_1","ga_arg_ptr_candidate_0",3,
            "a".repeat(64));
        String serialized=HardwareScopedVariableReceipt.encode(original);
        ok(HardwareScopedVariableReceipt.decode(serialized).equals(original) &&
                original.optionKey().equals("PV_000005A0_P_0000") &&
                original.origin().contains("actor UNKNOWN"),
            "Canonical persist/reopen round trip binds Function, kind, ordinal and storage");
        var local=new HardwareScopedVariableReceipt.Entry(0x640L,
            HardwareScopedVariableReview.Kind.LOCAL,0,
            "stack:fffffff8:4","local_8","ga_local_ptr_candidate_0",3,
            "a".repeat(64));
        var rows=List.of(
            new HardwareScopedVariableReceipt.Observation(
                original.optionKey(),serialized,original.afterName(),
                original.storage(),true,true),
            new HardwareScopedVariableReceipt.Observation(
                local.optionKey(),HardwareScopedVariableReceipt.encode(local),
                local.afterName(),local.storage(),true,true));
        var audit=HardwareScopedVariableReceipt.inspect(rows,5,"a".repeat(64));
        ok(audit.count(HardwareScopedVariableReceipt.State.CURRENT_APPROVED_NAME)==2 &&
                audit.csv().lines().count()==3 &&
                audit.csv().contains("actor UNKNOWN"),
            "Read-only Program Options audit correlates two current approved variables");
        var revisionOwner=new Object();
        var snapshot=HardwareAnalysisRevision.capture(revisionOwner,5,
            "68000:BE:32:CPU32","a".repeat(64),true);
        ok(audit.csvRevisionBound(snapshot,()->snapshot).equals(audit.csv()),
            "Current Program revision produces identical deterministic CSV");
        var invalid=HardwareAnalysisRevision.capture(revisionOwner,6,
            "68000:BE:32:CPU32","a".repeat(64),true);
        stale(()->audit.csvRevisionBound(snapshot,()->invalid),
            "Native Undo or changed analysis revision invalidates audit export");
        var foreign=HardwareAnalysisRevision.capture(new Object(),5,
            "68000:BE:32:CPU32","a".repeat(64),true);
        stale(()->audit.csvRevisionBound(snapshot,()->foreign),
            "Different Program owner cannot reuse approved variable audit");
        AtomicInteger reads=new AtomicInteger();
        stale(()->audit.csvRevisionBound(snapshot,
            ()->reads.getAndIncrement()==0?snapshot:invalid),
            "Revision race between CSV pre and post check rejects all rows");
        ok(reads.get()==2,"Both revision fences executed");
        var badStorage=HardwareScopedVariableReceipt.inspect(List.of(
            new HardwareScopedVariableReceipt.Observation(
                original.optionKey(),serialized,original.afterName(),
                "stack:0000000c:4",true,true)),5,"a".repeat(64));
        ok(badStorage.count(HardwareScopedVariableReceipt.State.STORAGE_CHANGED)==1,
            "Same ordinal and approved name with changed variable storage fails closed");
        var badType=HardwareScopedVariableReceipt.inspect(List.of(
            new HardwareScopedVariableReceipt.Observation(
                original.optionKey(),serialized,original.afterName(),
                original.storage(),false,true)),5,"a".repeat(64));
        ok(badType.count(HardwareScopedVariableReceipt.State.TYPE_OR_SOURCE_CHANGED)==1,
            "Non-pointer local cannot borrow a pointer approval receipt");
        var badName=HardwareScopedVariableReceipt.inspect(List.of(
            new HardwareScopedVariableReceipt.Observation(
                original.optionKey(),serialized,"human_override",
                original.storage(),true,true)),5,"a".repeat(64));
        ok(badName.count(HardwareScopedVariableReceipt.State.NAME_CHANGED_AFTER_APPROVAL)==1,
            "Manual rename is not still an approved current name");
        var badSha=HardwareScopedVariableReceipt.inspect(rows,5,"b".repeat(64));
        ok(badSha.count(HardwareScopedVariableReceipt.State.SOURCE_CHANGED)==2,
            "Different source import checksum invalidates both function claims");
        var unknownSha=HardwareScopedVariableReceipt.inspect(rows,5,"UNKNOWN");
        ok(unknownSha.count(HardwareScopedVariableReceipt.State.SOURCE_UNVERIFIED)==2,
            "Unknown source provenance is not considered verified");
        var absent=HardwareScopedVariableReceipt.inspect(List.of(
            new HardwareScopedVariableReceipt.Observation(
                original.optionKey(),serialized,null,null,false,false)),5,
            "a".repeat(64));
        ok(absent.count(HardwareScopedVariableReceipt.State.VARIABLE_MISSING)==1,
            "Removed parameter is not current approved evidence");
        var duplicateName=new HardwareScopedVariableReceipt.Entry(0x640L,
            kind,0,original.storage(),original.beforeName(),
            original.afterName(),3,"a".repeat(64));
        ok(!original.optionKey().equals(duplicateName.optionKey()),
            "Independent Functions with matching candidate names retain distinct receipt keys");
        rejects(()->HardwareScopedVariableReceipt.decode(
            serialized.substring(0,serialized.length()-1)+"0"),
            "Checksum alteration refuses corrupt transaction receipt");
        rejects(()->HardwareScopedVariableReceipt.decode("GA13-UNKNOWN"),
            "Unexpected schema never silently upgraded");
        rejects(()->HardwareScopedVariableReceipt.inspect(
            List.of(rows.get(0),rows.get(0)),5,"a".repeat(64)),
            "Duplicate persisted Option receipt keys rejected");
        rejects(()->HardwareScopedVariableReceipt.inspect(List.of(
            new HardwareScopedVariableReceipt.Observation(
                local.optionKey(),serialized,original.afterName(),
                original.storage(),true,true)),5,"a".repeat(64)),
            "Receipt cannot be replayed at another function/kind/ordinal key");
        rejects(()->HardwareScopedVariableReceipt.optionKey(0x1000000L,kind,0),
            "Unbounded Function entry refused");
        rejects(()->HardwareScopedVariableReceipt.decode("x".repeat(
            HardwareScopedVariableReceipt.MAX_BYTES+1)),
            "Oversized stored receipt denied");
        rejects(()->audit.csvRevisionBound(
            HardwareAnalysisRevision.capture(revisionOwner,7,
                "68000:BE:32:CPU32","a".repeat(64),true),()->snapshot),
            "Wrong capture revision never legitimizes snapshot");
        boolean immutable=false;
        try{audit.rows().clear();}catch(UnsupportedOperationException expected){
            immutable=true;
        }
        ok(immutable,"Audit rows immutable");
        System.out.println("GA08/13 POINTER TRANSACTION RECEIPT PASS checks="+checks);
    }
}
