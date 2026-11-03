package ghidrassist.hardware;

/** Pure Java negative modal/transaction race contract. */
public final class HardwareFunctionRenameRevisionGateSelfTest {
    private static int count;
    private static void ok(boolean yes,String reason){
        count++;
        if(!yes)throw new AssertionError(reason);
    }
    private static void reject(Runnable r,String why){
        boolean blocked=false;
        try{r.run();}catch(IllegalStateException expected){blocked=true;}
        ok(blocked,why);
    }
    public static void main(String[] args){
        Object program=new Object(),other=new Object();
        var receipt=HardwareAnalysisRevision.capture(program,7,
            "68000:BE:32:CPU32","original-import-sha",true);
        HardwareFunctionRenameRevisionGate.requireCurrent(receipt,
            program,7,"68000:BE:32:CPU32","original-import-sha",true);
        ok(true,"fresh reviewed source accepted");
        reject(()->HardwareFunctionRenameRevisionGate.requireCurrent(receipt,
            program,8,"68000:BE:32:CPU32","original-import-sha",true),
            "late database edit rejects even unchanged function name");
        reject(()->HardwareFunctionRenameRevisionGate.requireCurrent(receipt,
            program,9,"68000:BE:32:CPU32","original-import-sha",true),
            "undo/redo prevents stale naming decisions");
        reject(()->HardwareFunctionRenameRevisionGate.requireCurrent(receipt,
            other,7,"68000:BE:32:CPU32","original-import-sha",true),
            "another program with same name/hash cannot reuse receipt");
        reject(()->HardwareFunctionRenameRevisionGate.requireCurrent(receipt,
            program,7,"68000:BE:32:CPU32","other-import",true),
            "source metadata difference rejects naming");
        reject(()->HardwareFunctionRenameRevisionGate.requireCurrent(receipt,
            program,7,"OTHER:LE:32:default","original-import-sha",true),
            "language difference rejects naming");
        reject(()->HardwareFunctionRenameRevisionGate.requireCurrent(receipt,
            program,7,"68000:BE:32:CPU32","original-import-sha",false),
            "CPU32 generic survey never authorizes concrete names");
        reject(()->HardwareFunctionRenameRevisionGate.requireCurrent(null,
            program,7,"68000:BE:32:CPU32","original-import-sha",true),
            "absent review receipt rejected");
        var survey=HardwareAnalysisRevision.capture(program,7,
            "68000:BE:32:CPU32","original-import-sha",false);
        reject(()->HardwareFunctionRenameRevisionGate.requireCurrent(survey,
            program,7,"68000:BE:32:CPU32","original-import-sha",true),
            "generic profile snapshot cannot masquerade as MC68332");
        System.out.println("HardwareFunctionRenameRevisionGateSelfTest PASS: assertions="+count);
    }
}
