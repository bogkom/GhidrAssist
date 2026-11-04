package ghidrassist.hardware;

import java.util.Arrays;

/** GA-13 source-only receipt integrity, bounded canonical encoding and scope. */
public final class HardwareFunctionRenameReceiptSelfTest {
    private HardwareFunctionRenameReceiptSelfTest() {}
    private static int assertions;
    private static void check(boolean v,String why) {
        assertions++;
        if(!v)throw new AssertionError(why);
    }
    private static void reject(Runnable action,String why) {
        boolean rejected=false;
        try { action.run(); }
        catch(IllegalArgumentException expected) {rejected=true;}
        check(rejected,why);
    }
    public static void main(String[] args) {
        var original=new HardwareFunctionRenameReceipt.Entry(
            0x5a0L,73L,"ab".repeat(32),"FUN_000005A0",
            "HW_MC68332_CONFIGURE_CHIP_SELECTS_CANDIDATE_000005A0",
            "CONFIGURE_CHIP_SELECTS","CSBAR0|CSOR0|CSPAR0",3);
        String serialized=HardwareFunctionRenameReceipt.encode(original);
        check(HardwareFunctionRenameReceipt.decode(serialized).equals(original),
            "approved batch-row receipt is canonically reversible");
        check(serialized.equals(HardwareFunctionRenameReceipt.encode(
            HardwareFunctionRenameReceipt.decode(serialized))),
            "canonical serialized bytes independent of reloading");
        check(serialized.startsWith(HardwareFunctionRenameReceipt.VERSION+"\t") &&
            serialized.length()<HardwareFunctionRenameReceipt.MAX_RECEIPT_BYTES,
            "version and persistence budget explicit");
        check(HardwareFunctionRenameReceipt.optionKey(0x5a0L).equals(
            "FN_000005A0") &&
            !HardwareFunctionRenameReceipt.optionKey(0x640L).equals(
                HardwareFunctionRenameReceipt.optionKey(0x5a0L)),
            "per-entry Options names are deterministic and nonoverlapping");
        check(original.operationOrigin().contains("actor UNKNOWN") &&
            !original.operationOrigin().contains("human verified"),
            "SourceType cannot establish human or AI authorship");
        var unicode=new HardwareFunctionRenameReceipt.Entry(
            0xfffa00L,74L,"UNKNOWN","FUN_0000A000",
            "HW_MC68332_TEST_CANDIDATE_00FFFA00",
            "ROLE","A0 → SIMCR, \u2060",3);
        check(HardwareFunctionRenameReceipt.decode(
            HardwareFunctionRenameReceipt.encode(unicode)).equals(unicode),
            "Unicode source and unknown original executable hash remain explicit");
        reject(()->HardwareFunctionRenameReceipt.decode(
            serialized.replace("FN_000005A0","FN_00000640")),
            "address edit invalidates checksum");
        reject(()->HardwareFunctionRenameReceipt.decode(
            serialized.substring(0,serialized.length()-2)),
            "truncated checksum rejected");
        reject(()->HardwareFunctionRenameReceipt.decode(
            serialized.replace(HardwareFunctionRenameReceipt.VERSION,
                "GA13-FUNCTION-RENAME-2")),
            "unknown newer receipt schema rejected");
        reject(()->HardwareFunctionRenameReceipt.decode(""),
            "missing persisted metadata is not a completed audit");
        reject(()->HardwareFunctionRenameReceipt.decode("z".repeat(4000)),
            "oversized persisted metadata rejected before parsing");
        reject(()->HardwareFunctionRenameReceipt.optionKey(0x1000000L),
            "25-bit Ghidra function entry does not fit selected MC68332");
        reject(()->HardwareFunctionRenameReceipt.optionKey(-1L),
            "negative function entry cannot create a new Options key");
        reject(()->new HardwareFunctionRenameReceipt.Entry(
            0x5a0L,73L,"ab".repeat(32),"FUN_000005A0",
            "BAD","ROLE","evidence",2),
            "unreviewed two-site hint cannot become a durable approval receipt");
        reject(()->new HardwareFunctionRenameReceipt.Entry(
            0x5a0L,73L,"ab".repeat(32),"FUN_000005A0",
            "BAD","ROLE","x".repeat(513),3),
            "oversized source evidence cannot be truncated into an invented proof");
        reject(()->new HardwareFunctionRenameReceipt.Entry(
            0x5a0L,73L,"ab".repeat(32),"FUN_000005A0",
            "=FORMULA"+ "X".repeat(300),"ROLE","registers",3),
            "unsafe or oversized proposed label cannot be stored");
        var differentSource=new HardwareFunctionRenameReceipt.Entry(
            0x5a0L,73L,"UNKNOWN","FUN_000005A0",
            original.afterName(),original.role(),original.registers(),3);
        check(!HardwareFunctionRenameReceipt.encode(differentSource)
                .equals(serialized),
            "original import identity change yields distinct checksum evidence");
        check(!HardwareFunctionRenameReceipt.encode(new
            HardwareFunctionRenameReceipt.Entry(
                0x5a0L,74L,original.sourceSha256(),original.beforeName(),
                original.afterName(),original.role(),original.registers(),3))
                .equals(serialized),
            "approved analysis revision is part of persisted receipt");
        System.out.println("HardwareFunctionRenameReceiptSelfTest PASS: assertions="+assertions);
    }
}
