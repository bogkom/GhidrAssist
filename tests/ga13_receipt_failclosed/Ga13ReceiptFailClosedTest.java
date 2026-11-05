import ghidrassist.hardware.HardwareFunctionRenameReceipt;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Isolated GA-13 codec regression: no firmware, Ghidra database, or network. */
public final class Ga13ReceiptFailClosedTest {
    private static int checks;
    private static void ok(boolean value, String label) {
        checks++;
        if (!value) throw new AssertionError(label);
    }
    private static void rejected(Runnable action, String label) {
        boolean failed = false;
        try { action.run(); } catch (IllegalArgumentException expected) { failed = true; }
        ok(failed, label);
    }
    private static String mutate(String text, int field, String replacement) {
        String[] tokens = text.split("\t", -1);
        tokens[field] = replacement;
        return String.join("\t", tokens);
    }
    private static String b64(String data) {
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }
    public static void main(String[] args) {
        var entry = new HardwareFunctionRenameReceipt.Entry(
            0x130, 7L, "a".repeat(64), "FUN_00000130", "SIMCR_INIT",
            "MMIO_WRITE", "SIMCR, SYPCR", 3);
        String wire = HardwareFunctionRenameReceipt.encode(entry);
        ok(HardwareFunctionRenameReceipt.decode(wire).equals(entry), "canonical roundtrip");
        ok(HardwareFunctionRenameReceipt.decode(wire).operationOrigin().contains("UNKNOWN"),
            "no verified actor attribution");
        ok(HardwareFunctionRenameReceipt.optionKey(0x130).equals("FN_00000130"),
            "canonical key");
        rejected(() -> HardwareFunctionRenameReceipt.optionKey(-1), "negative address");
        rejected(() -> HardwareFunctionRenameReceipt.optionKey(0x1000000), "MCU24 boundary");
        rejected(() -> HardwareFunctionRenameReceipt.decode(null), "null serialized");
        rejected(() -> HardwareFunctionRenameReceipt.decode(""), "empty serialized");
        rejected(() -> HardwareFunctionRenameReceipt.decode(wire + "x"), "checksum suffix");
        rejected(() -> HardwareFunctionRenameReceipt.decode(wire.replaceFirst(
            "GA13-FUNCTION-RENAME-1", "GA13-FUNCTION-RENAME-2")), "future schema");
        rejected(() -> HardwareFunctionRenameReceipt.decode(mutate(wire, 1, "FN_01000000")),
            "out of range key");
        rejected(() -> HardwareFunctionRenameReceipt.decode(mutate(wire, 2, "-1")),
            "negative revision");
        rejected(() -> HardwareFunctionRenameReceipt.decode(mutate(wire, 3, "%%%")),
            "invalid base64 checksum");
        rejected(() -> HardwareFunctionRenameReceipt.decode(mutate(wire, 4, b64("other"))),
            "changed before name");
        rejected(() -> HardwareFunctionRenameReceipt.decode(mutate(wire, 5, b64("other"))),
            "changed after name");
        rejected(() -> HardwareFunctionRenameReceipt.decode(mutate(wire, 8, "2")),
            "below minimum write sites");
        rejected(() -> HardwareFunctionRenameReceipt.decode(mutate(wire, 8, "2049")),
            "above maximum write sites");
        rejected(() -> HardwareFunctionRenameReceipt.decode(wire + "\t"), "extra field");
        rejected(() -> HardwareFunctionRenameReceipt.decode(wire + "x".repeat(4000)),
            "oversized input");
        rejected(() -> new HardwareFunctionRenameReceipt.Entry(
            0, 1, "a", "before", "after", "role", "r", 0), "invalid new entry");
        var boundary = new HardwareFunctionRenameReceipt.Entry(
            0xffffff, Long.MAX_VALUE, "a".repeat(128), "b".repeat(256),
            "c".repeat(256), "d".repeat(128), "e".repeat(512), 2048);
        ok(HardwareFunctionRenameReceipt.decode(
            HardwareFunctionRenameReceipt.encode(boundary)).equals(boundary),
            "maximum valid bounded entry");
        System.out.println("GA13 RECEIPT FAIL-CLOSED PASS checks=" + checks);
    }
}
