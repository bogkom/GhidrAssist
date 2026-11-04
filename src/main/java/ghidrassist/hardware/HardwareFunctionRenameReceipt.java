package ghidrassist.hardware;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

/**
 * GA-13: bounded, deterministic record of an explicitly approved function
 * rename. The record lives in the Ghidra Program's OWN transactional Options,
 * never in user preferences, the original firmware or a remote service.
 *
 * The checksum detects accidental corruption, NOT malicious modification or
 * authorship. Ghidra SourceType.USER_DEFINED cannot distinguish human, AI,
 * scripts or extensions. Only the initiating operation is identified here.
 */
public final class HardwareFunctionRenameReceipt {
    private HardwareFunctionRenameReceipt() {}

    public static final String OPTIONS_CATEGORY = "GhidrAssist Function Rename Receipts";
    public static final String VERSION = "GA13-FUNCTION-RENAME-1";
    public static final int MAX_RECEIPT_BYTES = 3072;

    public record Entry(long entry, long reviewedModification,
            String sourceSha256, String beforeName, String afterName,
            String role, String registers, int writeSites) {
        public Entry {
            if (entry < 0 || entry > 0xffffffL || reviewedModification < 0 ||
                    sourceSha256 == null || sourceSha256.isEmpty() ||
                    sourceSha256.length() > 128 ||
                    beforeName == null || beforeName.isEmpty() ||
                    beforeName.length() > 256 ||
                    afterName == null || afterName.isEmpty() ||
                    afterName.length() > 256 ||
                    role == null || role.isEmpty() || role.length() > 128 ||
                    registers == null || registers.isEmpty() ||
                    registers.length() > 512 ||
                    writeSites < 3 || writeSites > 2048)
                throw new IllegalArgumentException("Incomplete or unbounded rename receipt");
        }

        /** Identifies the operation, not an authenticated human/AI actor. */
        public String operationOrigin() {
            return "GhidrAssist explicit function-name approval; actor UNKNOWN";
        }
    }

    public static String optionKey(long functionEntry) {
        if (functionEntry < 0 || functionEntry > 0xffffffL)
            throw new IllegalArgumentException("Function address outside MCU24 scope");
        return String.format(Locale.ROOT, "FN_%08X", functionEntry);
    }

    private static String field(String text) {
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String unfield(String encoded) {
        return new String(Base64.getUrlDecoder().decode(encoded),
            StandardCharsets.UTF_8);
    }

    private static String sha256(String payload) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 provider missing", impossible);
        }
    }

    /**
     * Canonical, versioned, tab-delimited Base64URL record with checksum.
     * Never accept a silent truncation of evidence fields.
     */
    public static String encode(Entry e) {
        if (e == null) throw new IllegalArgumentException("Missing rename receipt");
        String payload = String.join("\t", VERSION, optionKey(e.entry()),
            Long.toString(e.reviewedModification()), field(e.sourceSha256()),
            field(e.beforeName()), field(e.afterName()), field(e.role()),
            field(e.registers()), Integer.toString(e.writeSites()));
        String serialized = payload + "\t" + sha256(payload);
        if (serialized.getBytes(StandardCharsets.UTF_8).length > MAX_RECEIPT_BYTES)
            throw new IllegalArgumentException("Rename receipt exceeds persistence budget");
        return serialized;
    }

    /**
     * A corrupt/stale future schema is not treated as valid evidence.
     * A checksum provides integrity against accidents, NOT authenticity.
     */
    public static Entry decode(String serialized) {
        if (serialized == null || serialized.isEmpty() ||
                serialized.getBytes(StandardCharsets.UTF_8).length > MAX_RECEIPT_BYTES)
            throw new IllegalArgumentException("Missing or oversized stored receipt");
        String[] parts = serialized.split("\t", -1);
        if (parts.length != 10 || !VERSION.equals(parts[0]) ||
                !parts[1].matches("FN_[0-9A-F]{8}") ||
                !parts[9].matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("Unsupported rename receipt format");
        String payload = serialized.substring(0, serialized.lastIndexOf('\t'));
        if (!MessageDigest.isEqual(
                sha256(payload).getBytes(StandardCharsets.US_ASCII),
                parts[9].getBytes(StandardCharsets.US_ASCII)))
            throw new IllegalArgumentException("Rename receipt checksum mismatch");
        try {
            long entry = Long.parseLong(parts[1].substring(3), 16);
            Entry e = new Entry(entry, Long.parseLong(parts[2]),
                unfield(parts[3]), unfield(parts[4]), unfield(parts[5]),
                unfield(parts[6]), unfield(parts[7]), Integer.parseInt(parts[8]));
            if (!encode(e).equals(serialized))
                throw new IllegalArgumentException("Noncanonical rename receipt");
            return e;
        } catch (IllegalArgumentException badInput) {
            throw new IllegalArgumentException("Invalid stored rename receipt", badInput);
        }
    }
}
