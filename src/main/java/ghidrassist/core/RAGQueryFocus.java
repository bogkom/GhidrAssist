package ghidrassist.core;

import java.util.Locale;

/**
 * Focus documentation retrieval without dropping independent parts of a user's question.
 * Hardware register names are search anchors, not proof of the target MCU identity.
 */
public final class RAGQueryFocus {
    private RAGQueryFocus() {}

    public static boolean isChipSelectQuery(String query) {
        if (query == null) return false;
        return query.toLowerCase(Locale.ROOT).matches(
            "(?s).*\\b(?:csbar[0-9]*|csor[0-9]*|cspar[0-9]*|chip[ -]?select|cs0|cs1)\\b.*");
    }

    public static String focus(String userQuery) {
        if (userQuery == null || userQuery.isBlank()) return "";
        String cleaned = userQuery.replaceAll("(?i)#(?:func|hardware|line|addr)\\b", " ")
            .strip();
        String lower = cleaned.toLowerCase(Locale.ROOT);
        boolean simcr = lower.contains("simcr") || lower.contains("fffa00") ||
            lower.contains("7ffa00");
        boolean chipSelect = isChipSelectQuery(cleaned);
        if (chipSelect) {
            String anchors = "MC68332 conditional register mapping: CSBAR0 CSBAR1 " +
                "CSOR0 CSOR1 CSPAR0 Chip-Select Base Address Registers " +
                "Chip-Select Option Registers Table 4-22 DSACK BYTE R/W block size";
            return anchors + (simcr ? " SIMCR MM Module Mapping" : "");
        }
        if (simcr) {
            return "SIMCR MM $YFFA00 Module Configuration Register " +
                "Module Mapping bit reset 0x0040";
        }
        return cleaned;
    }
}
