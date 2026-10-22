package ghidrassist.core;

import java.util.Locale;

/** Retrieve manual evidence with the human question, not multi-KB #func text. */
public final class RAGQueryFocus {
    private RAGQueryFocus() {}
    public static String focus(String userQuery){
        if(userQuery==null || userQuery.isBlank())return "";
        String cleaned=userQuery.replaceAll("(?i)#(?:func|hardware|line|addr)\\b"," ").strip();
        String lower=cleaned.toLowerCase(Locale.ROOT);
        if(lower.contains("simcr") || lower.contains("fffa00") ||
                lower.contains("7ffa00")) {
            // Prefer SIMCR definition over generic QSM/TPU addresses mentioned in
            // broad instructions; MC68332 remains only a library hypothesis.
            return "SIMCR MM $YFFA00 Module Configuration Register "+
                "Module Mapping bit reset 0x0040";
        }
        return cleaned;
    }
}
