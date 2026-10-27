package ghidrassist.tools.context;

import ghidrassist.context.*;

public class ToolResultContextSelfTest {
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    public static void main(String[] args) {
        String first = "SOURCE: one.pdf PDF_PAGE: 256 RAG_SCOPE: selected";
        String middle = "SOURCE: two.pdf PDF_PAGE: 17 RAG_SCOPE: all";
        String footer = "returnedCount=2 offset=4 hasMore=true nextOffset=6";
        String raw = first + "\n" + "excerpt ".repeat(1000) + "\n" + middle + "\n" + "body ".repeat(1000) + "\n" + footer;
        for (int budget : new int[] {0, 10, 2200}) {
            String truncated = ToolResultContext.truncate(raw, budget);
            check(truncated.contains(first) && truncated.contains(middle) && truncated.contains(footer), "Metadata must survive budget " + budget);
            check(truncated.length() < raw.length(), "Excerpts must actually shrink");
            String repeated = ToolResultContext.truncate(truncated, 4);
            check(repeated.contains(first) && repeated.contains(middle) && repeated.contains(footer), "Repeated shrinking must preserve metadata");
        }
        ContextWindowManager manager = new ContextWindowManager(new ContextWindowConfig(), new CharacterBasedTokenCounter(), null, null);
        String context = manager.truncateToolResult(raw, 8);
        check(context.contains(first) && context.contains(middle) && context.contains(footer), "Conversation context metadata");
        check(ToolResultContext.truncate("short", 10).equals("short"), "Small responses unchanged");
        check(ToolResultContext.truncate(null, 1) == null, "Null unchanged");
        check(ToolResultContext.truncate("", 0).isEmpty(), "Empty unchanged");
        String ordinary = "start" + "body".repeat(1000) + "end";
        String concise = ToolResultContext.truncate(ordinary, 30);
        check(concise.startsWith("start") && concise.endsWith("end"), "Non-RAG head/tail behavior");
        System.out.println("ToolResultContextSelfTest PASS");
    }
}
