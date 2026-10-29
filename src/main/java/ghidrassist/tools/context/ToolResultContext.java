package ghidrassist.tools.context;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/** Keep protocol metadata outside the excerpt budget, even across repeated truncation. */
public final class ToolResultContext {
    private static final Pattern METADATA = Pattern.compile(
        "(?:\\b(?:SOURCE|PDF_PAGE|RAG_SCOPE):|\\b(?:returnedCount|offset|hasMore|nextOffset|totalCount|totalCharacters|returnedCharacters|charOffset|nextCharOffset)=)");
    private ToolResultContext() { }

    public static String metadata(String content) {
        if (content == null) return "";
        Set<String> lines = new LinkedHashSet<>();
        content.lines().filter(line -> METADATA.matcher(line).find()).forEach(lines::add);
        return String.join("\n", lines);
    }

    /** The excerpt budget may be exceeded by mandatory source/pagination metadata. */
    public static String truncate(String content, int excerptCharacters) {
        if (content == null || content.isEmpty()) return content;
        if (excerptCharacters < 0) throw new IllegalArgumentException("Negative excerpt budget");
        if (content.length() <= excerptCharacters) return content;
        int head = (int)(excerptCharacters * 0.7);
        int tail = excerptCharacters - head;
        String headers = metadata(content);
        String excerpt = content.substring(0, head) + "\n[output truncated]\n"
            + content.substring(content.length() - tail);
        return headers.isEmpty() ? excerpt
            : "[TOOL_RESULT_METADATA]\n" + headers + "\n[/TOOL_RESULT_METADATA]\n" + excerpt;
    }
}
