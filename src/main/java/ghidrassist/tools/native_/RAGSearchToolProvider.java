package ghidrassist.tools.native_;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidrassist.core.RAGEngine;
import ghidrassist.core.RAGLibraries;
import ghidrassist.core.SearchResult;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolProvider;
import ghidrassist.tools.api.ToolResult;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/** Read-only native tools for PDF manuals and other indexed documents. */
public final class RAGSearchToolProvider implements ToolProvider {
    private static final String SEARCH = "ga_search_documents";
    private static final String PAGE = "ga_get_document_page";
    private volatile Program currentProgram;

    @Override public String getProviderName() { return "Documentation RAG"; }

    private static JsonObject stringProperty(String description) {
        JsonObject prop = new JsonObject();
        prop.addProperty("type", "string");
        prop.addProperty("description", description);
        return prop;
    }

    private static JsonObject integerProperty(String description) {
        JsonObject prop = new JsonObject();
        prop.addProperty("type", "integer");
        prop.addProperty("description", description);
        return prop;
    }

    private static JsonObject scopeProperty() {
        JsonObject scope = stringProperty("selected (default): checked libraries of active Ghidra program; all: entire indexed library");
        JsonArray values = new JsonArray();
        values.add("selected");
        values.add("all");
        scope.add("enum", values);
        return scope;
    }

    @Override public List<Tool> getTools() {
        JsonObject search = new JsonObject();
        search.addProperty("type", "object");
        JsonObject searchProps = new JsonObject();
        searchProps.add("query", stringProperty("Manual/PDF text query"));
        searchProps.add("filename", stringProperty("Optional exact indexed manual filename, e.g. MC68332UM.pdf"));
        searchProps.add("scope", scopeProperty());
        searchProps.add("offset", integerProperty("Zero-based search result offset"));
        searchProps.add("max_results", integerProperty("Page size (1..40, default 8)"));
        search.add("properties", searchProps);
        JsonArray required = new JsonArray();
        required.add("query");
        search.add("required", required);

        JsonObject page = new JsonObject();
        page.addProperty("type", "object");
        JsonObject pageProps = new JsonObject();
        pageProps.add("filename", stringProperty("Exact indexed document filename"));
        pageProps.add("page", integerProperty("Physical PDF page number, starting at 1"));
        pageProps.add("scope", scopeProperty());
        pageProps.add("offset", integerProperty("Zero-based character offset for large pages"));
        pageProps.add("max_chars", integerProperty("Maximum page characters to return (1..64000, default 16000)"));
        page.add("properties", pageProps);
        JsonArray pageRequired = new JsonArray();
        pageRequired.add("filename");
        pageRequired.add("page");
        page.add("required", pageRequired);
        return List.of(
            new NativeTool(SEARCH,
                "Search indexed manuals, honoring the active project's checked RAG libraries by default. "
                + "Set filename for exact source selection. Returns physical PDF pages, excerpts, and source provenance.",
                search, getProviderName()),
            new NativeTool(PAGE,
                "Read indexed full text of a specified physical PDF page, with pagination and source-library filtering. "
                + "For table layout always verify the original PDF visually.",
                page, getProviderName()));
    }

    @Override public boolean handlesTool(String name) { return SEARCH.equals(name) || PAGE.equals(name); }
    @Override public void setContext(Program program) { currentProgram = program; }

    private static int readInt(JsonObject args, String key, int defaultValue, int min, int max) {
        if (!args.has(key)) return defaultValue;
        int value = args.get(key).getAsInt();
        if (value < min || value > max) throw new IllegalArgumentException(
            key + " must be in range " + min + ".." + max);
        return value;
    }

    private String scope(JsonObject args) {
        String value = args.has("scope") ? args.get("scope").getAsString() : "selected";
        if (!value.equals("selected") && !value.equals("all"))
            throw new IllegalArgumentException("scope must be selected or all");
        return value;
    }

    private Set<String> activeLibraries(String scope) {
        return scope.equals("all") ? RAGLibraries.allIds() : RAGLibraries.active(currentProgram);
    }

    @Override public CompletableFuture<ToolResult> executeTool(String name, JsonObject args) {
        if (!handlesTool(name)) return CompletableFuture.completedFuture(
            ToolResult.error("Unknown documentation tool"));
        if (args == null) return CompletableFuture.completedFuture(ToolResult.error("Missing arguments"));

        return CompletableFuture.supplyAsync(() -> {
            try {
                String scope = scope(args);
                Set<String> active = activeLibraries(scope);
                if (SEARCH.equals(name)) {
                    if (!args.has("query") || !args.get("query").isJsonPrimitive())
                        return ToolResult.error("Missing query");
                    String query = args.get("query").getAsString();
                    if (query.isBlank()) return ToolResult.error("Empty query");
                    String filename = args.has("filename") ? args.get("filename").getAsString().trim() : null;
                    int offset = readInt(args, "offset", 0, 0, 1000);
                    int pageSize = readInt(args, "max_results", 8, 1, 40);
                    int count = Math.min(1100, offset + pageSize + 1);
                    List<SearchResult> hits = RAGEngine.search(query, count, active, filename);
                    int start = Math.min(offset, hits.size());
                    int end = Math.min(hits.size(), start + pageSize);
                    StringBuilder out = new StringBuilder();
                    out.append("RAG_SCOPE: ").append(scope).append(" LIBRARIES: ").append(active)
                        .append(" FILENAME_FILTER: ").append(filename == null ? "ALL" : filename).append("\n");
                    for (int i = start; i < end; i++) {
                        SearchResult hit = hits.get(i);
                        out.append("SOURCE: ").append(hit.getFilename())
                            .append(" PDF_PAGE: ").append(hit.getPageNumber())
                            .append(" CHUNK_ID: ").append(hit.getChunkId())
                            .append(" PATH: ").append(hit.getSourcePath())
                            .append(" ORIGINAL_PAGE_URI: ")
                            .append(hit.getSourcePath() == null ? "UNAVAILABLE" :
                                new java.io.File(hit.getSourcePath()).toURI().toASCIIString()
                                + ("pdf".equalsIgnoreCase(hit.getSourceType())
                                    && hit.getPageNumber() > 0 ? "#page=" + hit.getPageNumber() : ""))
                            .append(" LAYOUT_UNCERTAIN: ").append(hit.isUncertainTable())
                            .append("\nEXCERPT: ").append(hit.getSnippet()).append("\n\n");
                    }
                    boolean more = hits.size() > end;
                    out.append("returnedCount=").append(end - start)
                        .append(" offset=").append(offset)
                        .append(" hasMore=").append(more)
                        .append(" truncated=").append(more)
                        .append(" nextOffset=").append(more ? Integer.toString(end) : "null")
                        .append("\nWARNING: Verify CPU bitfields and multi-column tables on original PDF page.");
                    return ToolResult.success(out.toString());
                }

                if (!args.has("filename") || !args.has("page"))
                    return ToolResult.error("filename and physical PDF page required");
                String filename = args.get("filename").getAsString().trim();
                int physicalPage = readInt(args, "page", 0, 1, Integer.MAX_VALUE);
                if (scope.equals("selected") && !active.contains(RAGEngine.getDocumentLibrary(filename)))
                    return ToolResult.error("Document is not in an active RAG library: " + filename);
                int offset = readInt(args, "offset", 0, 0, Integer.MAX_VALUE);
                int limit = readInt(args, "max_chars", 16000, 1, 64000);
                String content = RAGEngine.getIndexedPdfPage(filename, physicalPage);
                int from = Math.min(offset, content.length());
                int to = (int) Math.min((long) content.length(), (long) from + limit);
                boolean more = to < content.length();
                return ToolResult.success("SOURCE: " + filename + " PDF_PAGE: " + physicalPage
                    + " RAG_SCOPE: " + scope
                    + " totalCharacters=" + content.length()
                    + " returnedCharacters=" + (to - from)
                    + " offset=" + offset
                    + " hasMore=" + more
                    + " nextOffset=" + (more ? Integer.toString(to) : "null")
                    + "\nPAGE_TEXT:\n" + content.substring(from, to)
                    + "\nWARNING: Indexed text does not preserve all table geometry; visually inspect original PDF.");
            } catch (Exception ex) {
                return ToolResult.error("Documentation tool failed: " + ex.getMessage());
            }
        });
    }
}
