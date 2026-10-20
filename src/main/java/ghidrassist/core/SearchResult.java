package ghidrassist.core;

/** RAG search result with traceability to the original source page. */
public class SearchResult {
    private final String filename;
    private final String snippet;
    private final double score;
    private final int chunkId;
    private final String sourcePath;
    private final String sourceType;
    private final int pageNumber;
    private final boolean uncertainTable;

    public SearchResult(String filename, String snippet, double score, int chunkId) {
        this(filename, snippet, score, chunkId, null, null, -1, false);
    }

    public SearchResult(String filename, String snippet, double score, int chunkId,
            String sourcePath, String sourceType, int pageNumber, boolean uncertainTable) {
        this.filename = filename;
        this.snippet = snippet;
        this.score = score;
        this.chunkId = chunkId;
        this.sourcePath = sourcePath;
        this.sourceType = sourceType;
        this.pageNumber = pageNumber;
        this.uncertainTable = uncertainTable;
    }

    public String getFilename() { return filename; }
    public String getSnippet() { return snippet; }
    public double getScore() { return score; }
    public int getChunkId() { return chunkId; }
    public String getSourcePath() { return sourcePath; }
    public String getSourceType() { return sourceType; }
    public int getPageNumber() { return pageNumber; }
    public boolean isUncertainTable() { return uncertainTable; }
}
