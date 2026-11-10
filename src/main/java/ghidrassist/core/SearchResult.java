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
    /** SHA-256 captured at PDF/text indexing, NOT a live-file attestation. */
    private final String indexedSha256;
    /** RAG library ID read from the SAME indexed hit, not a later lookup. */
    private final String indexedLibraryId;

    public SearchResult(String filename, String snippet, double score, int chunkId) {
        this(filename, snippet, score, chunkId, null, null, -1, false, null);
    }

    public SearchResult(String filename, String snippet, double score, int chunkId,
            String sourcePath, String sourceType, int pageNumber, boolean uncertainTable) {
        this(filename,snippet,score,chunkId,sourcePath,sourceType,
            pageNumber,uncertainTable,null);
    }

    public SearchResult(String filename, String snippet, double score, int chunkId,
            String sourcePath, String sourceType, int pageNumber,
            boolean uncertainTable,String indexedSha256) {
        this(filename,snippet,score,chunkId,sourcePath,sourceType,
            pageNumber,uncertainTable,indexedSha256,null);
    }

    public SearchResult(String filename, String snippet, double score, int chunkId,
            String sourcePath, String sourceType, int pageNumber,
            boolean uncertainTable,String indexedSha256,String indexedLibraryId) {
        this.filename = filename;
        this.snippet = snippet;
        this.score = score;
        this.chunkId = chunkId;
        this.sourcePath = sourcePath;
        this.sourceType = sourceType;
        this.pageNumber = pageNumber;
        this.uncertainTable = uncertainTable;
        this.indexedSha256 = indexedSha256;
        this.indexedLibraryId = indexedLibraryId;
    }

    public String getFilename() { return filename; }
    public String getSnippet() { return snippet; }
    public double getScore() { return score; }
    public int getChunkId() { return chunkId; }
    public String getSourcePath() { return sourcePath; }
    public String getSourceType() { return sourceType; }
    public int getPageNumber() { return pageNumber; }
    public boolean isUncertainTable() { return uncertainTable; }
    public String getIndexedSha256() { return indexedSha256; }
    public String getIndexedLibraryId() { return indexedLibraryId; }
}
