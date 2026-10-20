package ghidrassist.core;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.*;
import org.apache.lucene.index.*;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.*;
import org.apache.lucene.search.similarities.BM25Similarity;
import org.apache.lucene.store.*;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import ghidra.framework.preferences.Preferences;
import ghidrassist.GAUtils;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class RAGEngine {
    private static Directory indexDirectory;
    private static Analyzer analyzer;
    private static IndexWriter indexWriter;
    private static ReentrantLock indexLock = new ReentrantLock();
    private static final int MAX_SNIPPET_LENGTH = 500;
    private static final int MAX_CACHE_SIZE = 1000; // Adjust based on your needs
    private static Cache<String, double[]> embeddingCache = CacheBuilder.newBuilder()
        .maximumSize(MAX_CACHE_SIZE)
        .expireAfterWrite(24, TimeUnit.HOURS)
        .build();

    static {
        try {
            initialize();
        } catch (IOException e) {
            throw new RuntimeException("Failed to initialize RAGEngine", e);
        }
    }

    private static void initialize() throws IOException {
        String indexPath = Preferences.getProperty("GhidrAssist.LuceneIndexPath", "");
        GAUtils.OperatingSystem os = GAUtils.OperatingSystem.detect();

        if (indexPath == null || indexPath.isEmpty()) {
            indexPath = GAUtils.getDefaultLucenePath(os);
            System.out.println("No index path specified. Using default: " + indexPath);
            Files.createDirectories(Paths.get(indexPath));
        }
        
        initializeIndex(indexPath);
    }

    private static void initializeIndex(String indexPath) throws IOException {
        Path path = Paths.get(indexPath);
        indexDirectory = FSDirectory.open(path);
        analyzer = new StandardAnalyzer();
        IndexWriterConfig config = new IndexWriterConfig(analyzer);
        indexWriter = new IndexWriter(indexDirectory, config);

        // Load persisted embeddings into cache
        loadEmbeddingsFromIndex();
    }

    /**
     * Load embeddings from Lucene index into memory cache.
     * Called during initialization to restore embeddings after restart.
     */
    private static void loadEmbeddingsFromIndex() throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            StoredFields storedFields = reader.storedFields();
            for (int i = 0; i < reader.maxDoc(); i++) {
                Document doc = storedFields.document(i);
                String filename = doc.get("filename");
                IndexableField chunkIdField = doc.getField("chunk_id");
                String embeddingStr = doc.get("embedding");

                if (filename != null && chunkIdField != null && embeddingStr != null && !embeddingStr.isEmpty()) {
                    int chunkId = chunkIdField.numericValue().intValue();
                    double[] embedding = deserializeEmbedding(embeddingStr);
                    if (embedding != null) {
                        String chunkKey = filename + "_" + chunkId;
                        embeddingCache.put(chunkKey, embedding);
                    }
                }
            }
            System.out.println("Loaded " + embeddingCache.size() + " embeddings from index");
        } finally {
            indexLock.unlock();
        }
    }

    /**
     * Serialize embedding array to string for storage.
     */
    private static String serializeEmbedding(double[] embedding) {
        if (embedding == null || embedding.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < embedding.length; i++) {
            if (i > 0) sb.append(",");
            sb.append(embedding[i]);
        }
        return sb.toString();
    }

    /**
     * Deserialize embedding string back to array.
     */
    private static double[] deserializeEmbedding(String str) {
        if (str == null || str.isEmpty()) {
            return null;
        }
        String[] parts = str.split(",");
        double[] embedding = new double[parts.length];
        for (int i = 0; i < parts.length; i++) {
            embedding[i] = Double.parseDouble(parts[i]);
        }
        return embedding;
    }

    private static APIProvider getProvider() {
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            throw new RuntimeException("No API provider configured");
        }
        return config.createProvider();
    }

    public static void ingestDocuments(List<File> files) throws IOException {
        ingestDocumentsWithReport(files, RAGLibraries.UNIVERSAL);
    }

    public static void ingestDocuments(List<File> files, String libraryId) throws IOException {
        ingestDocumentsWithReport(files, libraryId);
    }

    /** Reindex only changed files. PDF pages are indexed as complete logical chunks. */
    public static List<String> ingestDocumentsWithReport(List<File> files, String libraryId) throws IOException {
        if (!RAGLibraries.allIds().contains(libraryId)) throw new IOException("Unknown RAG library: " + libraryId);
        List<String> notices = new ArrayList<>();
        if (files == null || files.isEmpty()) return notices;
        APIProvider provider = getProvider();
        boolean embed = supportsEmbeddings(provider);
        for (File file : files) {
            if (file == null || !file.isFile() || !file.canRead())
                throw new IOException("Cannot read document: " + file);
            String name = file.getName();
            String lower = name.toLowerCase(java.util.Locale.ROOT);
            boolean pdf = lower.endsWith(".pdf");
            if (!pdf && !isTextDocument(lower))
                throw new IOException("Unsupported document extension: " + name);
            String path = file.getCanonicalPath();
            String digest = sha256(file);
            Document old = findDocumentMetadata(name);
            if (old != null) {
                String previousPath = old.get("source_path");
                if (previousPath == null || previousPath.isBlank())
                    throw new IOException("Legacy document already indexed: " + name
                        + ". Delete the old entry before importing its new version.");
                if (!previousPath.equals(path))
                    throw new IOException("Filename collision: " + name
                        + ". Rename one of the files to use both documents.");
                if (digest.equals(old.get("sha256")) &&
                    libraryId.equals(libraryOf(old))) {
                    notices.add(name + ": unchanged; skipped indexing.");
                    continue;
                }
            }
            List<Document> chunks = new ArrayList<>();
            Map<String, double[]> newEmbeddings = new HashMap<>();
            final boolean useEmbeddings = embed;
            final long fileSize = file.length();
            final int[] id = {0};
            if (pdf) {
                RAGPdfExtractor.Report report = RAGPdfExtractor.extract(file, (page, content, uncertain) -> {
                    // Whole page is one chunk: do not sever a register/bit table mid-page.
                    Document doc = newSourceDocument(name, libraryId, path, digest, "pdf",
                        fileSize, id[0], page, uncertain, content);
                    maybeEmbed(provider, useEmbeddings, content, name, id[0], doc, newEmbeddings);
                    chunks.add(doc);
                    id[0]++;
                });
                if (report.pagesWithoutText > 0) notices.add(name + ": " + report.pagesWithoutText
                    + "/" + report.pages + " pages without text layer were skipped (OCR not available).");
                if (report.uncertainTablePages > 0) notices.add(name + ": possible tables/columns on "
                    + report.uncertainTablePages + " pages; check the original PDF for exact layout.");
            } else {
                // Ordinary text and source code remain supported.
                String content = java.nio.file.Files.readString(file.toPath(), java.nio.charset.StandardCharsets.UTF_8);
                for (String chunk : chunkContent(content)) {
                    Document doc = newSourceDocument(name, libraryId, path, digest, "text",
                        fileSize, id[0], -1, false, chunk);
                    maybeEmbed(provider, useEmbeddings, chunk, name, id[0], doc, newEmbeddings);
                    chunks.add(doc);
                    id[0]++;
                }
            }
            if (chunks.isEmpty()) throw new IOException("Empty document: " + name);
            // Atomic replacement: a failed PDF extraction must never delete the old version.
            indexLock.lock();
            try {
                indexWriter.updateDocuments(new Term("filename", name), chunks);
                indexWriter.commit();
                embeddingCache.asMap().keySet().removeIf(key -> key.startsWith(name + "_"));
                newEmbeddings.forEach(embeddingCache::put);
            } finally { indexLock.unlock(); }
            notices.add(name + ": indexed " + chunks.size() + (pdf ? " PDF pages." : " text chunks."));
        }
        return notices;
    }

    private static boolean isTextDocument(String name) {
        for (String ext : new String[]{".txt", ".md", ".c", ".h", ".cpp", ".hpp", ".py",
                ".java", ".rs", ".asm"}) {
            if (name.endsWith(ext)) return true;
        }
        return false;
    }

    private static void maybeEmbed(APIProvider provider, boolean enabled, String text,
                                   String fileName, int chunkId, Document document,
                                   Map<String, double[]> newEmbeddings) throws IOException {
        if (!enabled) return;
        try {
            double[] embedding = provider.getEmbeddings(text);
            if (embedding != null && embedding.length > 0) {
                document.add(new StoredField("embedding", serializeEmbedding(embedding)));
                newEmbeddings.put(fileName + "_" + chunkId, embedding);
            }
        } catch (Exception e) {
            // If a supposedly supported provider rejects embeddings, fail clearly
            // instead of silently indexing a partial document under a hybrid configuration.
            throw new IOException("Embeddings failed for " + fileName + " chunk " + chunkId
                + ": " + e.getMessage(), e);
        }
    }

    private static Document newSourceDocument(String name, String libraryId, String sourcePath,
            String sha, String type, long bytes, int chunkId, int page, boolean uncertain,
            String content) {
        Document document = new Document();
        document.add(new StringField("filename", name, Field.Store.YES));
        document.add(new StringField("library", libraryId, Field.Store.YES));
        document.add(new IntPoint("chunk_id", chunkId));
        document.add(new StoredField("chunk_id", chunkId));
        document.add(new StoredField("file_size", bytes));
        document.add(new TextField("content", content, Field.Store.YES));
        document.add(new StoredField("source_path", sourcePath));
        document.add(new StoredField("source_type", type));
        document.add(new StoredField("sha256", sha));
        document.add(new StoredField("page_number", page));
        document.add(new StoredField("uncertain_table", uncertain ? 1 : 0));
        return document;
    }

    private static String libraryOf(Document d) {
        String value = d.get("library");
        return value == null ? RAGLibraries.UNIVERSAL : value;
    }

    private static Document findDocumentMetadata(String name) throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher s = new IndexSearcher(reader);
            TopDocs hits = s.search(new TermQuery(new Term("filename", name)), 1);
            return hits.scoreDocs.length == 0 ? null : s.storedFields().document(hits.scoreDocs[0].doc);
        } finally { indexLock.unlock(); }
    }

    private static String sha256(File file) throws IOException {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
                byte[] buf = new byte[65536];
                for (int len; (len = in.read(buf)) != -1;) digest.update(buf, 0, len);
            }
            StringBuilder hex = new StringBuilder(64);
            for (byte b : digest.digest()) hex.append(String.format("%02x", b & 255));
            return hex.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Only non-embedding backends use keyword search; network failures are NOT hidden. */
    private static boolean supportsEmbeddings(APIProvider provider) {
        switch (provider.getType()) {
            case OPENAI_OAUTH:
            case GEMINI_OAUTH:
            case GEMINI_PLATFORM_API:
            case XAI_PLATFORM_API:
            case ANTHROPIC_PLATFORM_API:
            case ANTHROPIC_CLAUDE_CLI:
                return false;
            default:
                return true;
        }
    }

    private static boolean embeddingUnsupported(Exception error) {
        Throwable current = error;
        while (current != null) {
            String msg = current.getMessage();
            String lower = msg == null ? "" : msg.toLowerCase(java.util.Locale.ROOT);
            if ((lower.contains("embedding") &&
                (lower.contains("not supported") || lower.contains("does not support") ||
                 lower.contains("unsupportedoperationexception"))) ||
                (current instanceof UnsupportedOperationException)) return true;
            current = current.getCause();
        }
        return false;
    }

    public static List<SearchResult> hybridSearch(String queryStr, int maxResults) throws Exception {
        return hybridSearch(queryStr, maxResults, RAGLibraries.allIds());
    }

    public static List<SearchResult> hybridSearch(String queryStr, int maxResults,
                                                   Set<String> activeLibraries) throws Exception {
        if (activeLibraries.isEmpty()) return Collections.emptyList();
        APIProvider provider = getProvider();
        if (!supportsEmbeddings(provider)) return search(queryStr, maxResults, activeLibraries);
        double[] queryEmbedding;
        try {
            queryEmbedding = provider.getEmbeddings(queryStr);
        } catch (Exception e) {
            if (embeddingUnsupported(e)) return search(queryStr, maxResults, activeLibraries);
            throw e;
        }
        if (queryEmbedding == null || queryEmbedding.length == 0)
            return search(queryStr, maxResults, activeLibraries);

        List<SearchResult> results = new ArrayList<>();
        List<VectorSearchResult> vectorResults = searchSimilar(queryEmbedding, maxResults, activeLibraries);
        List<SearchResult> keywordResults = search(queryStr, maxResults, activeLibraries);
        results.addAll(vectorResults.stream()
            .map(RAGEngine::enrichVectorResult)
            .collect(Collectors.toList()));
        results.addAll(keywordResults);
        return results.stream()
            .sorted((a, b) -> Double.compare(b.getScore(), a.getScore()))
            .limit(maxResults)
            .collect(Collectors.toList());
    }

    private static final double SEMANTIC_MIN_THRESHOLD = 0.50;  // Low floor - just filter noise
    private static final double SEMANTIC_RELATIVE_THRESHOLD = 0.95;  // Must be within 95% of top score
    private static final int SEMANTIC_MAX_RESULTS = 5;  // Hard limit on semantic results

    private static List<VectorSearchResult> searchSimilar(double[] queryEmbedding, int maxResults,
                                                           Set<String> activeLibraries) throws IOException {
        Map<String, String> fileLibraries = getAllFileLibraries();
        // First pass: collect all candidates above minimum threshold, sorted by score
        List<VectorSearchResult> candidates = embeddingCache.asMap().entrySet().stream()
            .map(entry -> {
                String key = entry.getKey();
                double[] embedding = entry.getValue();
                double similarity = cosineSimilarity(queryEmbedding, embedding);

                int lastUnderscore = key.lastIndexOf('_');
                String filename = key.substring(0, lastUnderscore);
                int chunkId = Integer.parseInt(key.substring(lastUnderscore + 1));
                if (!activeLibraries.contains(fileLibraries.getOrDefault(filename, RAGLibraries.UNIVERSAL)))
                    return null;

                try {
                    String snippet = getSnippetFromIndex(filename, chunkId);
                    return new VectorSearchResult(filename, snippet, similarity, chunkId);
                } catch (IOException e) {
                    return null;
                }
            })
            .filter(result -> result != null && result.getScore() >= SEMANTIC_MIN_THRESHOLD)
            .sorted((a, b) -> Double.compare(b.getScore(), a.getScore()))
            .collect(Collectors.toList());

        if (candidates.isEmpty()) {
            return candidates;
        }

        // Apply relative threshold: only keep results within 95% of top score
        double topScore = candidates.get(0).getScore();
        double relativeThreshold = topScore * SEMANTIC_RELATIVE_THRESHOLD;

        int limit = Math.min(maxResults, SEMANTIC_MAX_RESULTS);
        return candidates.stream()
            .filter(result -> result.getScore() >= relativeThreshold)
            .limit(limit)
            .collect(Collectors.toList());
    }

    private static double cosineSimilarity(double[] vecA, double[] vecB) {
        double dotProduct = 0.0;
        double normA = 0.0;
        double normB = 0.0;
        for (int i = 0; i < vecA.length; i++) {
            dotProduct += vecA[i] * vecB[i];
            normA += Math.pow(vecA[i], 2);
            normB += Math.pow(vecB[i], 2);
        }
        return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
    }

    private static String getSnippetFromIndex(String filename, int chunkId) throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);
            Query query = new BooleanQuery.Builder()
                    .add(new TermQuery(new Term("filename", filename)), BooleanClause.Occur.MUST)
                    .add(IntPoint.newExactQuery("chunk_id", chunkId), BooleanClause.Occur.MUST)
                    .build();

            TopDocs topDocs = searcher.search(query, 1);
            if (topDocs.totalHits.value == 0) {
                return "";
            }
            StoredFields storedFields = searcher.storedFields();
            Document doc = storedFields.document(topDocs.scoreDocs[0].doc);
            return doc.get("content");
        } finally {
            indexLock.unlock();
        }
    }

    private static List<String> chunkContent(String content) {
        List<String> chunks = new ArrayList<>();
        int start = 0;
        while (start < content.length()) {
            int end = start + 500;
            if (end >= content.length()) {
                chunks.add(content.substring(start));
                break;
            }
            int splitPos = content.indexOf("\n\n", end);
            if (splitPos == -1) {
                chunks.add(content.substring(start));
                break;
            } else {
                chunks.add(content.substring(start, splitPos + 2));
                start = splitPos + 2;
            }
        }
        return chunks;
    }

    private static String readFileContent(File file) throws IOException {
        return new String(Files.readAllBytes(file.toPath()));
    }

    public static List<SearchResult> search(String queryStr, int maxResults) throws Exception {
        return search(queryStr, maxResults, RAGLibraries.allIds());
    }

    public static List<SearchResult> search(String queryStr, int maxResults,
                                            Set<String> activeLibraries) throws Exception {
        List<SearchResult> results = new ArrayList<>();
        if (activeLibraries.isEmpty()) return results;

        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);
            searcher.setSimilarity(new BM25Similarity());

            BooleanQuery.Builder queryBuilder = new BooleanQuery.Builder();

            QueryParser contentParser = new QueryParser("content", analyzer);
            Query contentQuery = contentParser.parse(QueryParser.escape(queryStr));
            queryBuilder.add(new BoostQuery(contentQuery, 2.0f), BooleanClause.Occur.SHOULD);

            QueryParser filenameParser = new QueryParser("filename", analyzer);
            Query filenameQuery = filenameParser.parse(QueryParser.escape(queryStr));
            queryBuilder.add(filenameQuery, BooleanClause.Occur.SHOULD);

            // Library filter runs INSIDE Lucene, before the top-k limit.
            BooleanQuery.Builder libraryFilter = new BooleanQuery.Builder();
            for (String id : activeLibraries) {
                libraryFilter.add(new TermQuery(new Term("library", id)), BooleanClause.Occur.SHOULD);
            }
            // Pre-patch indexed files have no 'library' field; treat them as Universal.
            if (activeLibraries.contains(RAGLibraries.UNIVERSAL)) {
                BooleanQuery.Builder legacy = new BooleanQuery.Builder();
                legacy.add(new MatchAllDocsQuery(), BooleanClause.Occur.MUST);
                legacy.add(new WildcardQuery(new Term("library", "*")), BooleanClause.Occur.MUST_NOT);
                libraryFilter.add(legacy.build(), BooleanClause.Occur.SHOULD);
            }
            queryBuilder.add(libraryFilter.build(), BooleanClause.Occur.FILTER);

            TopDocs topDocs = searcher.search(queryBuilder.build(), maxResults * 3);

            List<ScoreDoc> scoreDocs = Arrays.asList(topDocs.scoreDocs);
            scoreDocs.sort((a, b) -> Float.compare(b.score, a.score));

            Set<String> uniqueFiles = new HashSet<>();
            for (ScoreDoc sd : scoreDocs) {
                Document doc = searcher.storedFields().document(sd.doc);
                String filename = doc.get("filename");
                String content = doc.get("content");
                int chunkId = doc.getField("chunk_id").numericValue().intValue();

                if (!uniqueFiles.contains(filename) && uniqueFiles.size() < maxResults) {
                    String snippet = generateSnippet(content, queryStr);
                    // Normalize BM25 score to 0-1 range using saturation function
                    // This aligns with cosine similarity scoring (also 0-1)
                    double normalizedScore = sd.score / (sd.score + 1.0);
                    results.add(sourceSearchResult(doc, snippet, normalizedScore));
                    uniqueFiles.add(filename);
                }
            }
        } finally {
            indexLock.unlock();
        }

        return results;
    }

    public static List<String> listIndexedFiles() throws IOException {
        List<String> files = new ArrayList<>();
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            for (org.apache.lucene.index.LeafReaderContext leaf : reader.leaves()) {
                org.apache.lucene.util.Bits live = leaf.reader().getLiveDocs();
                StoredFields fields = leaf.reader().storedFields();
                for (int i = 0; i < leaf.reader().maxDoc(); i++) {
                    if (live != null && !live.get(i)) continue;
                    String filename = fields.document(i).get("filename");
                    if (filename != null && !files.contains(filename)) files.add(filename);
                }
            }
        } finally {
            indexLock.unlock();
        }
        return files;
    }

    /** Include legacy entries (missing library field) in Universal. */
    private static Map<String, String> getAllFileLibraries() throws IOException {
        Map<String, String> result = new HashMap<>();
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            for (org.apache.lucene.index.LeafReaderContext leaf : reader.leaves()) {
                org.apache.lucene.util.Bits live = leaf.reader().getLiveDocs();
                StoredFields fields = leaf.reader().storedFields();
                for (int i = 0; i < leaf.reader().maxDoc(); i++) {
                    if (live != null && !live.get(i)) continue;
                    Document doc = fields.document(i);
                    String name = doc.get("filename");
                    if (name != null) result.put(name, libraryOf(doc));
                }
            }
        } finally { indexLock.unlock(); }
        return result;
    }

    public static String getDocumentLibrary(String filename) throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);
            TopDocs hits = searcher.search(new TermQuery(new Term("filename", filename)), 1);
            if (hits.scoreDocs.length == 0) return null;
            String id = searcher.storedFields().document(hits.scoreDocs[0].doc).get("library");
            return id == null ? RAGLibraries.UNIVERSAL : id;
        } finally { indexLock.unlock(); }
    }

    /** Preserve the full indexed text and stored embedding, without re-importing the source file. */
    public static void moveDocument(String filename, String destination) throws IOException {
        if (!RAGLibraries.allIds().contains(destination)) throw new IOException("Unknown RAG library");
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);
            TopDocs hits = searcher.search(new TermQuery(new Term("filename", filename)), reader.numDocs());
            if (hits.scoreDocs.length == 0) throw new IOException("Document not found: " + filename);
            List<Document> replacements = new ArrayList<>();
            for (ScoreDoc hit : hits.scoreDocs) {
                Document original = searcher.storedFields().document(hit.doc);
                Document doc = new Document();
                doc.add(new StringField("filename", filename, Field.Store.YES));
                doc.add(new StringField("library", destination, Field.Store.YES));
                int chunkId = original.getField("chunk_id").numericValue().intValue();
                doc.add(new IntPoint("chunk_id", chunkId));
                doc.add(new StoredField("chunk_id", chunkId));
                IndexableField size = original.getField("file_size");
                if (size != null) doc.add(new StoredField("file_size", size.numericValue().longValue()));
                doc.add(new TextField("content", original.get("content"), Field.Store.YES));
                String embedding = original.get("embedding");
                if (embedding != null) doc.add(new StoredField("embedding", embedding));
                for (String key : new String[]{"source_path", "source_type", "sha256"}) {
                    String value = original.get(key);
                    if (value != null) doc.add(new StoredField(key, value));
                }
                for (String key : new String[]{"page_number", "uncertain_table"}) {
                    IndexableField field = original.getField(key);
                    if (field != null) doc.add(new StoredField(key, field.numericValue().intValue()));
                }
                replacements.add(doc);
            }
            indexWriter.updateDocuments(new Term("filename", filename), replacements);
            indexWriter.commit();
        } finally { indexLock.unlock(); }
    }

    public static void moveLibraryDocuments(String source, String destination) throws IOException {
        for (Map.Entry<String, String> entry : getAllFileLibraries().entrySet()) {
            if (source.equals(entry.getValue())) moveDocument(entry.getKey(), destination);
        }
    }

    private static SearchResult sourceSearchResult(Document doc, String snippet, double score) {
        IndexableField id = doc.getField("chunk_id");
        int chunk = id == null ? 0 : id.numericValue().intValue();
        IndexableField pageField = doc.getField("page_number");
        int page = pageField == null ? -1 : pageField.numericValue().intValue();
        IndexableField tableField = doc.getField("uncertain_table");
        boolean uncertain = tableField != null && tableField.numericValue().intValue() != 0;
        if ("pdf".equals(doc.get("source_type")) && snippet != null && snippet.length() > 4000) {
            // Don't send extremely long pages to the model; original page remains accessible.
            snippet = snippet.substring(0, 4000) + "\n[EXCERPT TRUNCATED - OPEN ORIGINAL PDF]";
        }
        return new SearchResult(doc.get("filename"), snippet, score, chunk,
            doc.get("source_path"), doc.get("source_type"), page, uncertain);
    }

    private static SearchResult enrichVectorResult(VectorSearchResult vector) {
        try {
            indexLock.lock();
            try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
                IndexSearcher searcher = new IndexSearcher(reader);
                Query query = new BooleanQuery.Builder()
                    .add(new TermQuery(new Term("filename", vector.getFilename())), BooleanClause.Occur.MUST)
                    .add(IntPoint.newExactQuery("chunk_id", vector.getChunkId()), BooleanClause.Occur.MUST)
                    .build();
                TopDocs hits = searcher.search(query, 1);
                if (hits.scoreDocs.length == 0) throw new IOException("Search result vanished: " + vector.getFilename());
                Document doc = searcher.storedFields().document(hits.scoreDocs[0].doc);
                return sourceSearchResult(doc, vector.getSnippet(), vector.getScore());
            } finally { indexLock.unlock(); }
        } catch (IOException ex) {
            throw new java.io.UncheckedIOException("Unable to fetch RAG source metadata", ex);
        }
    }

    public static void deleteDocument(String filename) throws IOException {
        indexLock.lock();
        try {
            Term term = new Term("filename", filename);
            indexWriter.deleteDocuments(term);
            indexWriter.commit();
            // Also remove embeddings from cache
            embeddingCache.asMap().entrySet().removeIf(entry -> entry.getKey().startsWith(filename + "_"));
        } finally {
            indexLock.unlock();
        }
    }

    /**
     * Get the chunk count for a specific document.
     * @param filename The document filename
     * @return Number of chunks for this document
     */
    public static int getChunkCount(String filename) throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);
            Query query = new TermQuery(new Term("filename", filename));
            TopDocs topDocs = searcher.search(query, Integer.MAX_VALUE);
            return (int) topDocs.totalHits.value;
        } finally {
            indexLock.unlock();
        }
    }

    /**
     * Get the total chunk count across all documents.
     * @return Total number of chunks in the index
     */
    public static int getTotalChunkCount() throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            return reader.numDocs();
        } finally {
            indexLock.unlock();
        }
    }

    /**
     * Get the number of cached embeddings.
     * @return Number of embeddings in cache
     */
    public static int getEmbeddingCount() {
        return (int) embeddingCache.size();
    }

    /**
     * Get the original file size for a document.
     * @param filename The document filename
     * @return File size in bytes, or -1 if not found
     */
    public static long getDocumentSize(String filename) throws IOException {
        indexLock.lock();
        try (DirectoryReader reader = DirectoryReader.open(indexWriter)) {
            IndexSearcher searcher = new IndexSearcher(reader);
            Query query = new TermQuery(new Term("filename", filename));
            TopDocs topDocs = searcher.search(query, 1);
            if (topDocs.totalHits.value > 0) {
                Document doc = searcher.storedFields().document(topDocs.scoreDocs[0].doc);
                IndexableField sizeField = doc.getField("file_size");
                if (sizeField != null) {
                    return sizeField.numericValue().longValue();
                }
            }
            return -1; // Not found or no size stored (legacy documents)
        } finally {
            indexLock.unlock();
        }
    }

    /**
     * Perform semantic (vector) search using embeddings.
     * @param queryStr The search query
     * @param maxResults Maximum number of results
     * @return List of search results
     */
    public static List<SearchResult> semanticSearch(String queryStr, int maxResults) throws Exception {
        return semanticSearch(queryStr, maxResults, RAGLibraries.allIds());
    }

    public static List<SearchResult> semanticSearch(String queryStr, int maxResults,
                                                    Set<String> activeLibraries) throws Exception {
        if (activeLibraries.isEmpty()) return Collections.emptyList();
        APIProvider provider = getProvider();
        if (!supportsEmbeddings(provider)) return search(queryStr, maxResults, activeLibraries);
        double[] queryEmbedding;
        try {
            queryEmbedding = provider.getEmbeddings(queryStr);
        } catch (Exception e) {
            if (embeddingUnsupported(e)) return search(queryStr, maxResults, activeLibraries);
            throw e;
        }
        if (queryEmbedding == null || queryEmbedding.length == 0)
            return search(queryStr, maxResults, activeLibraries);
        List<VectorSearchResult> vectorResults = searchSimilar(queryEmbedding, maxResults, activeLibraries);
        return vectorResults.stream()
            .map(RAGEngine::enrichVectorResult)
            .collect(Collectors.toList());
    }

    /**
     * Clear the entire index and embedding cache.
     */
    public static void clearIndex() throws IOException {
        indexLock.lock();
        try {
            indexWriter.deleteAll();
            indexWriter.commit();
            embeddingCache.invalidateAll();
        } finally {
            indexLock.unlock();
        }
    }

    private static String generateSnippet(String content, String query) {
        String[] queryTerms = query.toLowerCase().split("\s+");
        int bestPosition = content.length();
        for (String term : queryTerms) {
            int pos = content.toLowerCase().indexOf(term);
            if (pos != -1 && pos < bestPosition) {
                bestPosition = pos;
            }
        }

        int start = Math.max(0, bestPosition - MAX_SNIPPET_LENGTH / 2);
        int end = Math.min(content.length(), start + MAX_SNIPPET_LENGTH);
        String snippet = content.substring(start, end);

        if (start > 0) snippet = "..." + snippet;
        if (end < content.length()) snippet = snippet + "...";

        return snippet;
    }
}

class EmbeddingData {
    private double[] embedding;
    private String provider;

    public EmbeddingData(double[] embedding, String provider) {
        this.embedding = embedding;
        this.provider = provider;
    }

    public double[] getEmbedding() {
        return embedding;
    }

    public String getProvider() {
        return provider;
    }
}

class VectorSearchResult {
    private String filename;
    private String snippet;
    private double score;
    private int chunkId;

    public VectorSearchResult(String filename, String snippet, double score, int chunkId) {
        this.filename = filename;
        this.snippet = snippet;
        this.score = score;
        this.chunkId = chunkId;
    }

    public String getFilename() { return filename; }
    public String getSnippet() { return snippet; }
    public double getScore() { return score; }
    public int getChunkId() { return chunkId; }
}
