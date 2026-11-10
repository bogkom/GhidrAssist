package ghidrassist.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * GA-06/10/16: one indexed PDF folio and its ORIGINAL INDEX-TIME source
 * metadata. Multiple Lucene chunks must agree on provenance; choosing one
 * conflicting digest or silently overwriting a duplicate would manufacture
 * apparent source certainty. Neither index text nor digest authenticates
 * the currently present file or the actual MCU.
 */
public final class RAGIndexedPdfPageEvidence {
    private RAGIndexedPdfPageEvidence() {}
    public static final int MAX_CHUNKS=256;
    public static final int MAX_PAGE_CHARACTERS=2_000_000;

    public record Chunk(int physicalPage,int chunkId,String text,
            String indexedSha256,String sourcePath,String sourceType,
            String libraryId) {
        public Chunk {
            if(physicalPage<1 || physicalPage>100000 ||
                    chunkId<0 || chunkId>1_000_000 ||
                    text==null || text.length()>MAX_PAGE_CHARACTERS)
                throw new IllegalArgumentException("Invalid indexed PDF chunk");
        }
    }
    public record Page(int physicalPage,String text,String indexedSha256,
            String sourcePath,String libraryId,int chunks) {
        public Page {
            if(physicalPage<1 || physicalPage>100000 ||
                    text==null || text.length()>MAX_PAGE_CHARACTERS ||
                    chunks<1 || chunks>MAX_CHUNKS)
                throw new IllegalArgumentException("Invalid indexed PDF page");
        }
    }

    /**
     * A GUI result may be stale after reindexing or moving a PDF between
     * libraries. Never display the new document's text as if it were the
     * previously selected search hit, even when filename and chunk match.
     */
    public static void requireSameSource(Page current,SearchResult selected) {
        if(current==null || selected==null ||
                !"pdf".equalsIgnoreCase(selected.getSourceType()) ||
                current.physicalPage()!=selected.getPageNumber() ||
                !Objects.equals(current.indexedSha256(),selected.getIndexedSha256()) ||
                !Objects.equals(current.sourcePath(),selected.getSourcePath()) ||
                !Objects.equals(current.libraryId(),selected.getIndexedLibraryId()))
            throw new IllegalArgumentException(
                "STALE_INDEXED_PDF_SOURCE: rerun document search");
    }

    /** Fail closed on any inconsistent document/page identity. */
    public static Page join(int requestedPage,List<Chunk> chunks) {
        if(requestedPage<1 || requestedPage>100000 || chunks==null ||
                chunks.isEmpty() || chunks.size()>MAX_CHUNKS)
            throw new IllegalArgumentException("Invalid indexed PDF page selection");
        List<Chunk> ordered=new ArrayList<>(chunks);
        if(ordered.contains(null))
            throw new IllegalArgumentException("Missing PDF source chunk");
        ordered.sort(Comparator.comparingInt(Chunk::chunkId));
        Chunk reference=ordered.get(0);
        Set<Integer> unique=new HashSet<>();
        StringBuilder body=new StringBuilder();
        for(Chunk c:ordered) {
            if(c==null || c.physicalPage()!=requestedPage ||
                    !"pdf".equalsIgnoreCase(c.sourceType()) ||
                    !Objects.equals(c.indexedSha256(),reference.indexedSha256()) ||
                    !Objects.equals(c.sourcePath(),reference.sourcePath()) ||
                    !Objects.equals(c.libraryId(),reference.libraryId()) ||
                    !unique.add(c.chunkId()))
                throw new IllegalArgumentException(
                    "Conflicting indexed PDF page provenance");
            if(body.length()>0)body.append("\n\n");
            if(body.length()+c.text().length()>MAX_PAGE_CHARACTERS)
                throw new IllegalArgumentException("Indexed PDF page exceeds display bound");
            body.append(c.text());
        }
        return new Page(requestedPage,body.toString(),
            reference.indexedSha256(),reference.sourcePath(),
            reference.libraryId(),ordered.size());
    }
}
