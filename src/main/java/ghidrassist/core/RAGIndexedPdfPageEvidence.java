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

    /** Legacy indexed rows may remain viewable as UNKNOWN but cannot
     * authenticate a current search hit or a cross-folio source group. */
    private static boolean claimedIdentity(String digest,String path,String library) {
        if(digest==null || !digest.matches("[0-9a-f]{64}") ||
                path==null || path.isBlank() || path.length()>4096 ||
                library==null || library.isBlank() || library.length()>256)
            return false;
        for(String value:new String[]{path,library})
            for(int i=0;i<value.length();) {
                int code=value.codePointAt(i);
                if(Character.isISOControl(code) ||
                        Character.getType(code)==Character.FORMAT ||
                        Character.getType(code)==Character.LINE_SEPARATOR ||
                        Character.getType(code)==Character.PARAGRAPH_SEPARATOR)
                    return false;
                i+=Character.charCount(code);
            }
        return true;
    }

    /**
     * A GUI result may be stale after reindexing or moving a PDF between
     * libraries. Never display the new document's text as if it were the
     * previously selected search hit, even when filename and chunk match.
     */
    public static void requireSameSource(Page current,SearchResult selected) {
        if(current==null || selected==null ||
                !claimedIdentity(current.indexedSha256(),
                    current.sourcePath(),current.libraryId()) ||
                !claimedIdentity(selected.getIndexedSha256(),
                    selected.getSourcePath(),selected.getIndexedLibraryId()) ||
                !"pdf".equalsIgnoreCase(selected.getSourceType()) ||
                current.physicalPage()!=selected.getPageNumber() ||
                !Objects.equals(current.indexedSha256(),selected.getIndexedSha256()) ||
                !Objects.equals(current.sourcePath(),selected.getSourcePath()) ||
                !Objects.equals(current.libraryId(),selected.getIndexedLibraryId()))
            throw new IllegalArgumentException(
                "STALE_INDEXED_PDF_SOURCE: rerun document search");
    }

    /**
     * The reviewed source spans physical PDF pages 219/220/221. Binding
     * each folio to one same indexed digest, path and library prevents a
     * cross-folio mix after concurrent index replacement. This is still
     * index-time metadata, NOT authentication of arbitrary page text.
     */
    public static void requireOneIndexedDocument(
            java.util.Map<Integer,Page> pages) {
        if(pages==null || pages.isEmpty() || pages.size()>16)
            throw new IllegalArgumentException("Unbounded indexed PDF source group");
        Page previous=null;
        for(var item:pages.entrySet()) {
            Page current=item.getValue();
            if(item.getKey()==null || current==null ||
                    item.getKey()!=current.physicalPage() ||
                    !claimedIdentity(current.indexedSha256(),
                        current.sourcePath(),current.libraryId()))
                throw new IllegalArgumentException("Missing indexed source identity");
            if(previous!=null && (
                    !Objects.equals(previous.indexedSha256(),current.indexedSha256()) ||
                    !Objects.equals(previous.sourcePath(),current.sourcePath()) ||
                    !Objects.equals(previous.libraryId(),current.libraryId())))
                throw new IllegalArgumentException(
                    "Cross-folio PDF index digest/path/library conflict");
            previous=current;
        }
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
