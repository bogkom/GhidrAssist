package ghidrassist.core;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import ghidrassist.hardware.ManualRegisterHints;
import ghidrassist.hardware.ManualModuleTable;
import ghidrassist.hardware.ManualDocumentScope;
import ghidrassist.hardware.ManualPrintedPage;
import ghidrassist.hardware.ManualPaginationAudit;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.TextPosition;

/**
 * Text-layer PDF extraction. Processes one page at a time; never claims to
 * reconstruct exact table semantics or images/diagrams. OCR is deliberately absent.
 */
public final class RAGPdfExtractor {
    private RAGPdfExtractor() {}

    public interface PageConsumer {
        void accept(int pageNumber, String content, boolean uncertainTable) throws IOException;
    }

    public static final class Report {
        public final int pages;
        public final int indexedPages;
        public final int pagesWithoutText;
        public final int uncertainTablePages;
        Report(int pages, int indexedPages, int pagesWithoutText, int uncertainTablePages) {
            this.pages = pages;
            this.indexedPages = indexedPages;
            this.pagesWithoutText = pagesWithoutText;
            this.uncertainTablePages = uncertainTablePages;
        }
    }

    public static Report extract(File source, PageConsumer sink) throws IOException {
        try (PDDocument pdf = Loader.loadPDF(source)) {
            if (pdf.isEncrypted() && !pdf.getCurrentAccessPermission().canExtractContent()) {
                throw new IOException("PDF does not permit text extraction: " + source.getName());
            }
            final int count = pdf.getNumberOfPages();
            if (count == 0) throw new IOException("PDF has no pages: " + source.getName());
            // One document identity for ALL page chunks. Bare archive names
            // such as c5sim.pdf occur in multiple Motorola MCU collections:
            // sample the first three actual PDF text pages for a matching
            // "MC683xx USER'S MANUAL" header before assigning a model.
            StringBuilder headerSample = new StringBuilder();
            for (int previewPage=1; previewPage<=Math.min(3,count); previewPage++) {
                LayoutAwareStripper preview = new LayoutAwareStripper();
                preview.setStartPage(previewPage);
                preview.setEndPage(previewPage);
                headerSample.append(preview.getText(pdf)).append('\n');
            }
            ManualDocumentScope.Identity identity =
                ManualDocumentScope.fromDocumentEvidence(source.getName(),
                    headerSample.toString());
            int indexed = 0;
            int blank = 0;
            int suspicious = 0;
            int lastFolioPhysical = 0;
            String lastFolio = null;
            for (int page = 1; page <= count; page++) {
                LayoutAwareStripper stripper = new LayoutAwareStripper();
                stripper.beginPage();
                stripper.setStartPage(page);
                stripper.setEndPage(page);
                String raw = stripper.getText(pdf);
                String text = raw == null ? "" : raw.strip();
                if (text.replaceAll("\\s", "").length() < 10) {
                    blank++;
                    continue;
                }
                String moduleRows = ManualModuleTable.evidenceTail(page, raw,
                    stripper.positionedWords(), 64);
                boolean table = stripper.hasPossibleTable() || !moduleRows.isEmpty();
                if (table) {
                    suspicious++;
                    text = "[POSSIBLE TABLE / COLUMNS: LAYOUT NOT VERIFIED; CHECK ORIGINAL PDF PAGE]"
                        + System.lineSeparator() + text;
                }
                // Add at most 12 *explicitly unverified* candidate row hints.
                // Never transform layout guesses into verified register definitions.
                if (table) {
                    text += ManualRegisterHints.evidenceTail(page, text, 12);
                }
                // Spatially aligned rows are still unverified device candidates;
                // never mutate a CPU profile or memory map during ingestion.
                text += moduleRows;
                // Metadata comes from the original filename, not inferred MCU
                // identity; per-page text always retains this distinction.
                // "Printed D-1" can mean PDF page 215 or page 1 depending
                // on the physical document edition and split chapter.
                // Record only header-supported labels, never body table IDs.
                ManualPrintedPage.Hint folio=ManualPrintedPage.fromText(raw);
                var sequence=ManualPaginationAudit.compare(
                    lastFolioPhysical,lastFolio,page,folio.label());
                // Only actual header candidates become comparison anchors.
                // Never infer labels for blank or unreadable pages.
                if(!"UNKNOWN".equals(folio.label())) {
                    lastFolio=folio.label();
                    lastFolioPhysical=page;
                }
                String printed=folio.evidence()+" "+sequence.evidence();
                text = identity.evidence(page) + " " + printed +
                    System.lineSeparator() + text;
                sink.accept(page, text, table);
                indexed++;
            }
            if (indexed == 0) {
                throw new IOException("PDF has no usable text layer (probably scanned). "
                    + "OCR is not available: " + source.getName());
            }
            return new Report(count, indexed, blank, suspicious);
        } catch (org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException e) {
            throw new IOException("PDF is password-protected: " + source.getName(), e);
        }
    }

    /**
     * Conservative coordinate-based spacing. A separator suggests visual columns,
     * NOT verified register/bit/value correspondence. The user can open source page.
     */
    private static final class LayoutAwareStripper extends PDFTextStripper {
        private int linesWithWideGaps;
        private int linesWithMultipleWideGaps;
        private final Map<Integer, List<TextPosition>> visualRows = new HashMap<>();

        LayoutAwareStripper() throws IOException {
            setSortByPosition(true);
            setShouldSeparateByBeads(false);
            setLineSeparator("\n");
            setWordSeparator(" ");
        }

        void beginPage() {
            linesWithWideGaps = 0;
            linesWithMultipleWideGaps = 0;
            visualRows.clear();
        }

        @Override
        protected void processTextPosition(TextPosition pos) {
            super.processTextPosition(pos);
            // Collect an additional, page-local view of glyph coordinates. Some
            // PDFs yield each word as a separate writeString() callback.
            if (pos != null) {
                int y = Math.round(pos.getYDirAdj() * 2f);
                visualRows.computeIfAbsent(y, unused -> new ArrayList<>()).add(pos);
            }
        }

        /**
         * Convert PDFBox glyph positions into page-local words without
         * discarding coordinates. Only the independent module-table parser
         * may decide whether three cells form an aligned row.
         */
        List<ManualModuleTable.Word> positionedWords() {
            List<ManualModuleTable.Word> words = new ArrayList<>();
            for (List<TextPosition> row : visualRows.values()) {
                row.sort(Comparator.comparingDouble(TextPosition::getXDirAdj));
                StringBuilder token = new StringBuilder();
                float start = 0f, right = 0f, y = 0f;
                for (TextPosition pos : row) {
                    String part = pos.getUnicode();
                    if (part == null || part.isEmpty()) continue;
                    float x = pos.getXDirAdj();
                    float end = x + pos.getWidthDirAdj();
                    float widthOfSpace = pos.getWidthOfSpace();
                    if (!Float.isFinite(widthOfSpace) || widthOfSpace <= 0)
                        widthOfSpace = 3f;
                    if (token.length() > 0 && x - right > Math.max(1.8f, widthOfSpace * 0.75f)) {
                        words.add(new ManualModuleTable.Word(token.toString(), start, right, y));
                        token.setLength(0);
                    }
                    for (int i=0; i<part.length(); i++) {
                        char ch=part.charAt(i);
                        if (Character.isWhitespace(ch)) {
                            if (token.length() > 0) {
                                words.add(new ManualModuleTable.Word(
                                    token.toString(), start, Math.max(right, x), y));
                                token.setLength(0);
                            }
                        } else {
                            if (token.length() == 0) { start=x; y=pos.getYDirAdj(); }
                            token.append(ch);
                        }
                    }
                    right = end;
                }
                if (token.length() > 0)
                    words.add(new ManualModuleTable.Word(token.toString(), start, right, y));
            }
            return words;
        }

        boolean hasPossibleTable() {
            int multiColumnRows = 0;
            for (List<TextPosition> row : visualRows.values()) {
                if (row.size() < 3) continue;
                row.sort(Comparator.comparingDouble(TextPosition::getXDirAdj));
                int gaps = 0;
                TextPosition previous = null;
                for (TextPosition item : row) {
                    if (previous != null) {
                        float space = Math.max(3f, previous.getWidthOfSpace());
                        float gap = item.getXDirAdj()
                            - (previous.getXDirAdj() + previous.getWidthDirAdj());
                        if (gap > space * 3.5f) gaps++;
                    }
                    previous = item;
                }
                if (gaps > 0) multiColumnRows++;
            }
            return linesWithMultipleWideGaps >= 2 || linesWithWideGaps >= 3
                || multiColumnRows >= 3;
        }

        @Override
        protected void writeString(String text, List<TextPosition> positions) throws IOException {
            if (positions == null || positions.size() < 2) {
                super.writeString(text);
                return;
            }
            StringBuilder result = new StringBuilder(text.length() + 24);
            float lastRight = Float.NaN;
            int wideGaps = 0;
            for (TextPosition pos : positions) {
                if (pos == null || pos.getUnicode() == null) continue;
                float x = pos.getXDirAdj();
                float space = pos.getWidthOfSpace();
                if (!Float.isFinite(space) || space <= 0) space = Math.max(3f, pos.getFontSizeInPt() / 3f);
                if (Float.isFinite(lastRight)) {
                    float gap = x - lastRight;
                    if (gap > space * 2.5f) {
                        // PDF coordinates indicate a wide visual separation.
                        result.append("    |    ");
                        wideGaps++;
                    } else if (gap > space * 0.8f && result.length() > 0 &&
                        !Character.isWhitespace(result.charAt(result.length()-1))) {
                        result.append(' ');
                    }
                }
                result.append(pos.getUnicode());
                lastRight = x + pos.getWidthDirAdj();
            }
            if (wideGaps > 0) linesWithWideGaps++;
            if (wideGaps >= 2) linesWithMultipleWideGaps++;
            super.writeString(result.toString());
        }
    }
}
