package ghidrassist.core;

import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.net.URI;

/** Open original documentation, preferably at the indexed PDF page. */
public final class RAGSourceOpener {
    private RAGSourceOpener() {}

    public static void open(SearchResult result) throws IOException {
        if (result == null || result.getSourcePath() == null || result.getSourcePath().isBlank()) {
            throw new IOException("Source file path is missing (old index entry).");
        }
        File source = new File(result.getSourcePath());
        if (!source.isFile()) throw new IOException("Original document not found: " + source);
        if (!Desktop.isDesktopSupported()) throw new IOException("Desktop document opening is unsupported.");
        Desktop desktop = Desktop.getDesktop();
        if ("pdf".equalsIgnoreCase(result.getSourceType()) && result.getPageNumber() > 0 &&
            desktop.isSupported(Desktop.Action.BROWSE)) {
            URI fileUri = source.toURI();
            // Widely supported by Firefox and Chromium PDF viewers; some viewers ignore #page.
            String target = fileUri.toASCIIString() + "#page=" + result.getPageNumber();
            desktop.browse(URI.create(target));
            return;
        }
        if (!desktop.isSupported(Desktop.Action.OPEN)) {
            throw new IOException("Desktop opening is unsupported.");
        }
        desktop.open(source);
    }
}
