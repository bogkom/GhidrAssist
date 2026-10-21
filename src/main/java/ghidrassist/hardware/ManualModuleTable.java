package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Read-only, coordinate-backed candidates for a technical manual's module
 * address table. This deliberately does NOT identify the device, modify CPU
 * profiles, or promise that a PDF table is semantically correct.
 *
 * The first supported table heading is "Table D-1 Module Address Map".
 * Geometry is mandatory: a plain text match cannot create a candidate row.
 */
public final class ManualModuleTable {
    private ManualModuleTable() {}

    private static final Pattern TITLE = Pattern.compile(
        "(?is)\\bTable\\s+D[-–]1\\s+Module\\s+Address\\s+Map\\b");
    private static final Pattern NAME = Pattern.compile(
        "[A-Z][A-Z0-9/]*(?: [A-Z0-9/()]+){0,4}");
    private static final Pattern ADDRESS = Pattern.compile(
        "(?i)(?:\\$Y[0-9A-F]{5}|\\$[0-9A-F]{6}|0X[0-9A-F]{6})");

    /** PDF coordinates use the text direction's page units, not row numbers. */
    public record Word(String value, float left, float right, float baseline) {
        public Word {
            if (value == null || value.isBlank() ||
                    !Float.isFinite(left) || !Float.isFinite(right) ||
                    !Float.isFinite(baseline) || left < 0 || right <= left) {
                throw new IllegalArgumentException("Invalid positioned word");
            }
        }
    }

    public static final class Candidate {
        public final int pdfPage;
        public final String module;
        public final int sizeBytes;
        public final String baseAsPrinted;
        /** The MM=1 interpretation of $Yxxxx, or the literal 24-bit base. */
        public final long candidateBase;
        public final boolean mmDependent;
        /** Model-specific qualifier printed in the table, otherwise unknown. */
        public final String modelConstraint;
        public final String provenance;

        private Candidate(int page, String module, int size, String printed,
                long address, boolean dependent) {
            pdfPage = page;
            this.module = module;
            sizeBytes = size;
            baseAsPrinted = printed;
            candidateBase = address;
            mmDependent = dependent;
            modelConstraint=module.contains("(MC68376 ONLY)") ?
                "MC68376_ONLY" : "UNSPECIFIED_IN_ROW";
            provenance = "PDF_PAGE_COORDINATES; HEADER_MATCH; DEVICE_UNVERIFIED";
        }

        public String evidenceLine() {
            return "pdf_page=" + pdfPage + " module=" + module +
                " size_bytes=" + sizeBytes + " base_as_printed=" + baseAsPrinted +
                " base_if_MM1=0x" + String.format(Locale.ROOT, "%06X", candidateBase) +
                " mapping=" + (mmDependent ? "MM_DEPENDENT_Y" : "LITERAL") +
                " model_constraint=" + modelConstraint +
                " confidence=LAYOUT_ALIGNED_CANDIDATE device=UNVERIFIED";
        }
    }

    /**
     * Accept only rows where name, decimal size, and address are separate,
     * left-to-right spatial columns. Reject duplicate or conflicting rows.
     * Missing/noisy layout is safely reported as zero candidates.
     */
    public static List<Candidate> parsePage(int page, String extractedText,
            List<Word> positionedWords) {
        if (page < 1) throw new IllegalArgumentException("PDF pages are 1-based");
        if (extractedText == null || !TITLE.matcher(extractedText).find() ||
                positionedWords == null || positionedWords.isEmpty()) return List.of();

        Map<Integer, List<Word>> lines = new TreeMap<>();
        for (Word word : positionedWords) {
            if (word == null) continue;
            // Half-point buckets match the PDFBox text positions on a baseline.
            int baseline = Math.round(word.baseline * 2);
            lines.computeIfAbsent(baseline, unused -> new ArrayList<>()).add(word);
        }
        Map<String, Candidate> unique = new LinkedHashMap<>();
        for (List<Word> line : lines.values()) {
            line.sort(Comparator.comparingDouble(Word::left));
            if (line.size() < 3 || line.size() > 8) continue;
            Word address = line.get(line.size()-1);
            Word size = line.get(line.size()-2);
            String rawAddress = address.value.trim().toUpperCase(Locale.ROOT);
            if (!ADDRESS.matcher(rawAddress).matches() ||
                    !size.value.matches("[1-9][0-9]{0,4}")) continue;
            int bytes;
            try { bytes = Integer.parseInt(size.value); }
            catch (NumberFormatException invalid) { continue; }
            // Non-power-of-two module apertures exist (MC68376 TouCAN:
            // 384 bytes); 8-bit-word alignment of registers is separate.
            if (bytes > 4096) continue;

            List<String> segments = new ArrayList<>();
            for (int i = 0; i < line.size()-2; i++)
                segments.add(line.get(i).value.strip().toUpperCase(Locale.ROOT));
            String name = String.join(" ", segments);
            if (!NAME.matcher(name).matches() || name.length() > 28) continue;
            Word lastName = line.get(line.size()-3);
            if (size.left - lastName.right < 8f ||
                    address.left - size.right < 8f) continue;

            boolean dependent = rawAddress.startsWith("$Y");
            String digits = dependent ? "F" + rawAddress.substring(2) :
                rawAddress.startsWith("$") ? rawAddress.substring(1) :
                rawAddress.substring(2);
            long base;
            try { base = Long.parseLong(digits, 16); }
            catch (NumberFormatException invalid) { continue; }
            if (base > 0xffffffL || base + bytes > 0x1000000L) continue;

            Candidate found = new Candidate(page, name, bytes, rawAddress, base, dependent);
            Candidate previous = unique.putIfAbsent(name, found);
            if (previous != null) {
                // A duplicate is not sufficient evidence, even when matching.
                return List.of();
            }
        }
        return List.copyOf(unique.values());
    }

    public static String evidenceTail(int page, String text, List<Word> words, int limit) {
        if (limit < 0) throw new IllegalArgumentException("Negative limit");
        List<Candidate> found = parsePage(page, text, words);
        if (found.isEmpty() || limit == 0) return "";
        StringBuilder out = new StringBuilder(
            "\n\n[GEOMETRY-ALIGNED MODULE ADDRESS TABLE CANDIDATES; " +
            "VERIFY PDF, CPU MODEL AND REGISTER SEMANTICS BEFORE USE]\n");
        for (int i=0; i<Math.min(found.size(), limit); i++)
            out.append(found.get(i).evidenceLine()).append('\n');
        if (found.size() > limit)
            out.append("... further candidate rows omitted.\n");
        return out.toString();
    }
}
