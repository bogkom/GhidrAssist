package ghidrassist.core;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.HashMap;
import java.util.Map;

/**
 * User-triggered external downloader only: no automatic RAG indexing.
 * The trusted Python script is packaged in the extension classpath.
 */
public final class Cpu32ManualDownloadRunner {
    private Cpu32ManualDownloadRunner() {}

    public record Outcome(int exitCode, Path log, Path report, String summary) {}

    /** Read actual statuses; never confuse process exit codes 0/1/2
     * with the number of PDFs downloaded or missing.
     */
    public static String summarizeReport(Path json) {
        try {
            if (!Files.isRegularFile(json) || Files.size(json) > 8_000_000)
                return "No readable document report.";
            JsonObject root = JsonParser.parseString(Files.readString(json)).getAsJsonObject();
            Map<String,Integer> counts = new HashMap<>();
            int review = 0;
            for (JsonElement elem : root.getAsJsonArray("documents")) {
                if (!elem.isJsonObject())continue;
                JsonObject row = elem.getAsJsonObject();
                if (!row.has("status"))continue;
                String status = row.get("status").getAsString();
                counts.merge(status,1,Integer::sum);
                if (row.has("library") &&
                        "TO_REVIEW".equals(row.get("library").getAsString()))
                    review++;
            }
            int saved = counts.getOrDefault("SAVED",0);
            int already = counts.getOrDefault("ALREADY_PRESENT",0) +
                counts.getOrDefault("EXISTS_NOT_REDOWLOADED",0);
            int conflicts = counts.getOrDefault("COLLISION_PRESERVED_FOR_REVIEW",0) +
                counts.getOrDefault("CONFLICT_NOT_OVERWRITTEN",0);
            int invalid = counts.getOrDefault("INVALID_PDF",0);
            int skipped = counts.getOrDefault("SKIPPED_OUT_OF_SCOPE",0);
            int other = counts.getOrDefault("FAILED",0) +
                counts.getOrDefault("ZIP_FAILED",0) +
                counts.getOrDefault("LOCAL_FOLDER_FAILED",0);
            return "New PDFs: "+saved+" | already present: "+already +
                " | stored in TO_REVIEW: "+review +
                "\nCollisions requiring review: "+conflicts+
                " | invalid PDF: "+invalid+
                " | unrelated skipped: "+skipped+
                " | other errors: "+other;
        } catch (Exception ex) {
            return "Document report could not be summarized; inspect the JSON file.";
        }
    }

    public static Outcome run(Path destination, Path archive)
            throws IOException, InterruptedException {
        return run(destination, archive, null, true);
    }

    public static Outcome run(Path destination, Path archive,
            Path localPdfDirectory, boolean attemptOnline)
            throws IOException, InterruptedException {
        if (destination == null) throw new IllegalArgumentException("Missing output folder");
        Files.createDirectories(destination);
        Path script = Files.createTempFile("ghidrassist-rag-cpu32-", ".py");
        try {
            try (InputStream resource = Cpu32ManualDownloadRunner.class
                    .getResourceAsStream("/rag_cpu32_downloader.py")) {
                if (resource == null)
                    throw new IOException("The packaged CPU32 downloader resource is missing");
                Files.copy(resource, script, StandardCopyOption.REPLACE_EXISTING);
            }
            List<String> command = new ArrayList<>();
            command.add("python3");
            command.add(script.toAbsolutePath().toString());
            command.add("--output");
            command.add(destination.toAbsolutePath().toString());
            if (archive != null) {
                if (!Files.isRegularFile(archive))
                    throw new IOException("NXP ZIP archive not found: " + archive);
                command.add("--zip");
                command.add(archive.toAbsolutePath().toString());
            }
            if (localPdfDirectory != null) {
                if (!Files.isDirectory(localPdfDirectory))
                    throw new IOException("Local manual directory not found: " +
                        localPdfDirectory);
                command.add("--pdf-dir");
                command.add(localPdfDirectory.toAbsolutePath().toString());
            }
            if (!attemptOnline)
                command.add("--offline");
            Path log = destination.resolve("download_process.log");
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            builder.redirectOutput(log.toFile());
            Process process = builder.start();
            boolean completed;
            try {
                completed = process.waitFor(15, TimeUnit.MINUTES);
            } catch (InterruptedException interrupted) {
                process.destroyForcibly();
                throw interrupted;
            }
            if (!completed) {
                process.destroyForcibly();
                throw new IOException("CPU32 manual download exceeded 15-minute limit; see " + log);
            }
            Path report = destination.resolve("download_report.json");
            return new Outcome(process.exitValue(), log, report,
                summarizeReport(report));
        } finally {
            Files.deleteIfExists(script);
        }
    }
}
