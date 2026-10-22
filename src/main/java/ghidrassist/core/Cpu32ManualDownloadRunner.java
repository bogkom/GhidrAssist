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

/**
 * User-triggered external downloader only: no automatic RAG indexing.
 * The trusted Python script is packaged in the extension classpath.
 */
public final class Cpu32ManualDownloadRunner {
    private Cpu32ManualDownloadRunner() {}

    public record Outcome(int exitCode, Path log, Path report) {}

    public static Outcome run(Path destination, Path archive)
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
            return new Outcome(process.exitValue(), log,
                destination.resolve("download_report.json"));
        } finally {
            Files.deleteIfExists(script);
        }
    }
}
