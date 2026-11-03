// @category GhidrAssist.Tests
// Real Ghidra synthetic CodeUnit/ReferenceManager evidence; no project edits.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import com.google.gson.JsonObject;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.lang.reflect.Method;

public class GA18VerifyListingSnapshot extends GhidraScript {
    private int assertions;
    private void check(boolean pass, String message) {
        assertions++;
        if (!pass) throw new IllegalStateException("GA18 LISTING FAIL: " + message);
    }
    @Override protected void run() throws Exception {
        if(currentProgram == null || !"synthetic-callgraph.bin".equals(currentProgram.getName()))
            throw new IllegalStateException("Synthetic callgraph fixture only");
        String jar = System.getProperty("ga18.test.jar", "");
        if(jar.isBlank()) throw new IllegalStateException("Missing ga18.test.jar");
        try(URLClassLoader loader = new URLClassLoader(
                new URL[]{Path.of(jar).toUri().toURL()}, getClass().getClassLoader())) {
            Class<?> clazz = Class.forName("ghidrassist.automation.AutomationListing", true, loader);
            Method query = clazz.getMethod("snapshot", Program.class, ProgramLocation.class);
            var target = currentProgram.getAddressFactory().getAddress("00000100");
            JsonObject snapshot = (JsonObject)query.invoke(null, currentProgram,
                new ProgramLocation(currentProgram, target));
            check("00000100".equalsIgnoreCase(snapshot.get("address").getAsString()),
                  "Listing location retained");
            check(snapshot.get("decoded").getAsBoolean(), "decoded JSR");
            check("JSR".equalsIgnoreCase(snapshot.get("mnemonic").getAsString()), "JSR mnemonic");
            check(snapshot.get("text").getAsString().toLowerCase().contains("jsr"), "Listing text");
            check(!snapshot.get("bytes_hex").getAsString().isEmpty(), "instruction bytes");
            check("00000100".equalsIgnoreCase(snapshot.get("function_entry").getAsString()),
                  "function containing instruction");
            check(snapshot.get("reference_total").getAsInt() >= 1, "outgoing static CALL reference");
            check(snapshot.getAsJsonArray("references").size() <= 16, "bounded references");
            var undecoded = currentProgram.getAddressFactory().getAddress("00000040");
            JsonObject empty = (JsonObject)query.invoke(null, currentProgram,
                new ProgramLocation(currentProgram, undecoded));
            check(!empty.get("decoded").getAsBoolean(), "no invented instruction at undecoded vector");
        }
        println("GA18 LISTING SNAPSHOT PASS: assertions=" + assertions
            + " (real Ghidra synthetic CPU32, read-only)");
    }
}
