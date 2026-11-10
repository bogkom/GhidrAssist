// @category GhidrAssist.Tests
// Native Ghidra 12.1.4 regression: a decompiler task must not cross Program identities.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import com.google.gson.JsonObject;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class GA18VerifyDecompilerTaskBinding extends GhidraScript {
    private int assertions;
    private void check(boolean ok, String description) {
        assertions++;
        if (!ok) throw new IllegalStateException("GA18 DECOMPILER BINDING FAIL: " + description);
    }

    @Override protected void run() throws Exception {
        if (currentProgram == null || !"synthetic-callgraph.bin".equals(currentProgram.getName()))
            throw new IllegalStateException("Synthetic callgraph fixture only");
        check("68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString()),
              "CPU32 program identity");
        Function function = currentProgram.getFunctionManager().getFunctionAt(
            currentProgram.getAddressFactory().getAddress("00000100"));
        check(function != null, "bootstrapped synthetic function at 0x100");
        String jar = System.getProperty("ga18.test.jar", "");
        if (jar.isBlank()) throw new IllegalStateException("Missing ga18.test.jar");
        try (URLClassLoader loader = new URLClassLoader(
                new URL[]{Path.of(jar).toUri().toURL()}, getClass().getClassLoader())) {
            Class<?> type = Class.forName("ghidrassist.automation.AutomationDecompiler", true, loader);
            Object instance = type.getConstructor().newInstance();
            Method start = type.getMethod("start", Program.class, Function.class);
            Method status = type.getMethod("status", Program.class, String.class, int.class, int.class);
            try {
                JsonObject receipt = (JsonObject)start.invoke(instance, currentProgram, function);
                String id = receipt.get("task_id").getAsString();
                check(!id.isBlank(), "new task ID returned");
                JsonObject live = (JsonObject)status.invoke(instance, currentProgram, id, 0, 0);
                check(id.equals(live.get("task_id").getAsString()), "current task recognized");
                // Null simulates a changed/no active Program. No second window opens.
                JsonObject switched = (JsonObject)status.invoke(instance, (Program)null, id, 0, 8192);
                check("STALE".equals(switched.get("state").getAsString()),
                      "program switch invalidates task result");
                check(!switched.has("text"), "no old pseudocode transferred");
                boolean rejected = false;
                try {
                    status.invoke(instance, currentProgram, "old-task-id", 0, 8192);
                } catch (InvocationTargetException error) {
                    rejected = error.getCause() instanceof IllegalArgumentException
                        && error.getCause().getMessage().contains("task_id mismatch");
                }
                check(rejected, "wrong task ID rejected");
                // An API task can outlive its read-only status check. The
                // headless analyzer closes currentProgram when post-scripts
                // exit; do not let the test's async decompiler retain it.
                // This is a bounded fixture lifecycle gate, not real ISR.
                long deadline=System.nanoTime()+
                    java.util.concurrent.TimeUnit.SECONDS.toNanos(36);
                JsonObject settled;
                do {
                    settled=(JsonObject)status.invoke(instance,
                        currentProgram,id,0,0);
                    if(!"RUNNING".equals(
                            settled.get("state").getAsString()))break;
                    if(System.nanoTime()>=deadline)
                        throw new IllegalStateException(
                            "Synthetic Decompiler task did not settle before Program close");
                    Thread.sleep(50);
                }while(true);
                check("COMPLETED".equals(settled.get("state").getAsString()) ||
                        "FAILED".equals(settled.get("state").getAsString()),
                    "synthetic Decompiler task finished before Program close");
            } finally {
                type.getMethod("close").invoke(instance);
            }
        }
        println("GA18 DECOMPILER TASK BINDING PASS: assertions=" + assertions
            + " (real Ghidra synthetic CPU32; no firmware or project writes)");
    }
}
