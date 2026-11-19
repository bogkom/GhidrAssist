// Genuine disposable Ghidra 12.1.4 headless witness for the production Apply service.
// Requires -Dga08.test.jar=<built extension jar> and a synthetic CPU32 program.
// This script is not a replacement for UI Review authorization or formal GA-08.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.lang.reflect.Method;
import java.util.List;

public class GA08VerifyProductionApply extends GhidraScript {
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException("GA08 FAIL: " + message);
    }

    @Override
    public void run() throws Exception {
        String path = System.getProperty("ga08.test.jar");
        require(path != null && new File(path).isFile(), "built production extension JAR missing");
        require(currentProgram != null, "synthetic program missing");
        URL jar = new File(path).toURI().toURL();
        // Anchor delegation to Ghidra's API loader, not the script compilation loader.
        // The latter may not resolve transitive classes used by the production JAR.
        try (URLClassLoader loader = new URLClassLoader(new URL[] {jar},
                ghidra.program.model.listing.Program.class.getClassLoader())) {
            Class<?> plan = Class.forName("ghidrassist.hardware.HardwareApplyPlan", true, loader);
            Class<?> itemType = Class.forName("ghidrassist.hardware.HardwareApplyPlan$Item", true, loader);
            Class<?> service = Class.forName("ghidrassist.hardware.HardwareApplyService", true, loader);
            Method candidates = plan.getMethod("mc68332Mm1Candidates", long.class);
            Method apply = service.getMethod("apply",
                    ghidra.program.model.listing.Program.class, List.class);
            List<?> items = (List<?>) candidates.invoke(null, 0x1000L);
            Object first = items.stream().filter(item -> {
                try {
                    Object kind = itemType.getField("kind").get(item);
                    return kind.toString().equals("MEMORY")
                        && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE");
                } catch (Exception ex) { throw new IllegalStateException(ex); }
            }).findFirst().orElseThrow();
            long address = itemType.getField("address").getLong(first);
            int length = itemType.getField("length").getInt(first);
            String name = (String) itemType.getField("name").get(first);
            var at = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(address);
            require(currentProgram.getMemory().getBlock(at) == null,
                    "fixture must not pre-map the module");
            Object second = items.stream().filter(item -> {
                try {
                    return itemType.getField("kind").get(item).toString().equals("MEMORY")
                        && itemType.getField("address").getLong(item) != address
                        && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE");
                } catch (Exception ex) { throw new IllegalStateException(ex); }
            }).findFirst().orElseThrow();
            long other = itemType.getField("address").getLong(second);
            var otherAt = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(other);
            int fixtureTx = currentProgram.startTransaction("GA08 disposable conflicting user block");
            try {
                currentProgram.getMemory().createUninitializedBlock(
                    "GA08_USER_CONFLICT", otherAt, 1, false);
            } finally {
                currentProgram.endTransaction(fixtureTx, true);
            }
            boolean rejected = false;
            try {
                apply.invoke(null, currentProgram, List.of(first, second));
            } catch (java.lang.reflect.InvocationTargetException expected) {
                rejected = expected.getCause() instanceof IllegalStateException
                    && expected.getCause().getMessage().contains("blocked");
            }
            require(rejected, "conflicting approved row must reject the whole batch");
            require(currentProgram.getMemory().getBlock(at) == null,
                    "earlier approved region survived a failed transaction");
            require(currentProgram.getMemory().getBlock(otherAt).getName()
                    .equals("GA08_USER_CONFLICT"), "user block changed on rollback");
            println("GA08 PRODUCTION APPLY ROLLBACK PASS: stale_conflict=1 prior_mutations=0");
            Object outcome = apply.invoke(null, currentProgram, List.of(first));
            require(outcome.getClass().getField("changed").getInt(outcome) == 1,
                    "production Apply must report one changed row");
            MemoryBlock block = currentProgram.getMemory().getBlock(at);
            require(block != null && block.getSize() == length && block.getName().equals(name),
                    "production Apply did not create the expected module");
            // Idempotent re-Apply must not create duplicate regions.
            Object again = apply.invoke(null, currentProgram, List.of(first));
            require(again.getClass().getField("changed").getInt(again) == 0,
                    "idempotent production Apply unexpectedly changed program");
            require(again.getClass().getField("skipped").getInt(again) == 1,
                    "idempotent production Apply must skip one row");
            println("GA08 PRODUCTION APPLY POSITIVE PASS: changed=1 idempotent_skip=1");
        }
    }
}
