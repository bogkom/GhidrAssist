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
        require("ga08-synthetic.bin".equals(currentProgram.getName()),
                "refuse to run production Apply witness outside disposable fixture");
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
            // User-owned controls were committed by the preceding setup script.
            require(currentProgram.getMemory().getBlock(otherAt)!=null &&
                    "GA08_USER_CONFLICT".equals(currentProgram.getMemory().getBlock(otherAt).getName()),
                    "independent conflict fixture missing");
            Object exact = items.stream().filter(item -> {
                try {
                    return itemType.getField("kind").get(item).toString().equals("MEMORY")
                        && itemType.getField("address").getLong(item) != address
                        && itemType.getField("address").getLong(item) != other
                        && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE");
                } catch(Exception ex){throw new IllegalStateException(ex);}
            }).findFirst().orElseThrow();
            long exactOffset=itemType.getField("address").getLong(exact);
            var exactAt=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(exactOffset);
            require(currentProgram.getMemory().getBlock(exactAt)!=null &&
                    "GA08_USER_EXACT".equals(currentProgram.getMemory().getBlock(exactAt).getName()),
                    "independent exact fixture missing");
            boolean exactRejected = false;
            try {
                apply.invoke(null, currentProgram, List.of(exact));
            } catch (java.lang.reflect.InvocationTargetException expected) {
                exactRejected = expected.getCause() instanceof IllegalStateException
                        && expected.getCause().getMessage().contains("blocked");
            }
            require(exactRejected, "exact user-owned module must be BLOCKED");
            require(currentProgram.getMemory().getBlock(exactAt).getName()
                    .equals("GA08_USER_EXACT"), "exact user block changed");
            println("GA08 EXACT USER BLOCK REFUSAL PASS: preserved=1");
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
            // Genuine transaction rollback: MEMORY is created first, then the
            // deliberately unmapped VBR row is rejected in the later kind pass.
            // Unlike the preflight conflict above, this must undo a real write.
            Object vbr = items.stream().filter(item -> {
                try {
                    return itemType.getField("kind").get(item).toString().equals("VBR_STRUCTURE");
                } catch (Exception ex) { throw new IllegalStateException(ex); }
            }).findFirst().orElseThrow();
            long vbrAddress = itemType.getField("address").getLong(vbr);
            var vbrAt = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(vbrAddress);
            require(currentProgram.getMemory().getBlock(vbrAt) == null,
                    "VBR negative control must be unmapped");
            boolean lateRejected = false;
            try {
                apply.invoke(null, currentProgram, List.of(first, vbr));
            } catch (java.lang.reflect.InvocationTargetException expected) {
                lateRejected = expected.getCause() instanceof IllegalStateException
                    && expected.getCause().getMessage().contains("blocked");
            }
            require(lateRejected, "late VBR conflict must reject a partially written batch");
            // GhidraScript owns an outer transaction. Nested service rollback is
            // not observable until this script returns and its outer transaction ends.
            // A separate postScript verifies the persisted state, then applies
            // the positive case. Never print a rollback PASS here.
            println("GA08 LATE ROLLBACK REQUESTED: verify in next script");
        }
    }
}
