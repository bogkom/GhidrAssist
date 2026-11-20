// Independent Ghidra headless process: verify durable production Apply after reopen.
// This is a disposable CPU32 fixture, not an ECU411 or GUI Undo witness.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.lang.reflect.Method;
import java.util.List;

public class GA08VerifyProductionApplyReopened extends GhidraScript {
    private void require(boolean ok, String message) {
        if (!ok) throw new IllegalStateException("GA08 REOPEN FAIL: " + message);
    }
    @Override public void run() throws Exception {
        require(currentProgram != null && "ga08-synthetic.bin".equals(currentProgram.getName()),
                "refuse non-disposable program");
        String path = System.getProperty("ga08.test.jar");
        require(path != null && new File(path).isFile(), "production JAR missing");
        try (URLClassLoader loader = new URLClassLoader(
                new URL[]{new File(path).toURI().toURL()},
                ghidra.program.model.listing.Program.class.getClassLoader())) {
            Class<?> plan = Class.forName("ghidrassist.hardware.HardwareApplyPlan", true, loader);
            Class<?> itemType = Class.forName("ghidrassist.hardware.HardwareApplyPlan$Item", true, loader);
            Class<?> service = Class.forName("ghidrassist.hardware.HardwareApplyService", true, loader);
            List<?> items = (List<?>) plan.getMethod("mc68332Mm1Candidates", long.class)
                    .invoke(null, 0x1000L);
            List<Object> memory = new java.util.ArrayList<>();
            for (Object item : items) {
                if (itemType.getField("kind").get(item).toString().equals("MEMORY")
                        && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE"))
                    memory.add(item);
            }
            require(memory.size() >= 3, "expected three independent module rows");
            Object first = memory.get(0);
            Object conflict = memory.get(1);
            Object exact = memory.get(2);
            var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
            long firstAddress = itemType.getField("address").getLong(first);
            int firstLength = itemType.getField("length").getInt(first);
            String firstName = (String) itemType.getField("name").get(first);
            MemoryBlock applied = currentProgram.getMemory().getBlock(space.getAddress(firstAddress));
            require(applied != null && firstName.equals(applied.getName())
                    && applied.getSize() == firstLength,
                    "approved module not persisted after closing project");
            for (Object item : List.of(conflict, exact)) {
                long address = itemType.getField("address").getLong(item);
                String expected = item == conflict ? "GA08_USER_CONFLICT" : "GA08_USER_EXACT";
                MemoryBlock user = currentProgram.getMemory().getBlock(space.getAddress(address));
                require(user != null && expected.equals(user.getName()),
                        "independent user block lost across reopen: " + expected);
                if (item == exact) require(user.getSize() == itemType.getField("length").getInt(item),
                        "exact user block size changed across reopen");
            }
            Method apply = service.getMethod("apply",
                    ghidra.program.model.listing.Program.class, List.class);
            Object outcome = apply.invoke(null, currentProgram, List.of(first));
            require(outcome.getClass().getField("changed").getInt(outcome) == 0
                    && outcome.getClass().getField("skipped").getInt(outcome) == 1,
                    "reopened approved module must be idempotent");
            println("GA08 PRODUCTION APPLY REOPEN PASS: module=1 user_blocks=2 idempotent=1");
        }
    }
}
