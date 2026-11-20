// Third independent process: refused Apply must not persist changes to user memory.
// Disposable synthetic CPU32 fixture only; not a GUI Undo or physical MCU witness.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.List;

public class GA08VerifyProductionApplyAfterRefusals extends GhidraScript {
    private void require(boolean ok, String reason) {
        if (!ok) throw new IllegalStateException("GA08 POST-REFUSAL FAIL: " + reason);
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
            List<?> candidates = (List<?>) plan.getMethod("mc68332Mm1Candidates", long.class)
                    .invoke(null, 0x1000L);
            List<Object> memory = new java.util.ArrayList<>();
            for (Object item : candidates) {
                if (itemType.getField("kind").get(item).toString().equals("MEMORY")
                        && !itemType.getField("name").get(item).equals("TPURAM_2K_CANDIDATE"))
                    memory.add(item);
            }
            require(memory.size() >= 3, "expected three module rows");
            var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
            String[] names = {
                (String) itemType.getField("name").get(memory.get(0)),
                "GA08_USER_CONFLICT", "GA08_USER_EXACT"
            };
            for (int i = 0; i < 3; i++) {
                Object item = memory.get(i);
                long address = itemType.getField("address").getLong(item);
                MemoryBlock block = currentProgram.getMemory().getBlock(space.getAddress(address));
                require(block != null && names[i].equals(block.getName()),
                        "persisted block changed after refused Apply: " + names[i]);
                require(block.getSize() == (i == 1 ? 1 : itemType.getField("length").getInt(item)),
                        "persisted block size changed: " + names[i]);
                require(!block.isInitialized() && !block.isMapped() && !block.isExecute()\n                        && block.isRead() && block.isWrite(),
                        "persisted block properties changed: " + names[i]);
            }
            var apply = service.getMethod("apply", ghidra.program.model.listing.Program.class, List.class);
            Object result = apply.invoke(null, currentProgram, List.of(memory.get(0)));
            require(result.getClass().getField("changed").getInt(result) == 0
                    && result.getClass().getField("skipped").getInt(result) == 1,
                    "approved region lost idempotence after refused Apply");
            // Re-evaluate both persisted negative controls through the production service.
            // This is a fresh process: refusal cannot depend on transient Review state.
            var preflight = service.getMethod("preflight",
                    ghidra.program.model.listing.Program.class, itemType, List.class);
            for (int i = 1; i < 3; i++) {
                Object item = memory.get(i);
                Object decision = preflight.invoke(null, currentProgram, item, candidates);
                require("BLOCKED".equals(decision.getClass().getField("state").get(decision).toString()),
                        "persisted user block no longer blocked in fresh process: " + names[i]);
                boolean refused = false;
                try {
                    apply.invoke(null, currentProgram, List.of(item));
                } catch (java.lang.reflect.InvocationTargetException failure) {
                    refused = failure.getCause() instanceof IllegalStateException;
                }
                require(refused, "fresh process accepted persisted user-owned block: " + names[i]);
                long address = itemType.getField("address").getLong(item);
                MemoryBlock block = currentProgram.getMemory().getBlock(space.getAddress(address));
                require(block != null && names[i].equals(block.getName())
                        && block.getSize() == (i == 1 ? 1 : itemType.getField("length").getInt(item))
                        && !block.isInitialized() && !block.isMapped() && !block.isExecute()
                        && block.isRead() && block.isWrite(),
                        "fresh process refusal mutated user block: " + names[i]);
            }
            println("GA08 THIRD PROCESS OWNERSHIP REFUSAL PASS: conflict=1 exact=1");
            println("GA08 POST REFUSAL PERSISTENCE PASS: module=1 user_blocks=2 idempotent=1");
        }
    }
}
