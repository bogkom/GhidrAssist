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
                require(user.getSize() == (item == exact ? itemType.getField("length").getInt(item) : 1),
                        "user block size changed across reopen");
                require(!user.isInitialized() && !user.isMapped() && !user.isExecute(),
                        "user block properties changed across reopen");
            }
            Method apply = service.getMethod("apply",
                    ghidra.program.model.listing.Program.class, List.class);
            Object outcome = apply.invoke(null, currentProgram, List.of(first));
            require(outcome.getClass().getField("changed").getInt(outcome) == 0
                    && outcome.getClass().getField("skipped").getInt(outcome) == 1,
                    "reopened approved module must be idempotent");
            // Persisted user-owned memory must still be refused on a fresh service invocation.
            // Neither a conflicting range nor an exact-size user block is owned by GhidrAssist.
            for (Object item : List.of(conflict, exact)) {
                boolean refused = false;
                try {
                    apply.invoke(null, currentProgram, List.of(item));
                } catch (java.lang.reflect.InvocationTargetException failure) {
                    refused = failure.getCause() instanceof IllegalStateException;
                }
                require(refused, "reopened Apply accepted user-owned memory");
                long address = itemType.getField("address").getLong(item);
                String expected = item == conflict ? "GA08_USER_CONFLICT" : "GA08_USER_EXACT";
                MemoryBlock user = currentProgram.getMemory().getBlock(space.getAddress(address));
                require(user != null && expected.equals(user.getName()),
                        "reopened refused Apply altered user-owned memory: " + expected);
            }
            require(currentProgram.getMemory().getBlock(space.getAddress(firstAddress)) == applied,
                    "reopened refusal changed the approved module");
            // Same name and exact extent do not confer ownership when permissions differ.
            // Exercise the production preflight against a disposable user block,
            // then restore the user's name and permissions even on assertion failure.
            MemoryBlock impostor = currentProgram.getMemory().getBlock(
                    space.getAddress(itemType.getField("address").getLong(exact)));
            String originalName = impostor.getName();
            boolean originalExecute = impostor.isExecute();
            boolean originalWrite = impostor.isWrite();
            boolean originalRead = impostor.isRead();
            try {
                impostor.setName((String) itemType.getField("name").get(exact));
                impostor.setExecute(true);
                for (int variant = 0; variant < 3; variant++) {
                    if (variant == 1) {
                        impostor.setExecute(false);
                        impostor.setWrite(false);
                    } else if (variant == 2) {
                        impostor.setWrite(true);
                        impostor.setRead(false);
                    }
                    Object decision = service.getMethod("preflight",
                            ghidra.program.model.listing.Program.class, itemType, List.class)
                            .invoke(null, currentProgram, exact, items);
                    require("BLOCKED".equals(decision.getClass().getField("state").get(decision).toString()),
                            "same-name user block with unsafe permissions passed preflight");
                    boolean rejected = false;
                    try {
                        apply.invoke(null, currentProgram, List.of(exact));
                    } catch (java.lang.reflect.InvocationTargetException failure) {
                        rejected = failure.getCause() instanceof IllegalStateException;
                    }
                    require(rejected, "same-name user block with unsafe permissions accepted Apply");
                    require(currentProgram.getMemory().getBlock(impostor.getStart()) == impostor,
                            "permission refusal replaced user memory");
                }
            } finally {
                impostor.setExecute(originalExecute);
                impostor.setRead(originalRead);
                impostor.setWrite(originalWrite);
                impostor.setName(originalName);
            }
            require(originalName.equals(impostor.getName())
                    && impostor.isExecute() == originalExecute
                    && impostor.isWrite() == originalWrite
                    && impostor.isRead() == originalRead,
                    "permission fixture failed to restore user block");
            println("GA08 REOPEN PERMISSION REFUSAL PASS: executable=1 readonly=1 unreadable=1");
            println("GA08 REOPEN USER OWNERSHIP REFUSAL PASS: conflict=1 exact=1");
            println("GA08 PRODUCTION APPLY REOPEN PASS: module=1 user_blocks=2 idempotent=1");
        }
    }
}
