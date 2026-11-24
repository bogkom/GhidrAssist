// Final headless postScript: revalidate and apply the approved CS in the
// final script transaction, then let analyzeHeadless persist the project.
// Never run on a user project; fourth independent reopen is the authority.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.List;

public class GA08PersistPositiveCs extends GhidraScript {
    private void require(boolean ok, String message) {
        if (!ok) throw new IllegalStateException("GA08 SAVE FAIL: " + message);
    }

    @Override public void run() throws Exception {
        require(currentProgram != null && "ga08-synthetic.bin".equals(currentProgram.getName()),
                "non-disposable program");
        String path = System.getProperty("ga08.test.jar");
        require(path != null && new File(path).isFile(), "production JAR unavailable");
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        long address = 0x00e00000L;
        String fragmentName = "CS_WINDOW_E00000_E0001F_PART_1";
        MemoryBlock block = currentProgram.getMemory().getBlock(space.getAddress(address));
        // Some headless script boundaries discard a prior script's transient
        // transaction. Re-apply through the production service in THIS final
        // transaction, rather than saving an absent block or forging a marker.
        try (URLClassLoader loader = new URLClassLoader(
                new URL[]{new File(path).toURI().toURL()},
                ghidra.program.model.listing.Program.class.getClassLoader())) {
            Class<?> kindType = Class.forName("ghidrassist.hardware.HardwareApplyPlan$Kind", true, loader);
            Class<?> itemType = Class.forName("ghidrassist.hardware.HardwareApplyPlan$Item", true, loader);
            Class<?> service = Class.forName("ghidrassist.hardware.HardwareApplyService", true, loader);
            @SuppressWarnings({"unchecked", "rawtypes"})
            Object memoryKind = Enum.valueOf((Class<? extends Enum>) kindType.asSubclass(Enum.class), "MEMORY");
            var ctor = itemType.getDeclaredConstructor(kindType, String.class, long.class,
                    int.class, String.class);
            ctor.setAccessible(true);
            Object candidate = ctor.newInstance(memoryKind, "CS_WINDOW_E00000_E0001F",
                    address, 0x20, "explicit disposable CS approval; physical wiring UNKNOWN");
            var preflight = service.getMethod("preflight",
                    ghidra.program.model.listing.Program.class, itemType, List.class);
            var apply = service.getMethod("apply",
                    ghidra.program.model.listing.Program.class, List.class);
            Object decision = preflight.invoke(null, currentProgram, candidate, List.of(candidate));
            String state = decision.getClass().getField("state").get(decision).toString();
            require(block == null ? "MANUAL_REVIEW".equals(state) : "ALREADY_PRESENT".equals(state),
                    "unexpected final transaction preflight: " + state);
            Object result = apply.invoke(null, currentProgram, List.of(candidate));
            int changed = result.getClass().getField("changed").getInt(result);
            int skipped = result.getClass().getField("skipped").getInt(result);
            require(block == null ? changed == 1 : changed == 0 && skipped == 1,
                    "final transaction Apply was not safe/idempotent");
        }
        block = currentProgram.getMemory().getBlock(space.getAddress(address));
        require(block != null && fragmentName.equals(block.getName())
                && block.getSize() == 0x20 && !block.isInitialized() && !block.isMapped()
                && block.isRead() && block.isWrite() && !block.isExecute(),
                "approved CS missing or invalid in final transaction");
        println("GA08 SAVE DIAGNOSTIC: programChanged=" + currentProgram.isChanged()
                + " fragment=" + block.getStart() + ".." + block.getEnd()
                + " blocks=" + currentProgram.getMemory().getBlocks().length);
        // HeadlessAnalyzer saves after the postScript transaction completes.
        // Calling currentProgram.save() here can race that transaction.
        println("GA08 FINAL TRANSACTION APPLY PASS: fragment=1");
    }
}
