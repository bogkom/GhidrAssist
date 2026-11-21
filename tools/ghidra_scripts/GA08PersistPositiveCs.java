// Separate postScript boundary: persist the approved synthetic CS after the
// preceding production Apply script has returned. Never run on user projects.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
public class GA08PersistPositiveCs extends GhidraScript {
    @Override public void run() throws Exception {
        if (currentProgram == null || !"ga08-synthetic.bin".equals(currentProgram.getName()))
            throw new IllegalStateException("GA08 SAVE FAIL: non-disposable program");
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        MemoryBlock block = currentProgram.getMemory().getBlock(space.getAddress(0x00e00000L));
        if (block == null || !"CS_WINDOW_E00000_E0001F_PART_1".equals(block.getName())
                || block.getSize() != 0x20)
            throw new IllegalStateException("GA08 SAVE FAIL: positive CS missing before save");
        // Headless-managed transactions may still be active; the actual
        // independent reopen remains the authority, never this marker alone.
        if (currentProgram.getCurrentTransactionInfo() != null)
            println("GA08 SAVE DIAGNOSTIC: transaction active");
        currentProgram.save("GA08 disposable approved CS persistence", monitor);
        println("GA08 EXPLICIT SAVE ATTEMPT PASS: fragment=1");
    }
}
