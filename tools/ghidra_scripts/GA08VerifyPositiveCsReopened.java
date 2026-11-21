// Fourth independent process: verify persisted positive CS Apply after all refusals.
// Disposable CPU32 only. Read-only inspection; no claim of GUI Undo or physical decode.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.util.Arrays;

public class GA08VerifyPositiveCsReopened extends GhidraScript {
    private void require(boolean ok, String message) {
        if (!ok) throw new IllegalStateException("GA08 FOURTH REOPEN FAIL: " + message);
    }

    @Override public void run() throws Exception {
        require(currentProgram != null && "ga08-synthetic.bin".equals(currentProgram.getName()),
                "non-disposable program");
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var memory = currentProgram.getMemory();
        long start = 0x00e00000L;
        long end = 0x00e0001fL;
        String expected = "CS_WINDOW_E00000_E0001F_PART_1";
        MemoryBlock cs = memory.getBlock(space.getAddress(start));
        require(cs != null && expected.equals(cs.getName())
                && cs.getStart().equals(space.getAddress(start))
                && cs.getEnd().equals(space.getAddress(end))
                && cs.getSize() == 0x20
                && !cs.isInitialized() && !cs.isMapped()
                && cs.isRead() && cs.isWrite() && !cs.isExecute()
                && !cs.isVolatile(), "approved CS fragment not persisted exactly");
        require(memory.getBlock(space.getAddress(end)) == cs,
                "CS end not covered by same fragment");
        require(Arrays.stream(memory.getBlocks()).filter(b -> b.getName().equals(expected)).count() == 1,
                "duplicate approved CS fragment");
        require(Arrays.stream(memory.getBlocks())
                .anyMatch(b -> "GA08_USER_CONFLICT".equals(b.getName()))
                && Arrays.stream(memory.getBlocks())
                .anyMatch(b -> "GA08_USER_EXACT".equals(b.getName())),
                "negative user controls not preserved");
        println("GA08 FOURTH PROCESS POSITIVE CS PERSISTENCE PASS: fragment=1 user_controls=2");
    }
}
