// GA-12: genuine program-content witness for a disposable restored Ghidra project.
// Run on both initial import and -process reopen; no production program is touched.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;

public class GA12VerifyRestoredProgram extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: no current program");
        }
        String[] args = getScriptArgs();
        if (args.length != 2 || !currentProgram.getName().equals(args[0])
                || !(args[1].equals("seed") || args[1].equals("verify"))) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: unexpected program");
        }
        if (!"68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString())) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: unexpected processor/language");
        }
        if (currentProgram.getMemory().getSize() != 6) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: unexpected memory size");
        }
        Address start = currentProgram.getMinAddress();
        if (start == null) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: missing start address");
        }
        byte[] actual = new byte[6];
        if (currentProgram.getMemory().getBytes(start, actual) != actual.length) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: incomplete fixture bytes");
        }
        byte[] expected = {(byte) 0x4e, (byte) 0x71, (byte) 0x4e,
                           (byte) 0x71, (byte) 0x4e, (byte) 0x75};
        if (!java.util.Arrays.equals(actual, expected)) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: fixture content mismatch");
        }
        // A database annotation, unlike the imported fixture bytes, must survive
        // Ghidra's save/close, offline copy, restore and process reopen.
        final String marker = "GA12_SYNTHETIC_PERSISTED_ANALYSIS_V1";
        String observed = currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, start);
        if (args[1].equals("seed")) {
            if (observed != null && !observed.isEmpty()) {
                throw new IllegalStateException("GA12_SEED_FAIL: annotation already present");
            }
            currentProgram.getListing().setComment(start, CodeUnit.PLATE_COMMENT, marker);
            println("GA12_ANALYSIS_SEEDED");
        } else {
            if (!marker.equals(observed)) {
                throw new IllegalStateException("GA12_REOPEN_FAIL: persisted annotation missing or changed");
            }
            println("GA12_ANALYSIS_PERSISTED_PASS");
        }
        println("GA12_REOPEN_PASS program=" + currentProgram.getName()
                + " language=" + currentProgram.getLanguageID()
                + " fixture=4e714e714e75 memory_bytes=6");
    }
}
