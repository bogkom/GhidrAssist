// GA-12: genuine program-content witness for a disposable restored Ghidra project.
// Run on both initial import and -process reopen; no production program is touched.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;

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
        final String secondMarker = "GA12_SYNTHETIC_SECOND_SITE_V1";
        Address secondSite = start.add(2);
        if (!currentProgram.getMemory().contains(secondSite)) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: missing second site");
        }
        // A user-defined label is a separate persisted database object, not a comment.
        final String labelName = "GA12_PERSISTED_LABEL";
        Address labelSite = start.add(4);
        if (!currentProgram.getMemory().contains(labelSite)) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: missing label site");
        }
        Symbol labelObserved = currentProgram.getSymbolTable().getPrimarySymbol(labelSite);
        String secondObserved = currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT, secondSite);
        String observed = currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, start);
        if (args[1].equals("seed")) {
            if ((observed != null && !observed.isEmpty())
                    || (secondObserved != null && !secondObserved.isEmpty())
                    || labelObserved != null) {
                throw new IllegalStateException("GA12_SEED_FAIL: annotation already present");
            }
            currentProgram.getListing().setComment(start, CodeUnit.PLATE_COMMENT, marker);
            currentProgram.getListing().setComment(secondSite, CodeUnit.EOL_COMMENT, secondMarker);
            createLabel(labelSite, labelName, true);
            Symbol seededLabel = currentProgram.getSymbolTable().getPrimarySymbol(labelSite);
            if (seededLabel == null || !labelName.equals(seededLabel.getName())
                    || seededLabel.getSource() != SourceType.USER_DEFINED) {
                throw new IllegalStateException("GA12_SEED_FAIL: user label not created");
            }
            println("GA12_ANALYSIS_SEEDED");
        } else {
            if (!marker.equals(observed) || !secondMarker.equals(secondObserved)
                    || labelObserved == null || !labelName.equals(labelObserved.getName())
                    || labelObserved.getSource() != SourceType.USER_DEFINED) {
                throw new IllegalStateException("GA12_REOPEN_FAIL: persisted annotation missing or changed");
            }
            println("GA12_ANALYSIS_PERSISTED_PASS");
        }
        println("GA12_REOPEN_PASS program=" + currentProgram.getName()
                + " language=" + currentProgram.getLanguageID()
                + " fixture=4e714e714e75 memory_bytes=6");
    }
}
