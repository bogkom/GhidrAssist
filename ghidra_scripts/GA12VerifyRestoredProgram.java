// GA-12: verify that a restored disposable Ghidra project actually opens.
// This is a GhidraScript, run by analyzeHeadless -process on a synthetic import.
import ghidra.app.script.GhidraScript;

public class GA12VerifyRestoredProgram extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: no current program");
        }
        String[] args = getScriptArgs();
        if (args.length != 1 || !currentProgram.getName().equals(args[0])) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: unexpected program: "
                    + currentProgram.getName());
        }
        if (currentProgram.getMemory().getSize() == 0) {
            throw new IllegalStateException("GA12_REOPEN_FAIL: empty program memory");
        }
        println("GA12_REOPEN_PASS program=" + currentProgram.getName()
                + " memory_bytes=" + currentProgram.getMemory().getSize());
    }
}
