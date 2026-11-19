// GA-12 isolated, explicitly authorized annotation apply/rollback witness.
// Persisted compensating rollback, not a claim about Ghidra's in-memory Undo stack.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;

public class GA12AuthorizedAnnotationCycle extends GhidraScript {
    private static final String BASE = "GA12_SYNTHETIC_SECOND_SITE_V1";
    private static final String APPLIED = "GA12_AUTHORIZED_APPLIED_V1";
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || currentProgram == null
                || !currentProgram.getName().equals(args[0])
                || !"68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString())
                || !args[2].equals("authorize-isolated-analysis")) {
            throw new IllegalStateException("GA12_AUTHORIZATION_REJECTED");
        }
        Address site = currentProgram.getMinAddress().add(2);
        String observed = currentProgram.getListing().getComment(CodeUnit.EOL_COMMENT, site);
        // Check unrelated persisted objects before every authorized transition.
        String plate = currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, currentProgram.getMinAddress());
        Symbol label = currentProgram.getSymbolTable().getPrimarySymbol(currentProgram.getMinAddress().add(4));
        if (!"GA12_SYNTHETIC_PERSISTED_ANALYSIS_V1".equals(plate)
                || label == null || !"GA12_PERSISTED_LABEL".equals(label.getName())
                || label.getSource() != SourceType.USER_DEFINED) {
            throw new IllegalStateException("GA12_UNRELATED_ANALYSIS_CHANGED");
        }
        switch (args[1]) {
            case "apply":
                if (!BASE.equals(observed)) {
                    throw new IllegalStateException("GA12_APPLY_PRECONDITION_REJECTED");
                }
                currentProgram.getListing().setComment(site, CodeUnit.EOL_COMMENT, APPLIED);
                println("GA12_AUTHORIZED_APPLY_PASS");
                break;
            case "verify-applied":
                if (!APPLIED.equals(observed)) {
                    throw new IllegalStateException("GA12_APPLIED_REOPEN_FAIL");
                }
                println("GA12_APPLIED_REOPEN_PASS");
                break;
            case "rollback":
                if (!APPLIED.equals(observed)) {
                    throw new IllegalStateException("GA12_ROLLBACK_PRECONDITION_REJECTED");
                }
                currentProgram.getListing().setComment(site, CodeUnit.EOL_COMMENT, BASE);
                println("GA12_AUTHORIZED_ROLLBACK_PASS");
                break;
            default:
                throw new IllegalStateException("GA12_UNSUPPORTED_ACTION");
        }
    }
}
