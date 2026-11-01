// @category GhidrAssist.Tests
// Read-only verification of the isolated synthetic CPU32 call graph.
// No Jython, no firmware modification, no project transactions.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;

public class GA18VerifySyntheticCallgraph extends GhidraScript {
    private static final int[] TARGET = {
        1, 2, 3, 4, 5, 2, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, -1
    };
    private static final int[] WRITERS = {3, 8, 13, 18};
    private static final long[] MMIO = {0xFFFA00L, 0xFFFA4CL, 0xFFFC00L, 0xFFFD00L};
    private int assertions = 0;
    private Address at(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
    private void check(boolean okay, String message) {
        assertions++;
        if (!okay) throw new IllegalStateException("GA18 FAIL: " + message);
    }
    @Override
    protected void run() throws Exception {
        if (currentProgram == null ||
            !"synthetic-callgraph.bin".equals(currentProgram.getName())) {
            throw new IllegalStateException("Only synthetic-callgraph.bin is permitted");
        }
        check("68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString()),
            "Wrong language");
        check(currentProgram.getMemory().contains(at(0x100)), "Import base must be 0x00000000");

        int verifiedEdges = 0;
        int verifiedMmio = 0;
        for (int i = 0; i < 20; i++) {
            monitor.checkCancelled();
            Address entry = at(0x100L + 0x30L * i);
            Function f = currentProgram.getFunctionManager().getFunctionAt(entry);
            check(f != null, "Missing function " + i + " at " + entry);
            Instruction first = currentProgram.getListing().getInstructionAt(entry);
            check(first != null, "Missing instruction at " + entry);
            int expected = TARGET[i];
            if (expected >= 0) {
                Address dst = at(0x100L + 0x30L * expected);
                check("JSR".equalsIgnoreCase(first.getMnemonicString()),
                    "Expected JSR at " + entry + ", got " + first.getMnemonicString());
                boolean flow = false;
                for (Address target : first.getFlows()) if (dst.equals(target)) flow = true;
                check(flow, "JSR flow from " + entry + " does not reach " + dst);
                boolean xref = false;
                for (Reference r : currentProgram.getReferenceManager().getReferencesTo(dst)) {
                    if (entry.equals(r.getFromAddress()) && r.getReferenceType().isCall()) {
                        xref = true;
                    }
                }
                check(xref, "Missing CALL XREF from " + entry + " to " + dst);
                verifiedEdges++;
            }
        }
        for (int k = 0; k < WRITERS.length; ++k) {
            int n = WRITERS[k];
            Address site = at(0x100L + 0x30L * n + 6L);
            Address target = at(MMIO[k]);
            Instruction ins = currentProgram.getListing().getInstructionAt(site);
            check(ins != null && "MOVE.W".equalsIgnoreCase(ins.getMnemonicString()),
                "Missing MOVE.W at " + site);
            boolean write = false;
            for (Reference r : ins.getReferencesFrom()) {
                if (target.equals(r.getToAddress()) && r.getReferenceType().isWrite())
                    write = true;
            }
            check(write, "Missing static WRITE XREF from " + site + " to " + target);
            verifiedMmio++;
        }
        // Static expected reachability: reset->1->2->3->4->5->2 is a cycle.
        Set<Integer> visited = new HashSet<Integer>();
        int node = 0;
        while (node >= 0 && visited.add(node)) node = TARGET[node];
        check(node == 2, "Expected reachable cycle at node 2");
        check(visited.size() == 6, "Expected six reachable functions from reset");
        check(!visited.contains(8) && !visited.contains(13) && !visited.contains(18),
            "Disconnected MMIO writer unexpectedly reachable");
        println("GA18 CALLGRAPH PASS: functions=20 edges=" + verifiedEdges +
            " mmio_static_writes=" + verifiedMmio +
            " reset_reachable=" + visited.size() + " assertions=" + assertions);
        println("Evidence is static only: no runtime execution or physical mapping verified.");
    }
}
