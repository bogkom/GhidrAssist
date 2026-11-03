package ghidrassist.automation;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.model.mem.MemoryAccessException;
import java.util.HexFormat;

/** One bounded, read-only instruction at the current CodeBrowser Listing location. */
public final class AutomationListing {
    private static final int MAX_REFERENCES = 16;
    private static final int MAX_BYTES = 32;

    private AutomationListing() {}

    public static JsonObject snapshot(Program program, ProgramLocation location)
            throws MemoryAccessException {
        JsonObject out = new JsonObject();
        String address = location == null || location.getAddress() == null
            ? "" : location.getAddress().toString();
        out.addProperty("address", address);
        out.addProperty("decoded", false);
        if (program == null || location == null || location.getAddress() == null) return out;
        if (location.getProgram() != program)
            throw new IllegalStateException("Stale Listing location belongs to a different program");
        out.addProperty("revision", program.getModificationNumber());
        if (!program.getMemory().contains(location.getAddress())) return out;
        var instruction = program.getListing().getInstructionContaining(location.getAddress());
        if (instruction == null) return out;
        out.addProperty("decoded", true);
        out.addProperty("instruction_address", instruction.getAddress().toString());
        out.addProperty("text", instruction.toString());
        out.addProperty("mnemonic", instruction.getMnemonicString());
        out.addProperty("length", instruction.getLength());
        out.addProperty("flow_type", instruction.getFlowType().toString());
        byte[] bytes = instruction.getBytes();
        int shown = Math.min(bytes.length, MAX_BYTES);
        out.addProperty("bytes_hex", HexFormat.of().formatHex(bytes, 0, shown));
        out.addProperty("bytes_truncated", bytes.length > shown);
        var function = program.getFunctionManager().getFunctionContaining(instruction.getAddress());
        out.addProperty("function_entry", function == null ? "" : function.getEntryPoint().toString());
        JsonArray references = new JsonArray();
        int total = 0;
        for (var ref : instruction.getReferencesFrom()) {
            if (total < MAX_REFERENCES) {
                JsonObject row = new JsonObject();
                row.addProperty("from", ref.getFromAddress().toString());
                row.addProperty("to", ref.getToAddress().toString());
                row.addProperty("type", ref.getReferenceType().toString());
                references.add(row);
            }
            total++;
        }
        out.addProperty("reference_total", total);
        out.addProperty("references_truncated", total > MAX_REFERENCES);
        out.add("references", references);
        out.addProperty("evidence", "Static decoded Ghidra instruction and references; no runtime execution verified");
        return out;
    }
}
