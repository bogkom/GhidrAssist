package ghidrassist.automation;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.program.model.mem.MemoryAccessException;
import java.util.HexFormat;

/** One bounded, read-only instruction at the current CodeBrowser Listing location. */
public final class AutomationListing {
    private static final int MAX_REFERENCES = 16;
    private static final int MAX_BYTES = 32;

    private AutomationListing() {}

    /** Read-only decoded instruction pages, with optional exact revision guard. */
    public static JsonObject range(Program program, ProgramLocation location,
            String startText, int offset, int limit, Long expectedRevision)
            throws MemoryAccessException {
        if(program==null)throw new IllegalStateException("No active program");
        if(location!=null && location.getProgram()!=program)
            throw new IllegalStateException("Stale Listing location belongs to a different program");
        if(offset<0 || offset>4096 || limit<1 || limit>64)
            throw new IllegalArgumentException("Invalid Listing range pagination");
        // CodeBrowser cursor movement does not change Program modification.
        // Subsequent pages must retain the first response's explicit start
        // address and revision; a fresh UI location is not the old cursor.
        if(offset>0 && (expectedRevision==null ||
                startText==null || startText.isBlank()))
            throw new IllegalArgumentException(
                "Subsequent Listing page requires explicit start and revision");
        long revision=program.getModificationNumber();
        if(expectedRevision!=null && revision!=expectedRevision.longValue())
            throw new IllegalStateException("Listing revision mismatch");
        Address start=startText==null || startText.isBlank()
            ? (location==null ? null : location.getAddress())
            : program.getAddressFactory().getAddress(startText);
        if(start==null || !program.getMemory().contains(start))
            throw new IllegalArgumentException("Invalid Listing range start address");

        JsonArray rows=new JsonArray();
        var iterator=program.getListing().getInstructions(start,true);
        int scanned=0;
        while(iterator.hasNext() && scanned<offset+limit) {
            var instruction=iterator.next();
            if(scanned>=offset) {
                JsonObject evidence=snapshot(program,
                    new ProgramLocation(program,instruction.getAddress()));
                rows.add(evidence);
            }
            scanned++;
        }
        JsonObject result=new JsonObject();
        result.addProperty("start",start.toString());
        result.addProperty("revision",revision);
        result.addProperty("offset",offset);
        result.addProperty("limit",limit);
        result.addProperty("returned",rows.size());
        result.addProperty("next_offset",offset+rows.size());
        result.addProperty("has_more",iterator.hasNext());
        result.addProperty("offset_unit","decoded_instructions");
        result.add("rows",rows);
        result.addProperty("evidence",
            "Static decoded Ghidra Listing in address order; gaps possible, no runtime execution verified");
        if(program.getModificationNumber()!=revision)
            throw new IllegalStateException(
                "STALE_REVISION: Listing changed during page collection");
        return result;
    }

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
