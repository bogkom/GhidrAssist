package ghidrassist.automation;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;

/**
 * Read-only whole-function body XREF pagination. Incoming targets include
 * offcut addresses; outgoing sources can include body data. "both" orders
 * incoming before outgoing and intentionally repeats internal references.
 */
public final class AutomationFunctionXrefs {
    private static final int MAX_VISITED=8192;
    private AutomationFunctionXrefs() {}

    private static JsonObject row(Function function, Reference ref, String direction) {
        JsonObject out=new JsonObject();
        out.addProperty("from",ref.getFromAddress().toString());
        out.addProperty("to",ref.getToAddress().toString());
        out.addProperty("type",ref.getReferenceType().toString());
        out.addProperty("direction",direction);
        out.addProperty("source_in_body",function.getBody().contains(ref.getFromAddress()));
        out.addProperty("target_in_body",function.getBody().contains(ref.getToAddress()));
        return out;
    }

    public static JsonObject body(Program program, Function function, String direction,
            int offset, int limit, Long expectedRevision, String expectedEntry) {
        if(program==null || function==null)
            throw new IllegalStateException("No active function");
        if(!"incoming".equals(direction) && !"outgoing".equals(direction) &&
                !"both".equals(direction))
            throw new IllegalArgumentException("Invalid body XREF direction");
        if(offset<0 || offset>4096 || limit<1 || limit>100)
            throw new IllegalArgumentException("Invalid body XREF pagination");
        long revision=program.getModificationNumber();
        if(expectedRevision!=null && revision!=expectedRevision.longValue())
            throw new IllegalStateException("Body XREF revision mismatch");
        String entry=function.getEntryPoint().toString();
        if(expectedEntry!=null && !expectedEntry.isBlank() &&
                !entry.equalsIgnoreCase(expectedEntry))
            throw new IllegalStateException("Active function changed during body XREF pagination");

        JsonArray rows=new JsonArray();
        int seen=0;
        int budget=Math.min(MAX_VISITED,offset+limit+1);
        boolean exhausted=true;
        var manager=program.getReferenceManager();
        if(!"outgoing".equals(direction)) {
            var addresses=manager.getReferenceDestinationIterator(function.getBody(),true);
            outer:
            while(addresses.hasNext()) {
                var refs=manager.getReferencesTo(addresses.next());
                while(refs.hasNext()) {
                    if(seen==budget) { exhausted=false; break outer; }
                    var ref=refs.next();
                    if(seen>=offset && rows.size()<limit)
                        rows.add(row(function,ref,"incoming"));
                    seen++;
                }
            }
        }
        if(exhausted && !"incoming".equals(direction)) {
            var addresses=manager.getReferenceSourceIterator(function.getBody(),true);
            outer:
            while(addresses.hasNext()) {
                for(var ref:manager.getReferencesFrom(addresses.next())) {
                    if(seen==budget) { exhausted=false; break outer; }
                    if(seen>=offset && rows.size()<limit)
                        rows.add(row(function,ref,"outgoing"));
                    seen++;
                }
            }
        }
        if(seen==MAX_VISITED && seen==budget) exhausted=false;
        JsonObject result=new JsonObject();
        result.addProperty("entry",entry);
        result.addProperty("revision",revision);
        result.addProperty("direction",direction);
        result.addProperty("offset",offset);
        result.addProperty("limit",limit);
        result.addProperty("returned",rows.size());
        result.addProperty("next_offset",offset+rows.size());
        result.addProperty("has_more",seen>offset+rows.size() || !exhausted);
        result.addProperty("scan_truncated",seen==MAX_VISITED && !exhausted);
        result.addProperty("total_known",exhausted);
        if(exhausted)result.addProperty("total",seen);
        result.add("rows",rows);
        result.addProperty("evidence","Static Ghidra function-body references; no dynamic CALL or execution proof");
        if(program.getModificationNumber()!=revision ||
                program.getFunctionManager().getFunctionAt(function.getEntryPoint())==null)
            throw new IllegalStateException(
                "STALE_REVISION: Program or function changed during XREF collection");
        return result;
    }
}
