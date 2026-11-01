// @category GhidrAssist.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.JsonObject;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.lang.reflect.Method;

public class GA18VerifySyntheticIndirectConstant extends GhidraScript {
    private int assertions;
    private void check(boolean valid,String label) {
        assertions++;
        if(!valid)throw new IllegalStateException("GA18 INDIRECT CONSTANT FAIL: "+label);
    }
    @Override protected void run() throws Exception {
        if(currentProgram==null || !"synthetic-indirect-constant.bin".equals(currentProgram.getName()) ||
           !"68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString()))
            throw new IllegalStateException("Synthetic indirect constant CPU32 required");
        String jar=System.getProperty("ga18.test.jar","");
        if(jar.isBlank())throw new IllegalStateException("ga18.test.jar required");
        try(URLClassLoader loader=new URLClassLoader(new URL[]{Path.of(jar).toUri().toURL()},getClass().getClassLoader())) {
            Method query=Class.forName("ghidrassist.automation.AutomationCallPaths",true,loader)
                 .getMethod("query",Program.class,String.class,String.class,int.class,int.class,int.class);
            var space=currentProgram.getAddressFactory().getDefaultAddressSpace();
            var callsite=space.getAddress(0x106);
            var target=space.getAddress(0x130);
            var refs=currentProgram.getReferenceManager();

            // Isolated fixture only. Suppress all preexisting CALL references
            // during the fallback probe, then ROLLBACK both probes.
            int tx=currentProgram.startTransaction("GA18 temporary CALL reference provenance probes");
            try {
                Reference[] before=refs.getReferencesFrom(callsite);
                for(Reference ref:before) {
                    if(ref.getReferenceType().isCall())
                        refs.delete(ref);
                }
                JsonObject fallback=(JsonObject)query.invoke(null,currentProgram,"reset","",8,0,10);
                check(fallback.get("total_functions").getAsInt()==2,"two functions");
                check(fallback.get("reachable_count").getAsInt()==2,"fallback reaches writer");
                check(fallback.get("total_paths").getAsInt()==1,"fallback one path");
                check(fallback.get("unresolved_calls").getAsInt()==0,"fallback resolved");
                check(fallback.getAsJsonArray("unresolved_call_sites").size()==0,"no unresolved sites");
                check(fallback.get("complete").getAsBoolean(),"fallback complete");
                var row=fallback.getAsJsonArray("paths").get(0).getAsJsonObject();
                check(row.getAsJsonArray("functions").size()==2,"two function chain");
                check(row.getAsJsonArray("functions").get(1).getAsString().equalsIgnoreCase("00000130"),"target");
                check(row.getAsJsonArray("call_sites").get(0).getAsString().equalsIgnoreCase("00000106"),"JSR site");
                check(row.getAsJsonArray("call_evidence").get(0).getAsString().equals("adjacent_movea_immediate"),
                      "fallback provenance mandatory");
                check(row.get("write_site").getAsString().equalsIgnoreCase("00000130"),"write instruction");
                check(row.get("mmio_target").getAsString().equalsIgnoreCase("00fffa00"),"MMIO target");

                refs.addMemoryReference(callsite,target,RefType.UNCONDITIONAL_CALL,SourceType.USER_DEFINED,0);
                JsonObject referenced=(JsonObject)query.invoke(null,currentProgram,"reset","",8,0,10);
                check(referenced.get("total_paths").getAsInt()==1,"reference path");
                check(referenced.get("reachable_count").getAsInt()==2,"reference reachability");
                check(referenced.getAsJsonArray("paths").get(0).getAsJsonObject()
                    .getAsJsonArray("call_evidence").get(0).getAsString()
                    .equals("ghidra_call_reference"),"reference provenance mandatory");
                check(referenced.get("complete").getAsBoolean(),"reference complete");
            } finally {
                currentProgram.endTransaction(tx,false); // Never persist injected/deleted test references.
            }
        }
        println("GA18 INDIRECT CONSTANT PROVENANCE PASS: assertions="+assertions+" fallback=1 ghidra_reference=1 rollback=1");
    }
}
