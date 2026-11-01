// @category GhidrAssist.Tests
// Read-only production graph verifier; synthetic fixture exclusively.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import com.google.gson.JsonObject;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.lang.reflect.Method;

public class GA18VerifySyntheticConvergent extends GhidraScript {
    private int assertions;
    private void check(boolean okay,String why) {
        assertions++;
        if(!okay)throw new IllegalStateException("GA18 CONVERGENT FAIL: "+why);
    }
    @Override protected void run() throws Exception {
        if(currentProgram==null || !"synthetic-convergent.bin".equals(currentProgram.getName()) ||
            !"68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString()))
            throw new IllegalStateException("Synthetic CPU32 fixture only");
        String jar=System.getProperty("ga18.test.jar","");
        if(jar.isBlank())throw new IllegalStateException("ga18.test.jar required");
        try(URLClassLoader loader=new URLClassLoader(new URL[]{Path.of(jar).toUri().toURL()},
                                                     getClass().getClassLoader())) {
            Method query=Class.forName("ghidrassist.automation.AutomationCallPaths",true,loader)
                .getMethod("query",Program.class,String.class,String.class,int.class,int.class,int.class);
            JsonObject result=(JsonObject)query.invoke(null,currentProgram,"reset","",8,0,10);
            check(result.get("total_functions").getAsInt()==4,"4 function entries");
            check(result.get("reachable_count").getAsInt()==4,"all functions reachable");
            check(result.get("unreachable_count").getAsInt()==0,"no disconnected functions");
            check(result.get("total_paths").getAsInt()==2,"two distinct paths");
            check(result.get("cycles_cut").getAsInt()==0,"no cycles");
            check(result.get("complete").getAsBoolean(),"traversal complete");
            var paths=result.getAsJsonArray("paths");
            check(paths.size()==2,"two rows");
            String[] mids={"00000130","00000160"};
            String[] rootCalls={"00000100","00000106"};
            String[] branchCalls={"00000130","00000160"};
            for(int i=0;i<2;i++) {
                var row=paths.get(i).getAsJsonObject();
                var functions=row.getAsJsonArray("functions");
                var calls=row.getAsJsonArray("call_sites");
                check(functions.size()==3,"three function entries "+i);
                check(functions.get(0).getAsString().equalsIgnoreCase("00000100"),"same root");
                check(functions.get(1).getAsString().equalsIgnoreCase(mids[i]),"distinct branch");
                check(functions.get(2).getAsString().equalsIgnoreCase("00000190"),"shared sink");
                check(calls.size()==2,"two call sites");
                check(calls.get(0).getAsString().equalsIgnoreCase(rootCalls[i]),"root CALL site");
                check(calls.get(1).getAsString().equalsIgnoreCase(branchCalls[i]),"branch CALL site");
                check(row.get("write_site").getAsString().equalsIgnoreCase("00000190"),"shared write site");
                check(row.get("mmio_target").getAsString().equalsIgnoreCase("00fffa00"),"shared MMIO address");
            }
            JsonObject page=(JsonObject)query.invoke(null,currentProgram,"reset","",8,1,1);
            check(page.get("total_paths").getAsInt()==2,"pagination total");
            check(page.getAsJsonArray("paths").size()==1,"pagination size");
            check(page.getAsJsonArray("paths").get(0).equals(paths.get(1)),"pagination preserves second path");
            JsonObject shallow=(JsonObject)query.invoke(null,currentProgram,"reset","",1,0,10);
            check(shallow.get("total_paths").getAsInt()==0,"depth excludes shared write");
            check(shallow.get("depth_cut").getAsInt()==2,"both branch paths cut");
            check(!shallow.get("complete").getAsBoolean(),"partial result declared");
        }
        println("GA18 CONVERGENT PATHS PASS: assertions="+assertions+" paths=2 shared_mmio_writes=1");
    }
}
