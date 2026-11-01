// @category GhidrAssist.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
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
            JsonObject result=(JsonObject)query.invoke(null,currentProgram,"reset","",8,0,10);
            check(result.get("total_functions").getAsInt()==2,"two functions");
            check(result.get("reachable_count").getAsInt()==2,"proven indirect target reached");
            check(result.get("total_paths").getAsInt()==1,"one MMIO path");
            check(result.get("unresolved_calls").getAsInt()==0,"resolved indirect site not unknown");
            check(result.getAsJsonArray("unresolved_call_sites").size()==0,"zero unresolved sites");
            check(result.get("complete").getAsBoolean(),"complete path");
            var row=result.getAsJsonArray("paths").get(0).getAsJsonObject();
            check(row.getAsJsonArray("functions").size()==2,"two function chain");
            check(row.getAsJsonArray("functions").get(1).getAsString().equalsIgnoreCase("00000130"),"function target");
            check(row.getAsJsonArray("call_sites").get(0).getAsString().equalsIgnoreCase("00000106"),"indirect JSR site");
            check(row.getAsJsonArray("call_evidence").get(0).getAsString().equals("adjacent_movea_immediate"),"explicit provenance");
            check(row.get("write_site").getAsString().equalsIgnoreCase("00000130"),"shared write instruction");
            check(row.get("mmio_target").getAsString().equalsIgnoreCase("00fffa00"),"peripheral target");
        }
        println("GA18 INDIRECT CONSTANT PASS: assertions="+assertions+" resolved_calls=1 paths=1");
    }
}
