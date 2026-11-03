// @category GhidrAssist.Tests
// Native Ghidra Java script: test PRODUCTION traversal on the synthetic fixture.
import ghidra.app.script.GhidraScript;
import com.google.gson.JsonObject;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.lang.reflect.Method;

public class GA18VerifyAutomationPaths extends GhidraScript {
    private int assertions;
    private void check(boolean value, String explanation) {
        assertions++;
        if(!value) throw new IllegalStateException("GA18 PATHS FAIL: "+explanation);
    }
    private JsonObject query(Method rpc, String origin, String entry, int depth,
                             int offset, int limit) throws Exception {
        try {
            return (JsonObject)rpc.invoke(null,currentProgram,origin,entry,depth,offset,limit);
        } catch(java.lang.reflect.InvocationTargetException e) {
            Throwable cause=e.getCause();
            throw new IllegalStateException("Production traversal failed",cause);
        }
    }
    private String stringAt(JsonObject object, String key) {
        return object.get(key).getAsString().toLowerCase();
    }
    @Override protected void run() throws Exception {
        if(currentProgram==null || !"synthetic-callgraph.bin".equals(currentProgram.getName()))
            throw new IllegalStateException("Synthetic callgraph only");
        check("68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString()),
              "CPU32 language");
        String jar=System.getProperty("ga18.test.jar","");
        if(jar.isBlank()) throw new IllegalStateException("Missing ga18.test.jar");
        try(URLClassLoader loader=new URLClassLoader(
                new URL[]{Path.of(jar).toUri().toURL()},getClass().getClassLoader())) {
            Class<?> target=Class.forName("ghidrassist.automation.AutomationCallPaths",true,loader);
            Method rpc=target.getMethod("query",
                ghidra.program.model.listing.Program.class,String.class,String.class,
                int.class,int.class,int.class);
            JsonObject reset=query(rpc,"reset","",8,0,50);
            check(reset.get("total_functions").getAsInt()==20,"functions");
            check(reset.get("reachable_count").getAsInt()==6,"reset reachable");
            check(reset.get("unreachable_count").getAsInt()==14,"reset unreachable");
            check(reset.get("total_paths").getAsInt()==1,"reset paths");
            check(reset.get("cycles_cut").getAsInt()==1,"cycle");
            check(reset.get("complete").getAsBoolean(),"complete graph at depth 8");
            JsonObject hit=reset.getAsJsonArray("paths").get(0).getAsJsonObject();
            check(hit.getAsJsonArray("functions").size()==4,"four steps");
            check(hit.getAsJsonArray("call_sites").size()==3,"three CALL sites");
            check("00000100".equalsIgnoreCase(hit.getAsJsonArray("functions").get(0).getAsString()),"reset source");
            check("00000190".equalsIgnoreCase(hit.getAsJsonArray("functions").get(3).getAsString()),"writer function");
            check("00000196".equalsIgnoreCase(stringAt(hit,"write_site")),"writer PC");
            check("00fffa00".equalsIgnoreCase(stringAt(hit,"mmio_target")),"MMIO target");
            JsonObject disconnected=query(rpc,"entry","00000220",20,0,50);
            check(disconnected.get("reachable_count").getAsInt()==14,"disconnected component");
            check(disconnected.get("total_paths").getAsInt()==3,"three disconnected writers");
            check(disconnected.getAsJsonArray("paths").size()==3,"all writer rows");
            JsonObject paged=query(rpc,"entry","00000220",20,1,1);
            check(paged.get("total_paths").getAsInt()==3,"stable count");
            check(paged.getAsJsonArray("paths").size()==1,"page size");
            check(paged.getAsJsonArray("paths").get(0).toString()
                .equals(disconnected.getAsJsonArray("paths").get(1).toString()),"page content");
            JsonObject shallow=query(rpc,"reset","",2,0,100);
            check(shallow.get("reachable_count").getAsInt()==3,"depth reached");
            check(shallow.get("depth_cut").getAsInt()>0,"depth truncation explicit");
            check(!shallow.get("complete").getAsBoolean(),"depth incomplete");
        }
        println("GA18 PRODUCTION PATHS PASS: assertions="+assertions+
                " (real Ghidra, synthetic fixture; static evidence only)");
    }
}
