// @category GhidrAssist.Tests
// Read-only: unresolved JSR (A0) must be reported without inventing a target.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import com.google.gson.JsonObject;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.lang.reflect.Method;

public class GA18VerifySyntheticIndirect extends GhidraScript {
    private int assertions;
    private void check(boolean valid,String label) {
        assertions++;
        if(!valid)throw new IllegalStateException("GA18 INDIRECT FAIL: "+label);
    }
    @Override protected void run() throws Exception {
        if(currentProgram==null || !"synthetic-indirect.bin".equals(currentProgram.getName()) ||
            !"68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString()))
            throw new IllegalStateException("Synthetic indirect CPU32 only");
        String jar=System.getProperty("ga18.test.jar","");
        if(jar.isBlank())throw new IllegalStateException("ga18.test.jar required");
        try(URLClassLoader loader=new URLClassLoader(new URL[]{Path.of(jar).toUri().toURL()},getClass().getClassLoader())) {
            var klass=Class.forName("ghidrassist.automation.AutomationCallPaths",true,loader);
            Method query=klass.getMethod("query",Program.class,String.class,String.class,int.class,int.class,int.class);
            JsonObject reset=(JsonObject)query.invoke(null,currentProgram,"reset","",8,0,10);
            check(reset.get("total_functions").getAsInt()==2,"two functions");
            check(reset.get("reachable_count").getAsInt()==1,"indirect target not guessed");
            check(reset.get("unreachable_count").getAsInt()==1,"writer not asserted reachable");
            check(reset.get("total_paths").getAsInt()==0,"no invented WRITE path");
            check(reset.get("unresolved_calls").getAsInt()==1,"unresolved indirect call counted");
            check(reset.getAsJsonArray("unresolved_call_sites").size()==1,"site count");
            check(reset.getAsJsonArray("unresolved_call_sites").get(0).getAsString().equalsIgnoreCase("00000100"),"site address");
            check(!reset.get("complete").getAsBoolean(),"incomplete static evidence");
            check(!reset.get("budget_exceeded").getAsBoolean(),"no budget exhaustion");
            JsonObject writer=(JsonObject)query.invoke(null,currentProgram,"entry","00000130",8,0,10);
            check(writer.get("total_paths").getAsInt()==1,"direct writer from entry remains visible");
            check(writer.get("unresolved_calls").getAsInt()==0,"no indirect calls at writer");
            check(writer.get("complete").getAsBoolean(),"writer entry complete");
            check(writer.getAsJsonArray("paths").get(0).getAsJsonObject().get("mmio_target").getAsString().equalsIgnoreCase("00fffa00"),"write address");
        }
        println("GA18 INDIRECT PATHS PASS: assertions="+assertions+" unresolved=1 no_guessed_paths=1");
    }
}
