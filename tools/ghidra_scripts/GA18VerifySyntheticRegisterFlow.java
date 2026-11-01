// @category GhidrAssist.Tests
// Strictly synthetic CPU32; all temporary CALL reference changes are rolled back.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import com.google.gson.JsonObject;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.lang.reflect.Method;

public class GA18VerifySyntheticRegisterFlow extends GhidraScript {
    private int assertions;
    private void check(boolean condition,String why) {
        assertions++;
        if(!condition) throw new IllegalStateException("GA18 REGISTER FLOW FAIL: "+why);
    }
    @Override protected void run() throws Exception {
        if(currentProgram==null || !"synthetic-register-flow.bin".equals(currentProgram.getName()) ||
           !"68000:BE:32:CPU32".equals(currentProgram.getLanguageID().toString()))
            throw new IllegalStateException("Isolated CPU32 synthetic-register-flow.bin required");
        String jar=System.getProperty("ga18.test.jar","");
        if(jar.isBlank()) throw new IllegalStateException("ga18.test.jar required");
        try(URLClassLoader loader=new URLClassLoader(new URL[]{Path.of(jar).toUri().toURL()},
                  getClass().getClassLoader()) {
                @Override protected synchronized Class<?> loadClass(String name,boolean resolve)
                        throws ClassNotFoundException {
                    if(name.equals("ghidrassist.automation.AutomationCallPaths") ||
                       name.startsWith("ghidrassist.automation.AutomationCallPaths$")) {
                        Class<?> type=findLoadedClass(name);
                        if(type==null) type=findClass(name);
                        if(resolve) resolveClass(type);
                        return type;
                    }
                    return super.loadClass(name,resolve);
                }
            }) {
            Method query=Class.forName("ghidrassist.automation.AutomationCallPaths",true,loader)
                .getMethod("query",Program.class,String.class,String.class,int.class,int.class,int.class);
            var space=currentProgram.getAddressFactory().getDefaultAddressSpace();
            var refs=currentProgram.getReferenceManager();
            int tx=currentProgram.startTransaction("GA18 temporary synthetic CALL reference removal");
            try {
                for(long site:new long[]{0x108,0x168,0x19a}) {
                    for(Reference ref:refs.getReferencesFrom(space.getAddress(site)))
                        if(ref.getReferenceType().isCall()) refs.delete(ref);
                }
                JsonObject positive=(JsonObject)query.invoke(null,currentProgram,"reset","",8,0,10);
                check(positive.get("total_functions").getAsInt()==4,"all functions indexed");
                check(positive.get("reachable_count").getAsInt()==2,"only known target reachable");
                check(positive.get("unreachable_count").getAsInt()==2,"other roots disconnected");
                check(positive.get("total_paths").getAsInt()==1,"one path");
                check(positive.get("unresolved_calls").getAsInt()==0,"known call resolved");
                check(positive.get("complete").getAsBoolean(),"complete known path");
                var row=positive.getAsJsonArray("paths").get(0).getAsJsonObject();
                check(row.getAsJsonArray("functions").get(1).getAsString().equalsIgnoreCase("00000130"),"target 130");
                check(row.getAsJsonArray("call_sites").get(0).getAsString().equalsIgnoreCase("00000108"),"JSR address 108");
                check(row.getAsJsonArray("call_evidence").get(0).getAsString().equals("bounded_movea_nop_chain"),"bounded proof");
                check(row.get("write_site").getAsString().equalsIgnoreCase("00000130"),"MMIO write 130");
                for(String origin:new String[]{"00000160","00000190"}) {
                    JsonObject negative=(JsonObject)query.invoke(null,currentProgram,"entry",origin,8,0,10);
                    check(negative.get("reachable_count").getAsInt()==1,"no guessed target "+origin);
                    check(negative.get("total_paths").getAsInt()==0,"no phantom write "+origin);
                    check(negative.get("unresolved_calls").getAsInt()==1,"unresolved "+origin);
                    check(negative.getAsJsonArray("unresolved_call_sites").size()==1,"one unknown site "+origin);
                    check(!negative.get("complete").getAsBoolean(),"incomplete proof "+origin);
                }
            } finally {
                currentProgram.endTransaction(tx,false);
            }
        }
        println("GA18 REGISTER FLOW PASS: assertions="+assertions+" nop=1 clobber=1 branch=1 rollback=1");
    }
}
