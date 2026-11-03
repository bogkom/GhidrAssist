// @category GhidrAssist.Tests
// Real Ghidra synthetic CPU32 fixture; never loads private firmware.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import com.google.gson.JsonObject;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class GA18VerifyListingRangeAndBodyXrefs extends GhidraScript {
    private int assertions;
    private void check(boolean ok, String message) {
        assertions++;
        if(!ok)throw new IllegalStateException("GA18 LISTING RANGE/XREF FAIL: "+message);
    }
    private void denied(Method method, Object... args) throws Exception {
        try {
            method.invoke(null,args);
        } catch(InvocationTargetException fail) {
            Throwable cause=fail.getCause();
            check(cause instanceof IllegalArgumentException ||
                cause instanceof IllegalStateException,
                "invalid request rejected: "+cause.getMessage());
            return;
        }
        check(false,"invalid request was unexpectedly accepted");
    }
    @Override protected void run() throws Exception {
        if(currentProgram==null || !"synthetic-callgraph.bin".equals(currentProgram.getName()))
            throw new IllegalStateException("Synthetic callgraph fixture only");
        String jar=System.getProperty("ga18.test.jar","");
        if(jar.isBlank())throw new IllegalStateException("Missing product jar");
        var start=currentProgram.getAddressFactory().getAddress("00000100");
        var callee=currentProgram.getAddressFactory().getAddress("00000130");
        ProgramLocation position=new ProgramLocation(currentProgram,start);
        Function caller=currentProgram.getFunctionManager().getFunctionContaining(start);
        Function target=currentProgram.getFunctionManager().getFunctionContaining(callee);
        check(caller!=null && target!=null,"fixture functions exist");
        long revision=currentProgram.getModificationNumber();
        try(URLClassLoader loader=new URLClassLoader(
                new URL[]{Path.of(jar).toUri().toURL()},getClass().getClassLoader())) {
            Class<?> listing=Class.forName("ghidrassist.automation.AutomationListing",true,loader);
            Method range=listing.getMethod("range",Program.class,ProgramLocation.class,
                String.class,int.class,int.class,Long.class);
            JsonObject first=(JsonObject)range.invoke(null,currentProgram,position,
                "00000100",0,1,Long.valueOf(revision));
            check(first.get("returned").getAsInt()==1,"one Listing row");
            check(first.get("has_more").getAsBoolean(),"Listing has next row");
            check(first.get("revision").getAsLong()==revision,"Listing revision receipt");
            check("JSR".equalsIgnoreCase(first.getAsJsonArray("rows").get(0)
                .getAsJsonObject().get("mnemonic").getAsString()),"JSR first");
            JsonObject second=(JsonObject)range.invoke(null,currentProgram,position,
                "00000100",1,1,Long.valueOf(revision));
            check(second.get("returned").getAsInt()==1,"next decoded instruction");
            check("00000106".equalsIgnoreCase(second.getAsJsonArray("rows").get(0)
                .getAsJsonObject().get("instruction_address").getAsString()),"RTS at 0x106");
            check(second.get("next_offset").getAsInt()==2,"next offset advances");
            denied(range,currentProgram,position,"00000100",0,65,null);
            denied(range,currentProgram,position,"00000100",0,1,Long.valueOf(revision+1));
            denied(range,currentProgram,position,"garbled-address",0,1,null);

            Class<?> xrefs=Class.forName("ghidrassist.automation.AutomationFunctionXrefs",true,loader);
            Method body=xrefs.getMethod("body",Program.class,Function.class,String.class,
                int.class,int.class,Long.class,String.class);
            JsonObject outgoing=(JsonObject)body.invoke(null,currentProgram,caller,
                "outgoing",0,100,Long.valueOf(revision),caller.getEntryPoint().toString());
            check(outgoing.get("returned").getAsInt()>=1,"outgoing reference");
            check(outgoing.get("revision").getAsLong()==revision,"XREF revision receipt");
            boolean call=false;
            for(var element:outgoing.getAsJsonArray("rows")) {
                var row=element.getAsJsonObject();
                if(row.get("from").getAsString().equalsIgnoreCase("00000100") &&
                        row.get("to").getAsString().equalsIgnoreCase("00000130")) call=true;
            }
            check(call,"caller body references callee");
            JsonObject incoming=(JsonObject)body.invoke(null,currentProgram,target,
                "incoming",0,100,Long.valueOf(revision),target.getEntryPoint().toString());
            boolean called=false;
            for(var element:incoming.getAsJsonArray("rows")) {
                var row=element.getAsJsonObject();
                if(row.get("from").getAsString().equalsIgnoreCase("00000100") &&
                        row.get("to").getAsString().equalsIgnoreCase("00000130") &&
                        !row.get("source_in_body").getAsBoolean()) called=true;
            }
            check(called,"incoming call outside callee body");
            JsonObject page=(JsonObject)body.invoke(null,currentProgram,target,
                "incoming",0,1,Long.valueOf(revision),target.getEntryPoint().toString());
            check(page.get("returned").getAsInt()==1,"incoming paging");
            denied(body,currentProgram,target,"incorrect",0,1,null,"");
            denied(body,currentProgram,target,"incoming",0,101,null,"");
            denied(body,currentProgram,target,"incoming",0,1,Long.valueOf(revision+1),"");
            denied(body,currentProgram,target,"incoming",0,1,null,"00000220");
        }
        println("GA18 LISTING RANGE BODY XREF PASS: assertions="+assertions+
            " (real Ghidra CPU32 synthetic read-only)");
    }
}
