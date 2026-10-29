import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.apiprovider.*;
import ghidrassist.apiprovider.factory.*;
import javax.swing.*;
import java.awt.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import okhttp3.*;
import okio.Buffer;

/** Offline serialization audit through an actual visible PluginTool/TabController. */
public final class ResponsesGuiAuditMain {
    static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();
    static class Manager extends DefaultProjectManager { Manager() { super(); } }
    static class WindowTool extends PluginTool {
        WindowTool(Project p) { super(p,"Responses offline GUI audit",false,false,false); }
        void shutdown() { super.dispose(); }
    }
    static Object field(Object owner,String name)throws Exception {
        Class<?> c=owner.getClass();while(c!=null) {try{Field f=c.getDeclaredField(name);f.setAccessible(true);return f.get(owner);}catch(NoSuchFieldException e){c=c.getSuperclass();}}
        throw new NoSuchFieldException(name);
    }
    static void set(Object owner,String name,Object value)throws Exception {
        Field f=owner.getClass().getDeclaredField(name);f.setAccessible(true);f.set(owner,value);
    }
    static JsonElement clean(JsonElement v) {
        if(v.isJsonObject()){JsonObject o=new JsonObject();for(var e:v.getAsJsonObject().entrySet())if(!List.of("id","session_id","account_id","call_id","correlation_id","request_id").contains(e.getKey()))o.add(e.getKey(),clean(e.getValue()));return o;}
        if(v.isJsonArray()){JsonArray a=new JsonArray();for(JsonElement x:v.getAsJsonArray())a.add(clean(x));return a;}
        if(v.isJsonPrimitive()&&v.getAsJsonPrimitive().isString())return new JsonPrimitive(v.getAsString().replaceAll("(?i)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}","[REDACTED_ID]").replaceAll("(?i)(session(?:[_ -]?id)?(?:\\s*[:=]\\s*|\\s+))[0-9]+","$1[REDACTED]"));
        return v.deepCopy();
    }
    public static void main(String[] args)throws Exception {
        JsonObject env=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        JsonObject state=env.getAsJsonObject("environments").getAsJsonObject("installed");
        Path output=Path.of(args[2]);
        var app=new GhidraApplicationConfiguration();app.setShowSplashScreen(false);
        app.setApplicationLogFile(Path.of(state.get("base").getAsString(),"offline-gui.private.log").toFile());
        Application.initializeApplication(new GhidraApplicationLayout(Path.of(env.get("ghidra").getAsString()).toFile()),app);
        APIProviderConfig cfg=JSON.fromJson(Files.readString(Path.of(args[1])),APIProviderConfig.class);
        // The capture interceptor terminates before network; no real credential is loaded here.
        cfg.setKey("{\"access_token\":\"OFFLINE_TEST_ONLY\",\"expires_at\":9999999999999}");
        ghidra.framework.preferences.Preferences.setProperty("GhidrAssist.APIProviders",JSON.toJson(List.of(cfg)));
        ghidra.framework.preferences.Preferences.setProperty("GhidrAssist.SelectedAPIProvider",cfg.getName());
        ghidra.framework.preferences.Preferences.setProperty("GhidrAssist.LuceneIndexPath",env.get("index").getAsString());
        ghidra.framework.preferences.Preferences.setProperty("GhidrAssist.RAGLibraries.v1",Files.readString(Path.of(env.get("catalog").getAsString())));
        JsonObject result=new JsonObject();CountDownLatch captured=new CountDownLatch(1);
        APIProviderFactory original=ProviderRegistry.getInstance().getFactory(APIProvider.ProviderType.OPENAI_OAUTH);
        ProviderRegistry.getInstance().registerFactory(new APIProviderFactory(){
            public APIProvider createProvider(APIProviderConfig c)throws UnsupportedProviderException {
                APIProvider p=original.createProvider(c);
                try {Field f=APIProvider.class.getDeclaredField("client");f.setAccessible(true);OkHttpClient client=(OkHttpClient)f.get(p);
                    f.set(p,client.newBuilder().addInterceptor(chain->{
                        JsonObject request=new JsonObject();request.addProperty("method",chain.request().method());
                        request.addProperty("endpoint",chain.request().url().scheme()+"://"+chain.request().url().host()+chain.request().url().encodedPath());
                        JsonObject headers=new JsonObject();for(String h:List.of("Content-Type","accept","originator","OpenAI-Beta"))if(chain.request().header(h)!=null)headers.addProperty(h,chain.request().header(h));request.add("headers",headers);
                        Buffer buffer=new Buffer();chain.request().body().writeTo(buffer);request.add("payload",clean(JsonParser.parseString(buffer.readUtf8())));
                        result.add("request",request);captured.countDown();throw new java.io.IOException("OFFLINE_CAPTURE_NO_NETWORK");
                    }).build());
                }catch(ReflectiveOperationException e){throw new RuntimeException(e);}return p;
            }
            public boolean supports(APIProvider.ProviderType t){return t==getProviderType();}
            public APIProvider.ProviderType getProviderType(){return APIProvider.ProviderType.OPENAI_OAUTH;}
            public String getFactoryName(){return "PassiveOfflineAudit";}
        });
        Manager manager=new Manager();Project project=manager.openProject(new ProjectLocator(state.get("project").getAsString(),env.get("project_name").getAsString()),false,false);AppInfo.setActiveProject(project);
        Object consumer=new Object();Program program=(Program)project.getProjectData().getFile("/"+env.get("program").getAsString()).getDomainObject(consumer,false,false,TaskMonitor.DUMMY);
        WindowTool[] tool=new WindowTool[1];Object[] controller=new Object[1];
        try {
            SwingUtilities.invokeAndWait(()->{try{
                tool[0]=new WindowTool(project);tool[0].addPlugin("ghidra.app.plugin.core.progmgr.ProgramManagerPlugin");tool[0].addPlugin("ghidrassist.GhidrAssistPlugin");tool[0].getService(ProgramManager.class).openProgram(program);tool[0].setVisible(true);
                GhidrAssistPlugin plugin=(GhidrAssistPlugin)tool[0].getManagedPlugins().stream().filter(p->p instanceof GhidrAssistPlugin).findFirst().orElseThrow();
                Object ui=field(field(plugin,"provider"),"ui");controller[0]=field(ui,"controller");
                controller[0].getClass().getMethod("setReasoningEffort",String.class).invoke(controller[0],"high");set(controller[0],"pendingAgentUseMCP",false);
                Method execute=java.util.Arrays.stream(controller[0].getClass().getDeclaredMethods()).filter(m->m.getName().equals("executeApprovedAgenticQuery")).findFirst().orElseThrow();execute.setAccessible(true);
                Object[] params=execute.getParameterCount()==4?new Object[]{"Call ga_get_document_page with filename MC68332UM.pdf page 256 scope all offset 0 max_chars 600.","Use returned tool evidence.","offline-audit","1. Read the requested page."}:new Object[]{"Call ga_get_document_page with filename MC68332UM.pdf page 256 scope all offset 0 max_chars 600.","Use returned tool evidence.","offline-audit","1. Read the requested page.",null};
                execute.invoke(controller[0],params);result.addProperty("edt",SwingUtilities.isEventDispatchThread());result.addProperty("window_showing",tool[0].getToolFrame().isShowing());
            }catch(Exception e){throw new RuntimeException(e);}});
            if(!captured.await(40,TimeUnit.SECONDS))throw new AssertionError("GUI request not captured");
            JsonObject classes=new JsonObject();
            for(String name:List.of("ghidrassist.GhidrAssistPlugin","ghidrassist.agent.react.ReActOrchestrator","ghidrassist.apiprovider.OpenAIOAuthProvider","ghidrassist.apiprovider.APIProvider","ghidrassist.tools.registry.ToolRegistry","ghidrassistmcp.GhidrAssistMCPApplicationPlugin","ghidrassistmcp.tools.GetCodeTool")){
                Class<?> c=Class.forName(name,false,ResponsesGuiAuditMain.class.getClassLoader());JsonObject item=new JsonObject();item.addProperty("code_source",c.getProtectionDomain().getCodeSource().getLocation().toString());
                try(var stream=c.getResourceAsStream("/"+name.replace('.','/')+".class")){item.addProperty("class_sha256",java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(stream.readAllBytes())));}classes.add(name,item);
            }
            result.add("resolved_classes",classes);result.addProperty("offline_no_network",true);result.addProperty("application_headless",app.isHeadless());result.addProperty("awt_headless",GraphicsEnvironment.isHeadless());
            Files.writeString(output,JSON.toJson(result)+"\n");
        } finally { SwingUtilities.invokeAndWait(()->{if(tool[0]!=null)tool[0].shutdown();});program.release(consumer);project.close(); }
        System.exit(0);
    }
}
