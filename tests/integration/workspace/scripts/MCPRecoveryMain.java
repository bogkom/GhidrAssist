import com.google.gson.*;
import ghidrassist.mcp2.protocol.MCPClientAdapter;
import ghidrassist.mcp2.server.MCPServerConfig;
import java.nio.file.*;
import java.util.concurrent.*;

/** Narrow actual SDK SSE initialization/retry/restart check; records no protocol identifiers. */
public final class MCPRecoveryMain {
    static void waitFor(Path marker)throws Exception {
        long end=System.nanoTime()+120_000_000_000L;
        while(!Files.exists(marker)){if(System.nanoTime()>end)throw new TimeoutException("control marker");Thread.sleep(50);}
    }
    static JsonObject connected(MCPClientAdapter client)throws Exception {
        long start=System.nanoTime();client.connect().get(35,TimeUnit.SECONDS);
        JsonObject value=new JsonObject();value.addProperty("connected",client.isReady());value.addProperty("tools",client.getDiscoveredTools().size());
        JsonElement response=client.executeTool("get_program_info",new JsonObject()).get(20,TimeUnit.SECONDS);
        value.addProperty("real_tool_response_nonempty",response!=null&&!response.isJsonNull());
        value.addProperty("seconds",(System.nanoTime()-start)/1e9);return value;
    }
    public static void main(String[] args)throws Exception {
        Path controls=Path.of(args[1]);JsonObject result=new JsonObject();
        MCPClientAdapter client=new MCPClientAdapter(new MCPServerConfig("isolated-recovery",args[0],MCPServerConfig.TransportType.SSE));
        try {
            client.connect().get(30,TimeUnit.SECONDS);throw new AssertionError("Unexpected server before startup");
        } catch(ExecutionException|TimeoutException expected) {
            result.addProperty("before_server", "INITIALIZATION_FAILED");
            result.addProperty("before_server_error_class",expected.getClass().getSimpleName());
            try{client.disconnect().get(8,TimeUnit.SECONDS);result.addProperty("failed_client_closed",true);}catch(Exception error){result.addProperty("failed_client_closed",false);}
        }
        Files.writeString(controls.resolve("failed-before-start"),"ready");waitFor(controls.resolve("ready-1"));
        result.add("recovered",connected(client));client.disconnect().get(10,TimeUnit.SECONDS);
        Files.writeString(controls.resolve("ready-to-restart"),"ready");waitFor(controls.resolve("ready-2"));
        result.add("after_restart",connected(client));client.disconnect().get(10,TimeUnit.SECONDS);
        Files.writeString(Path.of(args[2]),new GsonBuilder().setPrettyPrinting().create().toJson(result)+"\n");System.exit(0);
    }
}
