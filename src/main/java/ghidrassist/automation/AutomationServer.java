package ghidrassist.automation;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.GhidrAssistProvider;
import ghidra.app.services.GoToService;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Explicitly enabled, process-local Automation API. Disabled in ordinary Ghidra.
 * Every Swing operation executes on the EDT; requests never execute arbitrary code.
 */
public final class AutomationServer implements AutoCloseable {
    private static final Gson JSON = new Gson();
    private final HttpServer server;
    private final GhidrAssistPlugin plugin;

    private AutomationServer(GhidrAssistPlugin plugin, HttpServer server) {
        this.plugin = plugin;
        this.server = server;
    }

    public static AutomationServer start(GhidrAssistPlugin plugin) throws IOException {
        if (!Boolean.getBoolean("ghidrassist.automation.enabled")) return null;
        String token = System.getenv().getOrDefault("GHIDRASSIST_AUTOMATION_TOKEN", "");
        if (token.length() < 32) throw new IOException("Automation requires a session token of at least 32 characters");
        int port = Integer.getInteger("ghidrassist.automation.port", 0);
        if (port < 0 || port > 65535) throw new IOException("Invalid Automation port");
        HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 8);
        AutomationServer service = new AutomationServer(plugin, http);
        http.createContext("/rpc", service::handle);
        http.setExecutor(Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "GhidrAssist-automation-rpc");
            t.setDaemon(true);
            return t;
        }));
        http.start();
        String status = System.getProperty("ghidrassist.automation.ready", "");
        if (!status.isBlank()) {
            try {
                Path target = Path.of(status);
                Files.writeString(target, JSON.toJson(new Ready(3, http.getAddress().getPort(), ProcessHandle.current().pid())),
                        StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
            } catch (Exception error) {
                http.stop(0);
                throw new IOException("Could not publish Automation ready receipt", error);
            }
        }
        return service;
    }

    private record Ready(int schema, int port, long pid) {}

    private void handle(HttpExchange exchange) throws IOException {
        byte[] response;
        int code = 200;
        try {
            if (!"POST".equals(exchange.getRequestMethod())) throw new IllegalArgumentException("POST required");
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            String token = System.getenv().getOrDefault("GHIDRASSIST_AUTOMATION_TOKEN", "");
            if (!("Bearer " + token).equals(authorization)) {
                code = 401;
                throw new IllegalArgumentException("Unauthorized");
            }
            if (exchange.getRequestBody().available() > 65536) throw new IllegalArgumentException("Request too large");
            byte[] raw = exchange.getRequestBody().readNBytes(65537);
            if (raw.length > 65536) throw new IllegalArgumentException("Request too large");
            JsonObject request = JsonParser.parseString(new String(raw, StandardCharsets.UTF_8)).getAsJsonObject();
            JsonObject answer = dispatch(request);
            response = JSON.toJson(answer).getBytes(StandardCharsets.UTF_8);
        } catch (Exception error) {
            if (code == 200) code = 400;
            JsonObject problem = new JsonObject();
            problem.addProperty("error", error.getMessage() == null ? "Automation request failed" : error.getMessage());
            response = JSON.toJson(problem).getBytes(StandardCharsets.UTF_8);
        }
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(code, response.length);
        try (var output = exchange.getResponseBody()) { output.write(response); }
    }

    private JsonObject dispatch(JsonObject request) throws Exception {
        String method = request.get("method").getAsString();
        JsonObject args = request.has("params") ? request.getAsJsonObject("params") : new JsonObject();
        AtomicReference<JsonObject> answer = new AtomicReference<>();
        AtomicReference<Exception> failure = new AtomicReference<>();
        Runnable operation = () -> {
            try {
                JsonObject result = new JsonObject();
                result.addProperty("schema", 3);
                Program program = plugin.getCurrentProgram();
                result.addProperty("program", program == null ? "" : program.getName());
                if ("session.status".equals(method)) {
                    result.addProperty("status", "READY");
                } else if ("listing.snapshot".equals(method)) {
                    ProgramLocation loc = plugin.getTool().getService(ghidra.app.services.CodeViewerService.class) == null
                        ? null : plugin.getTool().getService(ghidra.app.services.CodeViewerService.class).getCurrentLocation();
                    result.addProperty("address", loc == null || loc.getAddress() == null ? "" : loc.getAddress().toString());
                } else if ("listing.goto".equals(method)) {
                    if (program == null) throw new IllegalStateException("No active program");
                    String address = args.get("address").getAsString();
                    var target = program.getAddressFactory().getAddress(address);
                    if (target == null || !program.getMemory().contains(target)) throw new IllegalArgumentException("Invalid program address");
                    GoToService go = plugin.getTool().getService(GoToService.class);
                    if (go == null || !go.goTo(target, program)) throw new IllegalStateException("Listing navigation unavailable");
                    result.addProperty("requested_address", target.toString());
                } else if ("hardware.task".equals(method) || "hardware.mmio.rows".equals(method)) {
                    GhidrAssistProvider provider = plugin.getAutomationProvider();
                    if (provider == null) throw new IllegalStateException("GhidrAssist UI unavailable");
                    if ("hardware.task".equals(method)) {
                        result.add("task",provider.getUI().automationTask());
                    } else {
                        String filter = args.has("filter") ? args.get("filter").getAsString() : "";
                        int offset = args.has("offset") ? args.get("offset").getAsInt() : 0;
                        int limit = args.has("limit") ? args.get("limit").getAsInt() : 100;
                        result.add("table",provider.getUI().automationMmioRows(filter,offset,limit));
                    }
                } else if ("ui.snapshot".equals(method) || "hardware.analyze".equals(method)) {
                    GhidrAssistProvider provider = plugin.getAutomationProvider();
                    if (provider == null) throw new IllegalStateException("GhidrAssist UI unavailable");
                    if ("hardware.analyze".equals(method)) provider.getUI().automationAnalyze();
                    result.add("ui", provider.getUI().automationSnapshot());
                } else throw new IllegalArgumentException("Unknown method: " + method);
                answer.set(result);
            } catch (Exception error) { failure.set(error); }
        };
        if (SwingUtilities.isEventDispatchThread()) operation.run();
        else SwingUtilities.invokeAndWait(operation);
        if (failure.get() != null) throw failure.get();
        return answer.get();
    }

    @Override public void close() { server.stop(0); }
}
