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
    private final AutomationDecompiler decompiler=new AutomationDecompiler();

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
                boolean writable = program != null && program.getDomainFile() != null &&
                    program.getDomainFile().canSave();
                result.addProperty("program_writable", writable);
                result.addProperty("program_read_only", program == null ||
                    program.getDomainFile() == null || program.getDomainFile().isReadOnly());
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
                } else if ("decompiler.start".equals(method)) {
                    if(program==null) throw new IllegalStateException("No active program");
                    var viewer=plugin.getTool().getService(ghidra.app.services.CodeViewerService.class);
                    ProgramLocation location=viewer==null ? null : viewer.getCurrentLocation();
                    var function=location==null || location.getAddress()==null ? null :
                        program.getFunctionManager().getFunctionContaining(location.getAddress());
                    result.add("decompiler",decompiler.start(program,function));
                } else if ("decompiler.status".equals(method)) {
                    int offset=args.has("offset") ? args.get("offset").getAsInt() : 0;
                    int limit=args.has("limit") ? args.get("limit").getAsInt() : 4096;
                    result.add("decompiler",decompiler.status(offset,limit));
                } else if ("analysis.paths".equals(method)) {
                    if (program == null) throw new IllegalStateException("No active program");
                    String origin = args.has("origin") ? args.get("origin").getAsString() : "reset";
                    String entry = args.has("entry") ? args.get("entry").getAsString() : "";
                    int depth = args.has("max_depth") ? args.get("max_depth").getAsInt() : 8;
                    int offset = args.has("offset") ? args.get("offset").getAsInt() : 0;
                    int limit = args.has("limit") ? args.get("limit").getAsInt() : 50;
                    result.add("paths", AutomationCallPaths.query(program, origin, entry, depth, offset, limit));
                } else if ("analysis.bundle".equals(method)) {
                    if(program==null) throw new IllegalStateException("No active program");
                    var viewer=plugin.getTool().getService(ghidra.app.services.CodeViewerService.class);
                    ProgramLocation location=viewer==null ? null : viewer.getCurrentLocation();
                    var function=location==null || location.getAddress()==null ? null :
                        program.getFunctionManager().getFunctionContaining(location.getAddress());
                    if(function==null) throw new IllegalStateException("No function at Listing location");
                    JsonObject bundle=new JsonObject();
                    bundle.addProperty("entry",function.getEntryPoint().toString());
                    bundle.addProperty("name",function.getName());
                    bundle.addProperty("body_addresses",function.getBody().getNumAddresses());
                    bundle.addProperty("revision",program.getModificationNumber());
                    com.google.gson.JsonArray incoming=new com.google.gson.JsonArray();
                    int incomingCount=0;
                    for(var ref:program.getReferenceManager().getReferencesTo(function.getEntryPoint())) {
                        if(incomingCount<100) {
                            JsonObject row=new JsonObject();
                            row.addProperty("from",ref.getFromAddress().toString());
                            row.addProperty("type",ref.getReferenceType().toString());
                            incoming.add(row);
                        }
                        incomingCount++;
                    }
                    bundle.add("incoming_entry_xrefs",incoming);
                    bundle.addProperty("incoming_total",incomingCount);
                    com.google.gson.JsonArray mmio=new com.google.gson.JsonArray();
                    int scanned=0;
                    int candidates=0;
                    var instructions=program.getListing().getInstructions(function.getBody(),true);
                    while(instructions.hasNext() && scanned<4096) {
                        var instruction=instructions.next();
                        scanned++;
                        for(var ref:instruction.getReferencesFrom()) {
                            long address=ref.getToAddress().getOffset();
                            if(Long.compareUnsigned(address,0xFFF000L)<0 ||
                               Long.compareUnsigned(address,0xFFFFFFL)>0) continue;
                            candidates++;
                            if(mmio.size()>=100)continue;
                            JsonObject row=new JsonObject();
                            row.addProperty("site",instruction.getAddress().toString());
                            row.addProperty("target",ref.getToAddress().toString());
                            row.addProperty("kind",ref.getReferenceType().toString());
                            row.addProperty("write_candidate",ref.getReferenceType().isWrite());
                            mmio.add(row);
                        }
                    }
                    bundle.add("mmio_reference_candidates",mmio);
                    bundle.addProperty("mmio_candidates_total_scanned",candidates);
                    bundle.addProperty("instructions_scanned",scanned);
                    bundle.addProperty("instruction_scan_truncated",instructions.hasNext());
                    bundle.addProperty("evidence","Static Ghidra references only; no runtime access or physical mapping confirmed");
                    bundle.add("decompiler",decompiler.start(program,function));
                    result.add("analysis",bundle);
                } else if ("function.snapshot".equals(method)) {
                    var viewer=plugin.getTool().getService(ghidra.app.services.CodeViewerService.class);
                    ProgramLocation activeLocation=viewer==null ? null : viewer.getCurrentLocation();
                    var function=activeLocation==null || activeLocation.getAddress()==null
                        ? null : program.getFunctionManager().getFunctionContaining(activeLocation.getAddress());
                    if(function==null) throw new IllegalStateException("No active function");
                    JsonObject info=new JsonObject();
                    info.addProperty("name",function.getName());
                    info.addProperty("entry",function.getEntryPoint().toString());
                    info.addProperty("body_addresses",function.getBody().getNumAddresses());
                    result.add("function",info);
                } else if ("function.xrefs".equals(method)) {
                    var viewer=plugin.getTool().getService(ghidra.app.services.CodeViewerService.class);
                    ProgramLocation activeLocation=viewer==null ? null : viewer.getCurrentLocation();
                    var function=activeLocation==null || activeLocation.getAddress()==null
                        ? null : program.getFunctionManager().getFunctionContaining(activeLocation.getAddress());
                    if(function==null) throw new IllegalStateException("No active function");
                    int offset=args.has("offset") ? args.get("offset").getAsInt() : 0;
                    int limit=args.has("limit") ? args.get("limit").getAsInt() : 100;
                    if(offset<0 || limit<1 || limit>200)
                        throw new IllegalArgumentException("Invalid XREF pagination");
                    com.google.gson.JsonArray refs=new com.google.gson.JsonArray();
                    int total=0;
                    var iterator=program.getReferenceManager().getReferencesTo(function.getEntryPoint());
                    for(var ref:iterator) {
                        if(total>=offset && total-offset<limit) {
                            JsonObject row=new JsonObject();
                            row.addProperty("from",ref.getFromAddress().toString());
                            row.addProperty("to",ref.getToAddress().toString());
                            row.addProperty("type",ref.getReferenceType().toString());
                            refs.add(row);
                        }
                        total++;
                    }
                    JsonObject xrefs=new JsonObject();
                    xrefs.addProperty("entry",function.getEntryPoint().toString());
                    xrefs.addProperty("total",total);
                    xrefs.addProperty("offset",offset);
                    xrefs.addProperty("limit",limit);
                    xrefs.add("rows",refs);
                    result.add("xrefs",xrefs);
                } else if ("hardware.apply.prepare".equals(method) ||
                           "hardware.apply.commit".equals(method) ||
                           "hardware.apply.undo".equals(method)) {
                    GhidrAssistProvider provider=plugin.getAutomationProvider();
                    if(provider==null)throw new IllegalStateException("GhidrAssist UI unavailable");
                    if("hardware.apply.prepare".equals(method)) {
                        int index=args.get("index").getAsInt();
                        result.add("approval",provider.getUI().automationApplyPrepare(index));
                    } else if("hardware.apply.commit".equals(method)) {
                        result.add("apply",provider.getUI().automationApplyCommit(
                            args.get("token").getAsString(),args.get("name").getAsString()));
                    } else {
                        result.add("undo",provider.getUI().automationApplyUndo());
                    }
                } else if ("ui.tab.select".equals(method)) {
                    GhidrAssistProvider provider=plugin.getAutomationProvider();
                    if(provider==null) throw new IllegalStateException("GhidrAssist UI unavailable");
                    if(!args.has("tab")) throw new IllegalArgumentException("Tab required");
                    result.add("ui",provider.getUI().automationSelectTab(args.get("tab").getAsString()));
                } else if ("ui.table.select".equals(method)) {
                    GhidrAssistProvider provider=plugin.getAutomationProvider();
                    if(provider==null) throw new IllegalStateException("GhidrAssist UI unavailable");
                    if(!args.has("table") || !args.has("row"))
                        throw new IllegalArgumentException("Table and row required");
                    result.add("selection",provider.getUI().automationSelectTableRow(
                        args.get("table").getAsString(),args.get("row").getAsInt()));
                } else if ("hardware.cancel".equals(method)) {
                    GhidrAssistProvider provider=plugin.getAutomationProvider();
                    if(provider==null) throw new IllegalStateException("GhidrAssist UI unavailable");
                    result.add("cancel",provider.getUI().automationCancel());
                } else if ("analysis.report".equals(method) || "analysis.export".equals(method)) {
                    GhidrAssistProvider provider=plugin.getAutomationProvider();
                    if(provider==null) throw new IllegalStateException("GhidrAssist UI unavailable");
                    String format=args.has("format") ? args.get("format").getAsString() : "markdown";
                    int offset=args.has("offset") ? args.get("offset").getAsInt() : 0;
                    int limit=args.has("limit") ? args.get("limit").getAsInt() : 4096;
                    // Export is a paginated transfer to the authenticated client,
                    // never arbitrary server-side writes to files or the project.
                    result.add("report",provider.getUI().automationReport(format,offset,limit));
                } else if ("hardware.profile.select".equals(method)) {
                    GhidrAssistProvider provider = plugin.getAutomationProvider();
                    if (provider == null) throw new IllegalStateException("GhidrAssist UI unavailable");
                    String profile = args.get("profile").getAsString();
                    provider.getUI().automationSelectProfile(profile);
                    result.add("ui", provider.getUI().automationSnapshot());
                } else if ("hardware.task".equals(method) || "hardware.mmio.rows".equals(method) || "hardware.review.preview".equals(method)) {
                    GhidrAssistProvider provider = plugin.getAutomationProvider();
                    if (provider == null) throw new IllegalStateException("GhidrAssist UI unavailable");
                    if ("hardware.task".equals(method)) {
                        result.add("task",provider.getUI().automationTask());
                    } else if ("hardware.review.preview".equals(method)) {
                        int offset = args.has("offset") ? args.get("offset").getAsInt() : 0;
                        int limit = args.has("limit") ? args.get("limit").getAsInt() : 50;
                        result.add("review",provider.getUI().automationReviewPreview(offset,limit));
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

    @Override public void close() { decompiler.close(); server.stop(0); }
}
