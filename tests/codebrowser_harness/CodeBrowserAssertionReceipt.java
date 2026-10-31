// GA-18 test-only in-process CodeBrowser API + unmodified X11 Robot PNG receipt.
// This is self-reported synthetic evidence, NOT trusted native GUI acceptance.
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class CodeBrowserAssertionReceipt {
    private static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Pattern XID = Pattern.compile(
        "^\\s*(0x[0-9a-fA-F]+)\\s+\"([^\"]+)\".*$");
    private CodeBrowserAssertionReceipt(){}
    private static void check(boolean ok,String explanation){
        if(!ok)throw new AssertionError("CodeBrowser receipt: "+explanation);
    }
    private static String cmd(String... command)throws Exception {
        Process process=new ProcessBuilder(command).redirectErrorStream(true).start();
        boolean finished=process.waitFor(12,TimeUnit.SECONDS);
        if(!finished){process.destroyForcibly();throw new AssertionError("X11 inspection timeout");}
        byte[] bytes=process.getInputStream().readNBytes(128*1024);
        check(process.exitValue()==0 && bytes.length<128*1024,
            "X11 inspector failed: "+String.join(" ",command));
        return new String(bytes,java.nio.charset.StandardCharsets.UTF_8);
    }
    static String[] x11(Frame frame)throws Exception {
        // Window ID comes from the live X server, NOT from an invented Java
        // Swing handle, report field, or synthetic title alone.
        String tree=cmd("xwininfo","-root","-tree");
        String xid=null;
        for(String line:tree.split("\\R")){
            Matcher m=XID.matcher(line);
            if(m.matches() && m.group(2).equals(frame.getTitle())){
                check(xid==null,"duplicate X11 windows sharing full frame title");
                xid=String.format(Locale.ROOT,"0x%08x",
                    Long.parseUnsignedLong(m.group(1).substring(2),16));
            }
        }
        check(xid!=null,"live X11 CodeBrowser window not found by exact title");
        String props=cmd("xprop","-id",xid,"WM_CLASS","WM_NAME","_NET_WM_NAME");
        String clazz=null,title=null;
        for(String line:props.split("\\R")){
            int equal=line.indexOf(" = ");
            if(equal<0)continue;
            String value=line.substring(equal+3).trim();
            if(line.startsWith("WM_CLASS(")){
                Matcher pair=Pattern.compile("\"([^\"]+)\"\\s*,\\s*\"([^\"]+)\"")
                    .matcher(value);
                check(pair.find(),"X11 WM_CLASS is not a two-component class");
                clazz=pair.group(1)+"."+pair.group(2);
            }else if(line.startsWith("_NET_WM_NAME(") || line.startsWith("WM_NAME(")){
                if(value.startsWith("\"") && value.endsWith("\""))
                    title=value.substring(1,value.length()-1);
            }
        }
        check(clazz!=null && !clazz.isBlank(),"no real X11 WM_CLASS");
        check(frame.getTitle().equals(title),"X11 full title differs from Swing frame title");
        check(frame.getTitle().contains("CodeBrowser"),
            "CodeBrowser window identity not explicit");
        return new String[]{xid,clazz,title};
    }
    private static Object field(Object owner,String name)throws Exception {
        for(Class<?> k=owner.getClass();k!=null;k=k.getSuperclass()){
            try {
                Field f=k.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(owner);
            }catch(NoSuchFieldException ignored){}
        }
        throw new NoSuchFieldException(name);
    }
    private static Object connectedDecompiler(GhidraTool tool)throws Exception {
        Object plugin=tool.getManagedPlugins().stream()
            .filter(p->p.getClass().getSimpleName().equals("DecompilePlugin"))
            .findFirst().orElseThrow(()->new AssertionError(
                "real DecompilePlugin was not installed"));
        Object provider=field(plugin,"connectedProvider");
        check(provider!=null,"real connected DecompilerProvider missing");
        return provider;
    }
    private static void displayDecompiler(GhidraTool tool)throws Exception {
        Object provider=connectedDecompiler(tool);
        check(provider instanceof docking.ComponentProvider,
            "Ghidra provider is not a real dockable Decompiler");
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            tool.showComponentProvider((docking.ComponentProvider)provider,true);
            tool.toFront((docking.ComponentProvider)provider);
        });
    }
    private static Function shownDecompilerFunction(GhidraTool tool)throws Exception {
        Object provider=connectedDecompiler(tool);
        // Invoke actual DecompilerProvider accessor, never infer it from
        // Listing cursor, title, or a hard-coded fixture address.
        Object controller=provider.getClass().getMethod("getController").invoke(provider);
        check(controller!=null,"connected DecompilerController missing");
        Method getFunction=controller.getClass().getMethod("getFunction");
        Object function=getFunction.invoke(controller);
        return function instanceof Function f?f:null;
    }
    record State(String program,String address,String function,
                         String decompilerFunction,long observedMs){}
    static State observe(GhidraTool tool,Program expected,Address address)
            throws Exception {
        ProgramManager pm=tool.getService(ProgramManager.class);
        CodeViewerService view=tool.getService(CodeViewerService.class);
        check(pm!=null && view!=null,"real active ProgramManager/CodeViewerService missing");
        Program active=pm.getCurrentProgram();
        ProgramLocation location=view.getCurrentLocation();
        check(active==expected,"active program mismatch");
        check(location!=null && location.getProgram()==expected &&
            location.getAddress()!=null,"Listing location has wrong Program");
        Function fn=active.getFunctionManager()
            .getFunctionContaining(location.getAddress());
        Function decomp=shownDecompilerFunction(tool);
        check(fn!=null,"Listing Function missing from actual FunctionManager");
        check(decomp!=null,"Decompiler Function missing from actual DecompilerController");
        check(fn.getProgram()==expected && decomp.getProgram()==expected,
            "Listing/Decompiler function refers to another Program");
        check(location.getAddress().equals(address) &&
            fn.getEntryPoint().equals(address) &&
            decomp.getEntryPoint().equals(fn.getEntryPoint()),
            "stale Listing/Decompiler function or address");
        return new State(active.getName(),String.format(Locale.ROOT,
            "0x%08X",location.getAddress().getOffset()),
            fn.getName(),decomp.getName(),System.currentTimeMillis());
    }
    private static void state(JsonObject output,String name,State state){
        JsonObject value=new JsonObject();
        value.addProperty("program",state.program);
        value.addProperty("address",state.address);
        value.addProperty("function",state.function);
        value.addProperty("decompiler_function",state.decompilerFunction);
        value.addProperty("observed_epoch_ms",state.observedMs);
        output.add(name,value);
    }
    static JsonObject capture(GhidraTool tool,Program expected,Address address,
            Path out,String runId,String caseId)throws Exception {
        return capture(tool,expected,address,out,runId,caseId,0);
    }

    private static boolean privateFile(Path p)throws Exception {
        if(Files.isSymbolicLink(p) ||
           !Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS))return false;
        Set<PosixFilePermission> perm=Files.getPosixFilePermissions(p);
        return !perm.contains(PosixFilePermission.GROUP_READ) &&
            !perm.contains(PosixFilePermission.GROUP_WRITE) &&
            !perm.contains(PosixFilePermission.GROUP_EXECUTE) &&
            !perm.contains(PosixFilePermission.OTHERS_READ) &&
            !perm.contains(PosixFilePermission.OTHERS_WRITE) &&
            !perm.contains(PosixFilePermission.OTHERS_EXECUTE);
    }

    private static void externalCapture(Path out,String runId,String caseId,
            String[] xid,State before,int seconds)throws Exception {
        check(runId.matches("[a-f0-9]{32}"),"external run ID must be 32 hex");
        check(caseId.equals("synthetic-codebrowser-001"),"wrong external fixture case");
        check(xid[1].equals("CodeBrowserMmioMain.CodeBrowserMmioMain"),
            "unexpected real X11 class for external fixture");
        check(xid[2].equals(
            "GhidrAssist isolated CodeBrowser MMIO: CodeBrowserFixture:/synthetic-mmio.bin"),
            "unexpected live X11 full window title");
        Path ready=out.resolve("capture-ready.json");
        JsonObject signal=new JsonObject();
        signal.addProperty("schema",1);
        signal.addProperty("action","GA18_X11_READY");
        signal.addProperty("case_id",caseId);
        signal.addProperty("run_id",runId);
        signal.addProperty("window_id",xid[0]);
        signal.addProperty("window_class",xid[1]);
        signal.addProperty("window_title",xid[2]);
        signal.addProperty("program",before.program);
        signal.addProperty("address",before.address);
        signal.addProperty("function",before.function);
        signal.addProperty("decompiler_function",before.decompilerFunction);
        signal.addProperty("pre_capture_epoch_ms",before.observedMs);
        Files.writeString(ready,JSON.toJson(signal),
            java.nio.file.StandardOpenOption.CREATE_NEW);
        Files.setPosixFilePermissions(ready,Set.of(
            PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE));
        // No GUI input, no arbitrary commands, no scanning other windows.
        // Supervisor's host-owned capture has to write the exact
        // pilot-x11-RUN/bridge-capture.json and original PNG.
        Path bridge=out.getParent().resolve("pilot-x11-"+runId);
        Path report=bridge.resolve("bridge-capture.json");
        Path png=bridge.resolve("ghidra-window.png");
        long deadline=System.nanoTime()+seconds*1_000_000_000L;
        boolean done=false;
        while(System.nanoTime()<deadline) {
            if(Files.exists(report,LinkOption.NOFOLLOW_LINKS)) {
                check(privateFile(report) && privateFile(png),
                    "host capture report/PNG must be private regular files");
                check(Files.size(report)<128*1024 && Files.size(png)<64L*1024*1024,
                    "host capture exceeds bounded evidence sizes");
                JsonObject obj=JsonParser.parseString(Files.readString(report))
                    .getAsJsonObject();
                check(obj.get("applied").getAsBoolean() &&
                    obj.get("result").getAsString().equals(
                      "HOST_SYNTHETIC_X11_CAPTURED_PROVENANCE_PENDING") &&
                    obj.get("run_id").getAsString().equals(runId) &&
                    obj.get("case_id").getAsString().equals(caseId) &&
                    obj.get("window_id").getAsString().equals(xid[0]) &&
                    obj.get("wm_class").getAsString().equals(xid[1]) &&
                    obj.get("window_title").getAsString().equals(xid[2]) &&
                    obj.get("identity_before_after_capture").getAsBoolean(),
                    "host bridge capture did not match same XID/run/title");
                long hostStart=obj.get("capture_start_epoch_ms").getAsLong();
                long hostEnd=obj.get("capture_end_epoch_ms").getAsLong();
                check(before.observedMs<=hostStart && hostStart<=hostEnd &&
                    hostEnd<=System.currentTimeMillis() && hostEnd-hostStart<=60000,
                    "host capture timestamps not inside pre/post interval");
                byte[] bytes=Files.readAllBytes(png);
                String hash=HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(bytes));
                check(hash.equals(obj.get("captured_screenshot_sha256")
                    .getAsString()),"host X11 PNG digest does not match bridge report");
                for(String flag:new String[]{"formal_gui_pass","supervisor_ack",
                        "native_nonce_ack","visual_readback_verified",
                        "trusted_ghidra_provenance_verified"}) {
                    check(obj.get(flag)!=null && !obj.get(flag).getAsBoolean(),
                        "unearned host GUI PASS flag: "+flag);
                }
                done=true;
                break;
            }
            Thread.sleep(100);
        }
        check(done,"bounded external host X11 capture timeout");
    }

    static JsonObject capture(GhidraTool tool,Program expected,Address address,
            Path out,String runId,String caseId,int externalWaitSeconds)throws Exception {
        check(runId!=null && runId.matches("[a-zA-Z0-9_-]{12,64}"),
            "invalid test run ID");
        check(caseId!=null && caseId.matches("[a-zA-Z0-9_-]{6,64}"),
            "invalid synthetic test case ID");
        Frame frame=tool.getToolFrame();
        check(frame!=null && frame.isShowing(),"actual CodeBrowser frame not displayed");
        // Make the actual Ghidra Decompiler component visible, not merely
        // a loaded plugin whose provider has never been shown/decompiled.
        displayDecompiler(tool);
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            tool.getService(ghidra.app.services.GoToService.class)
                .goTo(address,expected);
        });
        // Wait for the real asynchronous DecompilePlugin location update.
        long deadline=System.nanoTime()+20_000_000_000L;
        State before=null;
        String lastFailure="NO_OBSERVATION";
        while(System.nanoTime()<deadline) {
            try {before=observe(tool,expected,address);break;}
            catch(AssertionError | ReflectiveOperationException e){
                lastFailure=e.getClass().getSimpleName()+": "+e.getMessage();
                Thread.sleep(100);
            }
        }
        check(before!=null,"real Listing/Decompiler failed to converge; last="+lastFailure);
        String[] winBefore=x11(frame);
        if(externalWaitSeconds>0){
            check(externalWaitSeconds>=5 && externalWaitSeconds<=180,
                "external capture deadline must be 5..180 seconds");
            externalCapture(out,runId,caseId,winBefore,before,
                externalWaitSeconds);
        }
        Rectangle bounds=frame.getBounds().intersection(
            frame.getGraphicsConfiguration().getBounds());
        check(bounds.width>=640 && bounds.height>=400 && bounds.width<=8192 &&
            bounds.height<=8192,"actual CodeBrowser capture out of bounds");
        Robot robot=new Robot(frame.getGraphicsConfiguration().getDevice());
        robot.waitForIdle();
        // No printAll, no composited mock: actual X11 screen pixels, same run.
        long captureStart=System.currentTimeMillis();
        BufferedImage pixels=robot.createScreenCapture(bounds);
        long captureEnd=System.currentTimeMillis();
        check(pixels!=null && pixels.getWidth()==bounds.width &&
            pixels.getHeight()==bounds.height,"Robot dimensions differ");
        Path screenshot=out.resolve("ghidra-window.png");
        check(ImageIO.write(pixels,"png",screenshot.toFile()),
            "real screenshot PNG encoding unavailable");
        byte[] raw=Files.readAllBytes(screenshot);
        check(raw.length>4096 && ImageIO.read(screenshot.toFile())!=null,
            "real X11 PNG missing/corrupt");
        String digest=HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(raw));
        String[] winAfter=x11(frame);
        State after=observe(tool,expected,address);
        check(before.program.equals(after.program) &&
            before.address.equals(after.address) &&
            before.function.equals(after.function) &&
            before.decompilerFunction.equals(after.decompilerFunction),
            "Ghidra active state changed during screenshot");
        check(winBefore[0].equals(winAfter[0]) &&
            winBefore[1].equals(winAfter[1]) &&
            winBefore[2].equals(winAfter[2]),
            "X11 window ID/class/title changed during screenshot");
        check(before.observedMs<=captureStart && captureStart<=captureEnd &&
            captureEnd<=after.observedMs,
            "in-process observation timestamp order invalid");
        // Compatibility image is a byte-identical copy of the original,
        // not a resized/transformed capture.
        Files.copy(screenshot,out.resolve("codebrowser-x11.png"));
        JsonObject receipt=new JsonObject();
        receipt.addProperty("schema",1);
        receipt.addProperty("kind","ga18-codebrowser-listing-assertions");
        receipt.addProperty("case_id",caseId);
        receipt.addProperty("run_id",runId);
        receipt.addProperty("source_kind","ghidra-inprocess-codebrowser");
        receipt.addProperty("window_id",winBefore[0]);
        receipt.addProperty("window_class",winBefore[1]);
        receipt.addProperty("window_title",winBefore[2]);
        receipt.addProperty("program",before.program);
        receipt.addProperty("address",before.address);
        receipt.addProperty("function",before.function);
        receipt.addProperty("decompiler_function",before.decompilerFunction);
        receipt.addProperty("listing_verified",true);
        receipt.addProperty("decompiler_verified",true);
        receipt.addProperty("image_sha256",digest);
        receipt.addProperty("image_width",bounds.width);
        receipt.addProperty("image_height",bounds.height);
        receipt.addProperty("pre_capture_epoch_ms",before.observedMs);
        receipt.addProperty("capture_start_epoch_ms",captureStart);
        receipt.addProperty("capture_end_epoch_ms",captureEnd);
        receipt.addProperty("post_capture_epoch_ms",after.observedMs);
        state(receipt,"pre_capture",before);
        state(receipt,"post_capture",after);
        receipt.addProperty("inprocess_consistency_verified",true);
        receipt.addProperty("trusted_ghidra_provenance_verified",false);
        receipt.addProperty("same_run_semantics_verified",false);
        receipt.addProperty("independent_visual_readback",false);
        receipt.addProperty("visual_readback_verified",false);
        receipt.addProperty("supervisor_ack",false);
        receipt.addProperty("native_nonce_ack",false);
        receipt.addProperty("formal_gui_pass",false);
        Files.writeString(out.resolve("codebrowser-assertions.json"),
            JSON.toJson(receipt));
        return receipt;
    }
}
