import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.awt.Frame;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.Set;

/**
 * Disposable synthetic CodeBrowser hold. The host release is a scheduler
 * signal only, never proof of native CUA, native turn, nonce, ACK or GUI PASS.
 */
final class CodeBrowserCuaHold {
    private static final Gson JSON=new GsonBuilder().setPrettyPrinting().create();
    private static final Set<PosixFilePermission> PRIVATE=Set.of(
        PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE);
    private CodeBrowserCuaHold(){}

    private static void check(boolean ok,String why) {
        if(!ok)throw new AssertionError(why);
    }
    private static String str(JsonObject obj,String name){
        check(obj.has(name)&&obj.get(name).isJsonPrimitive()&&
            obj.get(name).getAsJsonPrimitive().isString(),
            "BLOCKED_CUA_INVALID_HOST_RELEASE");
        return obj.get(name).getAsString();
    }
    private static void writePrivate(Path p,JsonObject json)throws Exception {
        Files.writeString(p,JSON.toJson(json),StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE);
        Files.setPosixFilePermissions(p,PRIVATE);
    }
    private static String[] window(Frame frame,String[] expected)throws Exception {
        String[] actual;
        try {actual=CodeBrowserAssertionReceipt.x11(frame);}
        catch(Throwable failure) {
            throw new AssertionError("BLOCKED_CUA_WINDOW_CHANGED",failure);
        }
        check(java.util.Arrays.equals(actual,expected),"BLOCKED_CUA_WINDOW_CHANGED");
        return actual;
    }
    private static CodeBrowserAssertionReceipt.State state(
            GhidraTool tool,Program program,Address address,
            CodeBrowserAssertionReceipt.State before)throws Exception {
        CodeBrowserAssertionReceipt.State after;
        try {after=CodeBrowserAssertionReceipt.observe(tool,program,address);}
        catch(Throwable problem) {
            throw new AssertionError("BLOCKED_CUA_LISTING_OR_DECOMPILER_CHANGED",problem);
        }
        check(after.program().equals(before.program())&&
            after.address().equals(before.address())&&
            after.function().equals(before.function())&&
            after.decompilerFunction().equals(before.decompilerFunction()),
            "BLOCKED_CUA_LISTING_OR_DECOMPILER_CHANGED");
        return after;
    }
    static void waitForHost(GhidraTool tool,Program program,Address address,
            Path out,JsonObject oldReceipt,String runId,int seconds)throws Exception {
        check(seconds>=5&&seconds<=180,"BLOCKED_CUA_INVALID_TIMEOUT");
        check(runId.matches("[0-9a-f]{32}"),"BLOCKED_CUA_INVALID_RUN_ID");
        Frame frame=tool.getToolFrame();
        check(frame!=null&&frame.isShowing(),"BLOCKED_CUA_MISSING_WINDOW");
        String[] expected=CodeBrowserAssertionReceipt.x11(frame);
        check(expected[0].equals(str(oldReceipt,"window_id"))&&
            expected[1].equals(str(oldReceipt,"window_class"))&&
            expected[2].equals(str(oldReceipt,"window_title")),
            "BLOCKED_CUA_WINDOW_CHANGED");
        check(expected[1].equals("CodeBrowserMmioMain.CodeBrowserMmioMain")&&
            expected[2].equals("GhidrAssist isolated CodeBrowser MMIO: CodeBrowserFixture:/synthetic-mmio.bin"),
            "BLOCKED_CUA_UNEXPECTED_WINDOW");
        CodeBrowserAssertionReceipt.State before=
            CodeBrowserAssertionReceipt.observe(tool,program,address);
        check(before.program().equals("synthetic-mmio.bin")&&
              before.address().equals("0x00000020")&&
              before.function().equals("FUN_00000020")&&
              before.decompilerFunction().equals("FUN_00000020"),
              "BLOCKED_CUA_INVALID_SYNTHETIC_STATE");
        JsonObject ready=new JsonObject();
        ready.addProperty("schema",1);
        ready.addProperty("action","GA18_NATIVE_CUA_LIVE_READY");
        ready.addProperty("run_id",runId);
        ready.addProperty("window_id",expected[0]);
        ready.addProperty("window_class",expected[1]);
        ready.addProperty("window_title",expected[2]);
        ready.addProperty("program",before.program());
        ready.addProperty("address",before.address());
        ready.addProperty("function",before.function());
        ready.addProperty("decompiler_function",before.decompilerFunction());
        ready.addProperty("pre_hold_epoch_ms",before.observedMs());
        ready.addProperty("timeout_seconds",seconds);
        ready.addProperty("native_cua_verified",false);
        ready.addProperty("native_nonce_ack",false);
        ready.addProperty("formal_gui_pass",false);
        Path done=out.resolve("cua-live-result.json");
        JsonObject result=new JsonObject();
        result.addProperty("schema",1);
        result.addProperty("run_id",runId);
        result.addProperty("pre_window_id",expected[0]);
        result.addProperty("native_cua_verified",false);
        result.addProperty("native_nonce_ack",false);
        result.addProperty("supervisor_ack",false);
        result.addProperty("formal_gui_pass",false);
        try{
            writePrivate(out.resolve("cua-live-ready.json"),ready);
            long deadline=System.nanoTime()+seconds*1_000_000_000L;
            Path release=out.resolve("cua-live-release.json");
            boolean released=false;
            while(System.nanoTime()<deadline){
                // Identity and semantic state must hold throughout the live
                // window; a release file is never independent attestation.
                window(frame,expected);
                state(tool,program,address,before);
                if(Files.exists(release,LinkOption.NOFOLLOW_LINKS)){
                    check(!Files.isSymbolicLink(release)&&
                        Files.isRegularFile(release,LinkOption.NOFOLLOW_LINKS)&&
                        Files.getPosixFilePermissions(release).equals(PRIVATE)&&
                        Files.size(release)>0&&Files.size(release)<=4096,
                        "BLOCKED_CUA_UNSAFE_RELEASE");
                    JsonObject response=JsonParser.parseString(
                        Files.readString(release)).getAsJsonObject();
                    check(str(response,"run_id").equals(runId)&&
                        str(response,"window_id").equals(expected[0])&&
                        str(response,"window_class").equals(expected[1])&&
                        str(response,"window_title").equals(expected[2]),
                        "BLOCKED_CUA_WINDOW_CHANGED");
                    String status=str(response,"status");
                    if(status.equals("CUA_UNAVAILABLE"))
                        throw new AssertionError("BLOCKED_NATIVE_CUA_UNAVAILABLE");
                    check(status.equals("WINDOW_OBSERVATION_COMPLETE"),
                        "BLOCKED_CUA_INVALID_HOST_RELEASE");
                    released=true;break;
                }
                Thread.sleep(100);
            }
            check(released,"BLOCKED_NATIVE_CUA_TIMEOUT");
            window(frame,expected);
            CodeBrowserAssertionReceipt.State after=
                state(tool,program,address,before);
            result.addProperty("result","LIVE_CUA_WINDOW_RELEASED_STRUCTURAL_ONLY");
            result.addProperty("post_window_id",expected[0]);
            result.addProperty("program",after.program());
            result.addProperty("address",after.address());
            result.addProperty("function",after.function());
            result.addProperty("decompiler_function",after.decompilerFunction());
            result.addProperty("post_hold_epoch_ms",after.observedMs());
            result.addProperty("source_run_id_reused",false);
            writePrivate(done,result);
        }catch(Exception|AssertionError error){
            result.addProperty("result","BLOCKED");
            result.addProperty("reason",String.valueOf(error.getMessage()));
            writePrivate(done,result);
            throw error;
        }
    }
}
