package ghidrassist.agent.react;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidrassist.hardware.HardwareDurableStageStore;
import ghidrassist.hardware.HardwareGhidraInputFingerprint;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;

/**
 * GA-12/13/15: optional, read-only, restart-stable binding of an untrusted
 * historical Agentic checkpoint to the exact Ghidra Program/Listing state.
 * It does NOT preserve model sessions, tool policy, an approved plan or Apply.
 *
 * The original import SHA is insufficient: CodeBrowser may have edited
 * bytes, Listing, functions, references or names since the checkpoint.
 * The GA-12 full-input fingerprint and project identity are required.
 *
 * A SHA-256 digest detects accidental edits, NOT a malicious author with
 * filesystem write access. This binding is deliberately not a Review token.
 */
public final class AgenticReviewProgramBinding {
    private AgenticReviewProgramBinding() {}
    private static final int MAX_BINDING=4096;
    private static final int MAX_CHECKPOINT=8*1024*1024;
    private static final Gson JSON=new GsonBuilder().disableHtmlEscaping().create();
    private static final String KIND="ghidrassist-agentic-review-program-binding";

    private static byte[] bounded(Path file,int max)throws IOException {
        if(file==null || Files.isSymbolicLink(file))
            throw new IOException("Missing or linked review source");
        try(InputStream in=Files.newInputStream(file,LinkOption.NOFOLLOW_LINKS)){
            byte[] content=in.readNBytes(max+1);
            if(content.length==0 || content.length>max)
                throw new IOException("Missing or oversized review binding/checkpoint");
            return content;
        }
    }
    private static String readString(JsonObject o,String name,int max) {
        if(!o.has(name) || !o.get(name).isJsonPrimitive() ||
                !o.get(name).getAsJsonPrimitive().isString())
            throw new IllegalArgumentException("Missing binding string: "+name);
        String value=o.get(name).getAsString();
        if(value.isEmpty() || value.length()>max)
            throw new IllegalArgumentException("Invalid binding string: "+name);
        return value;
    }
    private static void requireFalse(JsonObject o,String name){
        if(!o.has(name) || !o.get(name).isJsonPrimitive() ||
                !o.get(name).getAsJsonPrimitive().isBoolean() ||
                o.get(name).getAsBoolean())
            throw new IllegalArgumentException("Binding cannot authorize: "+name);
    }
    private static void identity(JsonObject data,
            HardwareDurableStageStore.Key key){
        data.addProperty("project_id_sha256",key.programIdSha256());
        data.addProperty("import_sha256",key.importedSha256());
        data.addProperty("full_input_sha256",key.inputSha256());
        data.addProperty("analyzer_sha256",key.analyzerSha256());
        data.addProperty("language",key.language());
        data.addProperty("mc68332",key.mc68332());
    }
    private static void matches(JsonObject data,
            HardwareDurableStageStore.Key key) {
        if(!readString(data,"project_id_sha256",64).equals(key.programIdSha256()) ||
                !readString(data,"import_sha256",64).equals(key.importedSha256()) ||
                !readString(data,"full_input_sha256",64).equals(key.inputSha256()) ||
                !readString(data,"analyzer_sha256",64).equals(key.analyzerSha256()) ||
                !readString(data,"language",128).equals(key.language()) ||
                !data.has("mc68332") || !data.get("mc68332").isJsonPrimitive() ||
                !data.get("mc68332").getAsJsonPrimitive().isBoolean() ||
                data.get("mc68332").getAsBoolean()!=key.mc68332())
            throw new IllegalArgumentException("Review Program/Listing fingerprint changed");
    }
    private static String canonical(JsonObject object) {
        // This exact controlled-field payload is built in fixed key order.
        // On loading, use the same order to prevent JSON property ordering
        // from creating a new integrity identity.
        return JSON.toJson(object);
    }
    private static JsonObject fields(JsonObject in) {
        JsonObject out=new JsonObject();
        for(String name:new String[]{"schema","kind","objective",
                "checkpoint_bytes_sha256","project_id_sha256",
                "import_sha256","full_input_sha256","analyzer_sha256",
                "language","mc68332","new_review_approved",
                "tool_execution_authorized","apply_authorized",
                "resumable_ai_session","old_plan_inherited"}) {
            if(!in.has(name))throw new IllegalArgumentException(
                "Missing review binding field: "+name);
            out.add(name,in.get(name).deepCopy());
        }
        if(in.size()!=out.size())
            throw new IllegalArgumentException("Unknown review binding fields");
        return out;
    }
    public static void save(Path checkpoint,Path binding,Program program,
            String objective,boolean mc68332,TaskMonitor monitor)
            throws IOException,CancelledException {
        if(program==null || binding==null || monitor==null ||
                objective==null || objective.length()<8 || objective.length()>512)
            throw new IllegalArgumentException("Missing review context/objective");
        // Full preflight of original retained evidence and import SHA. This
        // neither requests any old approval nor starts an Agentic session.
        AgenticReviewDraft.loadSavedCheckpoint(checkpoint,program,objective);
        var key=HardwareGhidraInputFingerprint.capture(
            program,monitor,mc68332).orElseThrow(()->
                new IllegalArgumentException("Unverifiable full Ghidra Program input"));
        byte[] source=bounded(checkpoint,MAX_CHECKPOINT);
        JsonObject data=new JsonObject();
        data.addProperty("schema",1);
        data.addProperty("kind",KIND);
        data.addProperty("objective",objective);
        data.addProperty("checkpoint_bytes_sha256",HardwareDurableStageStore.hash(source));
        identity(data,key);
        for(String name:new String[]{"new_review_approved",
                "tool_execution_authorized","apply_authorized",
                "resumable_ai_session","old_plan_inherited"})
            data.addProperty(name,false);
        JsonObject envelope=new JsonObject();
        envelope.add("payload",data);
        envelope.addProperty("payload_sha256",
            HardwareDurableStageStore.hash(canonical(data)));
        byte[] serialized=(JSON.toJson(envelope)+"\n").getBytes(StandardCharsets.UTF_8);
        if(serialized.length>MAX_BINDING)
            throw new IOException("Oversized review binding");
        Path parent=binding.toAbsolutePath().getParent();
        if(parent==null || Files.isSymbolicLink(parent) ||
                !Files.isDirectory(parent,LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Review binding directory missing/unsafe");
        Path temp=Files.createTempFile(parent,".ga-review-binding-",".tmp");
        try {
            try{Files.setPosixFilePermissions(temp,EnumSet.of(
                PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE));}
            catch(UnsupportedOperationException ignored){}
            Files.write(temp,serialized,StandardOpenOption.TRUNCATE_EXISTING);
            // File creation is exclusive; a stale binding is never replaced.
            Files.createLink(binding,temp);
        }finally{Files.deleteIfExists(temp);}
    }
    public static AgenticReviewDraft load(Path checkpoint,Path binding,
            Program program,boolean mc68332,TaskMonitor monitor)
            throws IOException,CancelledException {
        if(program==null || monitor==null)
            throw new IllegalArgumentException("No active Program for review");
        var before=HardwareGhidraInputFingerprint.capture(
            program,monitor,mc68332).orElseThrow(()->
                new IllegalArgumentException("Unverifiable Program fingerprint"));
        JsonObject envelope=JsonParser.parseString(new String(
            bounded(binding,MAX_BINDING),StandardCharsets.UTF_8)).getAsJsonObject();
        JsonObject raw=envelope.getAsJsonObject("payload");
        if(raw==null)throw new IllegalArgumentException("Missing review binding payload");
        JsonObject data=fields(raw);
        if(!data.has("schema") ||
                !data.get("schema").isJsonPrimitive() ||
                !data.get("schema").getAsJsonPrimitive().isNumber() ||
                !"1".equals(data.get("schema").getAsString()) ||
                !KIND.equals(readString(data,"kind",80)) ||
                !readString(envelope,"payload_sha256",64).equals(
                    HardwareDurableStageStore.hash(canonical(data))))
            throw new IllegalArgumentException("Tampered review binding");
        for(String name:new String[]{"new_review_approved",
                "tool_execution_authorized","apply_authorized",
                "resumable_ai_session","old_plan_inherited"})
            requireFalse(data,name);
        matches(data,before);
        byte[] source=bounded(checkpoint,MAX_CHECKPOINT);
        if(!HardwareDurableStageStore.hash(source).equals(
                readString(data,"checkpoint_bytes_sha256",64)))
            throw new IllegalArgumentException("Historical review source changed");
        String objective=readString(data,"objective",512);
        AgenticReviewDraft draft=AgenticReviewDraft.loadSavedCheckpoint(
            checkpoint,program,objective);
        var after=HardwareGhidraInputFingerprint.capture(
            program,monitor,mc68332).orElseThrow(()->
                new IllegalArgumentException("Program changed during Review import"));
        if(!before.equals(after))
            throw new IllegalArgumentException("Program changed during Review import");
        return draft;
    }
}
