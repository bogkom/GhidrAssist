package ghidrassist.automation;

import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.agent.react.AgenticReviewProgramBinding;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.regex.Pattern;

/**
 * GA-12/13/15: explicit, local, restricted sidecar creation through authenticated
 * Automation API v3. Never writes a Program, inherits Review/Apply approval,
 * or accepts arbitrary host paths from an agent.
 */
public final class AutomationAgenticBinding {
    private AutomationAgenticBinding(){}
    private static final Pattern BASENAME=Pattern.compile(
        "[A-Za-z0-9][A-Za-z0-9_.-]{0,94}\\.json");
    private static String string(JsonObject args,String key,int max){
        if(!args.has(key)||!args.get(key).isJsonPrimitive()||
                !args.get(key).getAsJsonPrimitive().isString())
            throw new IllegalArgumentException("Missing string: "+key);
        String value=args.get(key).getAsString();
        if(value.isBlank()||value.length()>max)
            throw new IllegalArgumentException("Invalid string: "+key);
        return value;
    }
    private static String basename(JsonObject args,String key) {
        String value=string(args,key,100);
        if(value.startsWith(".") || value.contains("..") ||
                !BASENAME.matcher(value).matches())
            throw new IllegalArgumentException("Unsafe binding filename: "+key);
        return value;
    }
    /**
     * A JSON number MUST be an exact, canonical decimal integer. Gson's
     * getAsLong() truncates fractions and accepts quoted numbers, and may
     * silently overflow a 64-bit value. Never authorize a stale artifact
     * using these coercions.
     */
    static long exactRevision(JsonObject args){
        if(!args.has("expected_program_revision") ||
                !args.get("expected_program_revision").isJsonPrimitive() ||
                !args.get("expected_program_revision")
                    .getAsJsonPrimitive().isNumber())
            throw new IllegalArgumentException(
                "Expected revision must be an unquoted integer");
        String raw=args.get("expected_program_revision").getAsString();
        if(!raw.matches("(0|[1-9][0-9]{0,18})"))
            throw new IllegalArgumentException(
                "Expected revision must be a canonical nonnegative integer");
        try {
            return Long.parseLong(raw);
        }catch(NumberFormatException invalid){
            throw new IllegalArgumentException("Expected revision out of range",invalid);
        }
    }
    static String exactSourceSha(JsonObject args){
        String sha=string(args,"expected_import_sha256",64);
        if(!sha.matches("[A-Fa-f0-9]{64}"))
            throw new IllegalArgumentException(
                "Expected import SHA must have exactly 64 hexadecimal digits");
        return sha;
    }
    static void validateExpectedIdentity(JsonObject args,long revision,
            String importedSha,String programPath){
        // No ambiguous extra request fields (including alternative paths or
        // supposedly pre-approved plans). This is a closed security contract.
        java.util.Set<String> allowed=java.util.Set.of(
            "confirm_local_sidecar","expected_program_revision",
            "expected_import_sha256","expected_program_path","profile",
            "objective","source_file","output_file");
        for(String key:args.keySet())
            if(!allowed.contains(key))
                throw new IllegalArgumentException("Unknown binding field: "+key);
        if(exactRevision(args)!=revision ||
                importedSha==null ||
                !exactSourceSha(args).equalsIgnoreCase(importedSha) ||
                !string(args,"expected_program_path",256).equals(programPath))
            throw new IllegalStateException(
                "Program revision/import identity changed");
    }
    private static boolean profile(JsonObject args) {
        String value=string(args,"profile",32);
        if("CPU32_SURVEY".equals(value))return false;
        if("MC68332_USER_SELECTED".equals(value))return true;
        throw new IllegalArgumentException("Explicit CPU32/MC68332 profile required");
    }
    public static JsonObject create(
            GhidrAssistPlugin plugin,Program program,JsonObject args)throws Exception {
        // Sidecar creation is NOT enabled by the authenticated bearer token.
        if(!Boolean.getBoolean("ghidrassist.automation.agenticBindingCreate"))
            throw new IllegalStateException("Agentic binding creation not enabled");
        if(program==null||plugin.getCurrentProgram()!=program ||
                program.getDomainFile()==null)
            throw new IllegalStateException("Active Program unavailable or switched");
        // Never permit production files. Only an explicitly opted-in
        // synthetic fixture or an independently attested isolated copy.
        if(Boolean.getBoolean("ghidrassist.automation.syntheticWrites"))
            AutomationWritePolicy.requireSyntheticSafe(program);
        else
            AutomationWritePolicy.requireReviewCopy(
                program,plugin.getTool().getProject());
        if(!args.has("confirm_local_sidecar") ||
                !args.get("confirm_local_sidecar").isJsonPrimitive() ||
                !args.get("confirm_local_sidecar").getAsJsonPrimitive().isBoolean() ||
                !args.get("confirm_local_sidecar").getAsBoolean())
            throw new IllegalArgumentException("Explicit local sidecar confirmation required");
        long revision=program.getModificationNumber();
        validateExpectedIdentity(args,revision,
            program.getExecutableSHA256(),program.getDomainFile().getPathname());
        boolean mc68332=profile(args);
        String objective=string(args,"objective",512);
        if(objective.length()<8)
            throw new IllegalArgumentException("New independent objective required");
        String sourceName=basename(args,"source_file");
        String destinationName=basename(args,"output_file");
        if(sourceName.equals(destinationName))
            throw new IllegalArgumentException("Source and destination must differ");
        String configured=System.getProperty(
            "ghidrassist.automation.agenticBindingDir","");
        if(configured.isBlank())
            throw new IllegalStateException("No operator-scoped binding directory");
        Path dir=Path.of(configured).toAbsolutePath().normalize();
        if(Files.isSymbolicLink(dir) ||
                !Files.isDirectory(dir,LinkOption.NOFOLLOW_LINKS))
            throw new IllegalStateException("Binding directory unavailable/unsafe");
        Path source=dir.resolve(sourceName);
        Path destination=dir.resolve(destinationName);
        if(Files.isSymbolicLink(source) ||
                !Files.isRegularFile(source,LinkOption.NOFOLLOW_LINKS) ||
                Files.exists(destination,LinkOption.NOFOLLOW_LINKS))
            throw new IllegalArgumentException("Source missing or destination already exists");
        AgenticReviewProgramBinding.save(
            source,destination,program,objective,mc68332,TaskMonitor.DUMMY,
            ()->plugin.getCurrentProgram()==program &&
                program.getModificationNumber()==revision &&
                Boolean.getBoolean("ghidrassist.automation.agenticBindingCreate"));
        if(plugin.getCurrentProgram()!=program ||
                program.getModificationNumber()!=revision)
            throw new IllegalStateException(
                "Program switched during binding; new file remains unapproved");
        JsonObject reply=new JsonObject();
        reply.addProperty("created",true);
        reply.addProperty("schema",1);
        reply.addProperty("file_name",destinationName);
        reply.addProperty("profile",mc68332?
            "MC68332_USER_SELECTED":"CPU32_SURVEY");
        reply.addProperty("read_only_evidence",true);
        reply.addProperty("new_review_approved",false);
        reply.addProperty("resumable_ai_session",false);
        reply.addProperty("tool_execution_authorized",false);
        reply.addProperty("apply_authorized",false);
        reply.addProperty("old_plan_inherited",false);
        reply.addProperty("program_revision",revision);
        reply.addProperty("notice",
            "Sidecar created in operator-scoped directory; NEW Review and approval required");
        return reply;
    }
}
