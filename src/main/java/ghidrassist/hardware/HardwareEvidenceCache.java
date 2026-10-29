package ghidrassist.hardware;

import ghidra.program.model.listing.Program;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.regex.Pattern;

/**
 * Process-local evidence keyed by the current Ghidra program revision.
 *
 * Never return a report after an edit, undo/redo, language/source change,
 * or program switch. Values do not reference Program, preserving weak keys.
 * This is no persistent checkpoint and performs no Ghidra database writes.
 */
public final class HardwareEvidenceCache {
    private HardwareEvidenceCache(){}

    private record Cached(String markdown,long modificationNumber,String language,
                          String sourceSha256,String algorithm) {}
    private static final Map<Program,Cached> CACHE=new WeakHashMap<>();
    private static final Pattern HARDWARE_WORDS=Pattern.compile(
        "(?iu)(hardware|sprz[eę]t|procesor|mcu|cpu32|mc683|simcr|csbar|csor|cspar|"+
        "chip.?select|vbr|tram(?:bar|mcr)|tpuram|qsm|tpu|pami[eę]c|memory.map|mapa.pami[eę]ci|"+
        "rejestr|register|adresowanie|addressing|firmware.init|boot|can.controller)");

    private static Cached current(Program program) {
        if(program==null)return null;
        synchronized(CACHE) {
            Cached cached=CACHE.get(program);
            if(cached==null)return null;
            if(program.getModificationNumber()!=cached.modificationNumber ||
                    !program.getLanguageID().toString().equals(cached.language) ||
                    !Objects.equals(program.getExecutableSHA256(),cached.sourceSha256) ||
                    !HardwareAnalysisRevision.ALGORITHM.equals(cached.algorithm)) {
                CACHE.remove(program);
                return null;
            }
            return cached;
        }
    }

    /**
     * Compatibility method for intentional full-report producers.
     * The report is tied to the current revision; direct scan callers should
     * prefer publishIfCurrent to prevent publishing a stale async result.
     */
    public static void publish(Program program,String report) {
        if(program==null||report==null||report.isBlank())return;
        long rev=program.getModificationNumber();
        String language=program.getLanguageID().toString();
        String sha=program.getExecutableSHA256();
        synchronized(CACHE) {
            if(program.getModificationNumber()==rev)
                CACHE.put(program,new Cached(report,rev,language,sha,
                    HardwareAnalysisRevision.ALGORITHM));
        }
    }

    /** Fail closed if the asynchronous scan started on an earlier revision. */
    public static boolean publishIfCurrent(Program program,String report,
            HardwareAnalysisRevision started) {
        if(program==null || started==null || report==null || report.isBlank())
            return false;
        synchronized(CACHE) {
            if(!started.matches(program,program.getModificationNumber(),
                    program.getLanguageID().toString(),
                    program.getExecutableSHA256(),started.mc68332Selected()))
                return false;
            CACHE.put(program,new Cached(report,started.modificationNumber(),
                started.language(),started.sourceSha256(),
                HardwareAnalysisRevision.ALGORITHM));
            if(current(program)==null)return false;
            return true;
        }
    }

    public static void clear(Program program){
        if(program==null)return;
        synchronized(CACHE){CACHE.remove(program);}
    }

    public static boolean hasEvidence(Program program) {
        return current(program)!=null;
    }

    /** Automatically use a small sourced excerpt only for relevant queries. */
    public static String enrich(Program program,String request){
        return enrich(program,request,request);
    }

    /**
     * Judge relevance against the original user's words, not an earlier RAG
     * snippet that may contain unrelated hardware terminology.
     */
    public static String enrich(Program program,String request,String userIntent){
        if(request==null)return "";
        String intent=userIntent==null?"":userIntent;
        boolean requested=intent.toLowerCase(Locale.ROOT).contains("#hardware");
        String cleaned=request.replaceAll("(?i)#hardware\\b","");
        if(!requested && intent.toLowerCase(Locale.ROOT).contains("#func"))
            return HardwareBitMath.annotate(cleaned);
        if(!requested && !HARDWARE_WORDS.matcher(intent).find())return request;
        if(program==null)return cleaned;
        Cached snapshot=current(program);
        if(snapshot==null)return requested ?
            "[Hardware Analysis evidence unavailable or stale for this program revision. "+
            "Rerun Analyze; no hardware result inferred.]\n"+cleaned : cleaned;
        String selected=HardwareContextSelector.select(snapshot.markdown,intent,9000);
        // Modifications can occur while extracting text on another thread.
        // Recheck the snapshot before handing it to AI/RAG.
        if(current(program)!=snapshot) return requested ?
            "[Hardware Analysis changed during query preparation. "+
            "Rerun Analyze; no stale evidence forwarded.]\n"+cleaned : cleaned;
        return selected.isBlank()?cleaned:HardwareBitMath.annotate(selected+"\n"+cleaned);
    }
}
