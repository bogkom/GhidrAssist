package ghidrassist.hardware;

import ghidra.program.model.listing.Program;
import java.util.Locale;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.regex.Pattern;

/**
 * Process-local cache keyed by the exact Ghidra Program identity.
 *
 * It stores only evidence derived from a user-initiated local analysis.
 * Nothing is uploaded or indexed automatically. The text is an explicit
 * snapshot that must be refreshed after project reanalysis or program edits.
 */
public final class HardwareEvidenceCache {
    private HardwareEvidenceCache(){}
    private static final Map<Program,String> CACHE=new WeakHashMap<>();
    private static final Pattern HARDWARE_WORDS=Pattern.compile(
        "(?iu)(hardware|sprz[eę]t|procesor|mcu|cpu32|mc683|simcr|csbar|csor|cspar|"+
        "chip.?select|vbr|tram(?:bar|mcr)|tpuram|qsm|tpu|pami[eę]c|memory.map|mapa.pami[eę]ci|"+
        "rejestr|register|adresowanie|addressing|firmware.init|boot|can.controller)");
    public static void publish(Program program,String report){
        if(program==null||report==null||report.isBlank())return;
        synchronized(CACHE){CACHE.put(program,report);}
    }
    public static void clear(Program program){
        if(program==null)return;
        synchronized(CACHE){CACHE.remove(program);}
    }
    public static boolean hasEvidence(Program program){
        synchronized(CACHE){return program!=null&&CACHE.containsKey(program);}
    }
    /** Automatically use a small sourced excerpt only for relevant queries. */
    public static String enrich(Program program,String request){
        if(request==null)return "";
        boolean requested=request.toLowerCase(Locale.ROOT).contains("#hardware");
        String cleaned=request.replaceAll("(?i)#hardware\\b","");
        if(!requested && !HARDWARE_WORDS.matcher(request).find())return request;
        if(program==null)return cleaned;
        String markdown;
        synchronized(CACHE){markdown=CACHE.get(program);}
        if(markdown==null)
            return requested ?
                "[Hardware Analysis was not run for this program. Do not infer results.]\n"+
                cleaned : cleaned;
        String selected=HardwareContextSelector.select(markdown,request,9000);
        return selected.isBlank()?cleaned:selected+"\n"+cleaned;
    }
}
