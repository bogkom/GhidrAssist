package ghidrassist.hardware;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/**
 * Source-only consensus for a conditional same-function chip-select sketch.
 * Multiple distinct word literals, or even one unknown-width/value write,
 * invalidate any proposed single word. Never an active bus configuration.
 */
public final class HardwareStaticWordConsensus {
    private HardwareStaticWordConsensus(){}
    public record Observation(String register,boolean candidateWrite,Integer fullWordLiteral){}
    public record Result(Map<String,Integer> singleLiteralCandidates,
                         int conflictedRegisters,int registersWithUnknownWrites) {
        public Result {
            singleLiteralCandidates=Collections.unmodifiableMap(
                new LinkedHashMap<>(singleLiteralCandidates));
        }
        public String description(){
            return "single-static-literal register candidates="+
                singleLiteralCandidates.size()+"; conflicting register literals="+
                conflictedRegisters+"; registers with unknown writes="+
                registersWithUnknownWrites+"; source order is NOT execution order";
        }
    }
    private static final class Entry {
        Integer value;
        boolean seen,unknown,conflict;
    }
    public static Result inspect(List<Observation> observations){
        if(observations==null)throw new IllegalArgumentException("Missing word evidence");
        Map<String,Entry> entries=new LinkedHashMap<>();
        for(Observation site:observations){
            if(site==null || site.register()==null || site.register().isBlank())
                throw new IllegalArgumentException("Invalid register candidate");
            if(!site.candidateWrite())continue;
            Entry entry=entries.computeIfAbsent(site.register(),k->new Entry());
            entry.seen=true;
            Integer value=site.fullWordLiteral();
            if(value==null || value<0 || value>0xffff){
                entry.unknown=true;
                continue;
            }
            if(entry.value!=null && !entry.value.equals(value))
                entry.conflict=true;
            else if(entry.value==null)entry.value=value;
        }
        Map<String,Integer> accepted=new LinkedHashMap<>();
        int conflicts=0,unknowns=0;
        for(Map.Entry<String,Entry> kv:entries.entrySet()){
            Entry e=kv.getValue();
            if(e.conflict)conflicts++;
            if(e.unknown)unknowns++;
            if(e.seen && !e.unknown && !e.conflict && e.value!=null)
                accepted.put(kv.getKey(),e.value);
        }
        return new Result(accepted,conflicts,unknowns);
    }
}
