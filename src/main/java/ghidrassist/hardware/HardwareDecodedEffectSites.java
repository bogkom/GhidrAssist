package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Independent, bounded source inventory of Ghidra-decoded instruction sites.
 * Decoded STORE is a p-code memory write; MOVEC/VBR requires a VBR destination
 * register operand. Neither establishes runtime execution or active VBR.
 */
public final class HardwareDecodedEffectSites {
    private HardwareDecodedEffectSites() {}
    public record Decoded(long functionEntry, long instructionPc,
            boolean pcodeMemoryStore, boolean movecToVbr) {
        public Decoded {
            if(functionEntry<0 || functionEntry>0xffffffffL ||
                    instructionPc<functionEntry || instructionPc>0xffffffffL ||
                    (functionEntry&1)!=0 || (instructionPc&1)!=0)
                throw new IllegalArgumentException("Invalid decoded instruction coordinate");
        }
    }
    public record Result(List<HardwareResetEffectSites.Site> sites,
            boolean incomplete, int omitted, int inspected) {
        public Result {
            if(sites==null || sites.size()>HardwareResetEffectSites.MAX_SITES ||
                    omitted<0 || inspected<0 || omitted>inspected*2L)
                throw new IllegalArgumentException("Invalid decoded site inventory");
            sites=List.copyOf(sites);
        }
        /** A bounded join is allowed only when all decoded source evidence is present. */
        public HardwareResetEffectSites.Report correlate(
                HardwareResetHandlerWitness.Report witness,
                List<HardwareCallEffects.FunctionNode> functions) {
            if(incomplete || omitted!=0)
                throw new IllegalStateException("Incomplete decoded instruction inventory");
            return HardwareResetEffectSites.correlate(witness,functions,sites);
        }
    }
    public static Result collect(List<Decoded> decoded, boolean sourceIncomplete) {
        if(decoded==null)throw new IllegalArgumentException("Missing decoded source");
        // Canonicalize before applying the cap: input traversal order must not
        // decide which evidence survives a bounded, incomplete inventory.
        List<HardwareResetEffectSites.Site> candidates=new ArrayList<>();
        Set<Long> coordinates=new HashSet<>();
        for(Decoded d:decoded) {
            if(d==null || !coordinates.add(d.instructionPc()))
                throw new IllegalArgumentException("Null/duplicate decoded instruction PC");
            if(d.pcodeMemoryStore())
                candidates.add(new HardwareResetEffectSites.Site(d.functionEntry(),
                    d.instructionPc(),HardwareResetEffectSites.Kind.MEMORY_STORE));
            if(d.movecToVbr())
                candidates.add(new HardwareResetEffectSites.Site(d.functionEntry(),
                    d.instructionPc(),HardwareResetEffectSites.Kind.MOVEC_VBR));
        }
        candidates.sort(Comparator.comparingLong((HardwareResetEffectSites.Site site)->site.functionEntry())
                .thenComparingLong(HardwareResetEffectSites.Site::instructionPc)
                .thenComparing(HardwareResetEffectSites.Site::kind));
        int retained=Math.min(candidates.size(),HardwareResetEffectSites.MAX_SITES);
        int omitted=candidates.size()-retained;
        List<HardwareResetEffectSites.Site> out=new ArrayList<>(candidates.subList(0,retained));
        return new Result(out,sourceIncomplete || omitted>0,omitted,decoded.size());
    }
}
