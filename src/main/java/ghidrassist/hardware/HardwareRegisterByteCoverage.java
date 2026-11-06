package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Read-only byte coverage of explicitly selected MCU profile register ranges.
 *
 * A source STORE overlapping a profiled register does not establish that the
 * register was writable, mapped under an active MM state, or changed at runtime.
 * Profile offsets/widths/page labels are metadata, not authenticated manuals.
 * Never use this evidence for Review/Apply/Undo or a completed CFG checkpoint.
 */
public final class HardwareRegisterByteCoverage {
    private HardwareRegisterByteCoverage() {}

    public static final int MAX_STORES=128;
    public static final int MAX_DISPLAY_HITS=256;
    private static final long MASK24=HardwareDataflow.MASK24;

    public record Store(long callPc,long storePc,Long address,int bits) {
        public Store {
            if(callPc<0 || storePc<0 ||
                    address!=null && (address<0 || address>MASK24))
                throw new IllegalArgumentException("Invalid source STORE");
        }
    }
    /** One pair: a static STORE and a register-width interval, not an executed write. */
    public record Hit(long callPc,long storePc,long start,int storeBits,
            long registerBase,String module,String register,int registerBits,
            int coveredBytes,boolean wholeRegister,boolean exactRange,
            String sourcePageLabel) {
        public String coverage() {
            return exactRange ? "EXACT_BYTE_RANGE" :
                wholeRegister ? "SPANNING_WHOLE_REGISTER" : "PARTIAL_REGISTER";
        }
    }
    public record Report(int sampledStores,int unknownAddressOrWidth,
            int noProfiledRegister,int totalHits,int omittedHits,List<Hit> hits) {
        public Report { hits=List.copyOf(hits); }
        private static String hex(long n) {
            return String.format(Locale.ROOT,"0x%06X",n);
        }
        public String markdown(String lane) {
            StringBuilder out=new StringBuilder(
                "### MC68332 register-byte coverage for "+lane+" CALL evidence (GA-02/03/06)\n\n")
                .append("- **PROFILE METADATA / STATIC MAY-ALIAS ONLY**; explicit MC68332 ")
                .append("selection required. MM0 and MM1 are alternatives, not ")
                .append("simultaneously active maps. Bytes covered by a STORE ")
                .append("do NOT establish an accepted hardware write, a complete ")
                .append("register value, correct register width in silicon, ")
                .append("a latched MM bit, executed CALL, or Apply permission.\n")
                .append("- Sampled displayed STORE candidates: ").append(sampledStores)
                .append("; unknown address/width: ").append(unknownAddressOrWidth)
                .append("; no profile register overlap: ").append(noProfiledRegister)
                .append("; candidate STORE/register overlaps: ").append(totalHits)
                .append("; omitted overlap rows: ").append(omittedHits)
                .append(". Source-page labels are UNVERIFIED claims, not ")
                .append("authenticated manual/edition evidence.\n");
            if(!hits.isEmpty()) {
                out.append("\n| CALL PC | STORE PC | Source start / bits | ")
                    .append("Register / address / width | Bytes covered | ")
                    .append("Classification | Claimed source page (UNVERIFIED) |\n")
                    .append("|---|---|---|---|---|---|---|\n");
                for(Hit h:hits)
                    out.append("| ").append(hex(h.callPc()))
                       .append(" | ").append(hex(h.storePc()))
                       .append(" | ").append(hex(h.start())).append(" / ")
                           .append(h.storeBits())
                       .append(" | ").append(h.module()).append(".")
                           .append(h.register()).append(" / ")
                           .append(hex(h.registerBase())).append(" / ")
                           .append(h.registerBits())
                       .append(" | ").append(h.coveredBytes())
                       .append(" | ").append(h.coverage())
                       .append(" | ").append(h.sourcePageLabel())
                       .append(" |\n");
            }
            if(omittedHits>0)
                out.append("- **INCOMPLETE COVERAGE DISPLAY:** omitted rows ")
                    .append("must not become a negative evidence claim.\n");
            return out.append("- Only existing, displayed CALL source candidates ")
                .append("are annotated. Upstream unknown aliases, source budgets, ")
                .append("unresolved CALLs and omitted source rows stay UNKNOWN.\n\n")
                .toString();
        }
    }

    /** Number of shared bytes, modulo the 24-bit CPU32 external address space. */
    private static int sharedBytes(long storeBase,int storeBytes,
            long registerBase,int registerBytes) {
        int shared=0;
        for(int i=0;i<registerBytes;i++) {
            long registerByte=(registerBase+i)&MASK24;
            for(int j=0;j<storeBytes;j++)
                if(((storeBase+j)&MASK24)==registerByte) {
                    shared++;
                    break;
                }
        }
        return shared;
    }

    /** Classify only already-reported CALL candidates against an explicit MCU. */
    public static Report analyze(HardwareProfiles.Profile profile,
            Collection<Store> stores) {
        if(profile==null || !profile.concreteDevice ||
                !"MC68332".equals(profile.id) ||
                stores==null || stores.size()>MAX_STORES)
            throw new IllegalArgumentException(
                "Explicit bounded MC68332 register coverage required");
        List<Store> sorted=new ArrayList<>(stores);
        if(sorted.contains(null))
            throw new IllegalArgumentException("Null source STORE");
        sorted.sort(Comparator.comparingLong(Store::callPc)
            .thenComparingLong(Store::storePc)
            .thenComparing(s->s.address(),Comparator.nullsFirst(Long::compare))
            .thenComparingInt(Store::bits));
        List<Hit> all=new ArrayList<>();
        int unknown=0,unmatched=0;
        for(Store store:sorted) {
            int bytes=switch(store.bits()) {
                case 8 -> 1;
                case 16 -> 2;
                case 32 -> 4;
                default -> 0;
            };
            if(store.address()==null || bytes==0) {
                unknown++;
                continue;
            }
            boolean matched=false;
            for(HardwareProfiles.Register reg:profile.registers)
                for(int mm=0;mm<=1;mm++) {
                    long base=profile.absoluteAddress(reg,mm);
                    int regBytes=reg.widthBits/8;
                    int covered=sharedBytes(store.address(),bytes,base,regBytes);
                    if(covered==0)continue;
                    matched=true;
                    all.add(new Hit(store.callPc(),store.storePc(),
                        store.address(),store.bits(),base,reg.module,
                        reg.name,reg.widthBits,covered,covered==regBytes,
                        store.address()==base && bytes==regBytes,
                        reg.sourcePage==null?"UNVERIFIED":reg.sourcePage));
                }
            if(!matched)unmatched++;
        }
        all.sort(Comparator.comparingLong(Hit::callPc)
            .thenComparingLong(Hit::storePc)
            .thenComparingLong(Hit::start)
            .thenComparingLong(Hit::registerBase)
            .thenComparing(Hit::register));
        int visible=Math.min(MAX_DISPLAY_HITS,all.size());
        return new Report(sorted.size(),unknown,unmatched,all.size(),
            all.size()-visible,List.copyOf(all.subList(0,visible)));
    }
}
