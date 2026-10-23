package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Review-only proposals. Planning does not open a transaction or alter Ghidra.
 * A concrete MC68332 hypothesis and MM=1 must be selected explicitly.
 *
 * CS ranges are speculative and can be combined for convenient analysis.
 * Mapping a region does not establish physical device selection.
 */
public final class HardwareApplyPlan {
    private HardwareApplyPlan() {}
    public enum Kind { MEMORY, REGISTER, VBR_STRUCTURE }
    public static final class Item {
        public final Kind kind;
        public final String name;
        public final long address;
        public final int length;
        public final String details;
        Item(Kind kind,String name,long address,int length,String details){
            this.kind=kind;this.name=name;this.address=address;
            this.length=length;this.details=details;
        }
        public long last(){return address+length-1;}
        public String location(){
            return ChipSelectModel.hex(address,6)+".."+ChipSelectModel.hex(last(),6);
        }
    }
    private static void add(List<Item> out,Kind kind,String name,long at,int len,String note){
        if(len<1||at<0||at+len-1>0xffffffL)
            throw new IllegalArgumentException("Invalid 24-bit memory range");
        out.add(new Item(kind,name,at,len,note));
    }
    public static List<Item> mc68332Mm1Candidates(long vbrAddress){
        if(vbrAddress<0 || vbrAddress>0xfffffc || (vbrAddress&3)!=0)
            throw new IllegalArgumentException("VBR must be 4-byte aligned and in 24-bit space");
        List<Item> items=new ArrayList<>();
        // Source-backed aperture rows from MC68332UM Appendix D Table D-1.
        // Never infer the physical CPU from a Ghidra language selection.
        HardwareProfiles.Profile selected = HardwareProfiles.mc68332();
        for (HardwareProfiles.ModuleRegion region : selected.modules) {
            add(items,Kind.MEMORY,region.blockName,
                HardwareProfiles.INTERNAL_BASE_MM1 + region.offset,
                region.sizeBytes, "MC68332 hypothesis; " + region.sourcePage +
                    "; reserved offsets remain untyped");
        }
        add(items,Kind.MEMORY,"TPURAM_2K_CANDIDATE",0xfff000,0x800,
            "2KiB candidate relocated TPU RAM at TRAMBAR=0xFFF0");
        // CS candidates are derived from observed firmware writes, not fixed addresses.
        for(HardwareProfiles.Register register:selected.registers){
            long at=HardwareProfiles.INTERNAL_BASE_MM1+register.offset;
            add(items,Kind.REGISTER,register.name,at,
                register.widthBits/8,
                "Source-backed candidate: "+register.module+
                "; "+register.sourcePage+"; access="+register.access+
                "; write="+register.writePolicy+"; reset="+
                (register.resetValue==null?"UNVERIFIED":register.resetValue)+
                "; explicitly selected MCU hypothesis; no auto-rename of other symbols");
        }
        add(items,Kind.VBR_STRUCTURE,"CPU32_VBR_256_VECTORS",vbrAddress,256*4,
            "256 x 32-bit vector entries at USER-SUPPLIED VBR base; "+
            "apply only to entirely undefined data; no code clearing");
        return Collections.unmodifiableList(items);
    }

    /**
     * Build speculative CS memory windows solely from direct, literal CSBAR
     * assignments observed in the static scan. Alternative initializers are
     * kept as alternative candidate ranges: address order is not execution order.
     * No claim is made about CS assertion, external wiring or peripheral type.
     */
    public record CsbarEvidence(String register, int value, String function) {}

    public static List<Item> chipSelectWindowCandidates(
            List<CsbarEvidence> sites) {
        if (sites == null || sites.isEmpty()) return List.of();
        List<Item> windows = new ArrayList<>();
        for (CsbarEvidence site : sites) {
            if (site == null || site.register() == null) continue;
            String name = site.register();
            if (!(name.equals("CSBARBT") || name.matches("CSBAR(?:10|[0-9])"))) continue;
            HardwareProfiles.CsbarWindow window = HardwareProfiles.decodeCsbar(site.value());
            if (window.base < 0 || window.endInclusive > 0xffffffL) continue;
            add(windows, Kind.MEMORY, name, window.base, (int) window.size,
                name + " assignment in " + site.function() +
                "; device identity and assertion UNKNOWN");
        }
        if (windows.isEmpty()) return List.of();
        windows.sort(java.util.Comparator.comparingLong(x -> x.address));
        List<Item> merged = new ArrayList<>();
        long first = windows.get(0).address;
        long last = windows.get(0).last();
        java.util.LinkedHashSet<String> sources = new java.util.LinkedHashSet<>();
        sources.add(windows.get(0).details);
        for (int i=1; i<windows.size(); i++) {
            Item next = windows.get(i);
            if (next.address <= last + 1) {
                last = Math.max(last,next.last());
                sources.add(next.details);
            } else {
                addMerged(merged, first, last, sources);
                first = next.address;
                last = next.last();
                sources.clear();
                sources.add(next.details);
            }
        }
        addMerged(merged, first, last, sources);
        return List.copyOf(merged);
    }
    private static void addMerged(List<Item> out, long first, long last,
            java.util.Collection<String> sources) {
        String id = String.format(java.util.Locale.ROOT,
            "CS_WINDOW_%06X_%06X", first, last);
        add(out, Kind.MEMORY, id, first, (int)(last-first+1),
            "Combined overlapping/adjacent CS windows; " +
            String.join("; ",sources));
    }

    /** Full review plan, with CS windows discovered in the current scan. */
    public static List<Item> mc68332Mm1Candidates(long vbrAddress,
            List<CsbarEvidence> sites) {
        List<Item> original = mc68332Mm1Candidates(vbrAddress);
        List<Item> generated = chipSelectWindowCandidates(sites);
        if (generated.isEmpty()) return original;
        List<Item> combined = new ArrayList<>(original.size()+generated.size());
        combined.addAll(original.subList(0, original.size()-1));
        combined.addAll(generated);
        combined.add(original.get(original.size()-1)); // VBR always last
        return List.copyOf(combined);
    }
    public static boolean intersects(Item a,Item b){
        return a.address<=b.last()&&b.address<=a.last();
    }
}
