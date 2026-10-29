package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Read-only reconciliation of TWO independently supplied, structurally valid
 * MCU-profile manifest previews. Differences are claims for human review:
 * neither manifest is an authoritative source for device or silicon behavior.
 *
 * No Ghidra APIs, automatic import, network calls, file access or mutations.
 */
public final class HardwareProfileManifestComparison {
    private HardwareProfileManifestComparison() {}
    public static final int MAX_DISPLAY_FINDINGS=100;
    public record Finding(String kind,String record,String description) {}
    public record Report(String device, String leftManual, String rightManual,
            boolean matchingClaimedPdfDigest, int equalDefinitions,
            int changedDefinitions, int changedPageLabels,
            int leftOnly, int rightOnly, int overlappingDifferentNames,
            int omittedFindings, List<Finding> findings) {
        public Report { findings=List.copyOf(findings); }
        public String render() {
            StringBuilder out=new StringBuilder(
                "EXTERNAL MCU PROFILE COMPARISON — UNVERIFIED CLAIMS ONLY\n\n")
                .append("Device label (both manifests): ").append(device).append("\n")
                .append("Left manual/edition: ").append(leftManual).append("\n")
                .append("Right manual/edition: ").append(rightManual).append("\n")
                .append("Matching *claimed* non-UNKNOWN PDF SHA-256: ")
                    .append(matchingClaimedPdfDigest).append("\n\n")
                .append("Identical definitions: ").append(equalDefinitions).append("\n")
                .append("Different definitions: ").append(changedDefinitions).append("\n")
                .append("Source page-label differences: ").append(changedPageLabels).append("\n")
                .append("Only in left: ").append(leftOnly).append("\n")
                .append("Only in right: ").append(rightOnly).append("\n")
                .append("Overlapping register addresses with distinct names: ")
                    .append(overlappingDifferentNames).append("\n")
                .append("Detailed findings retained: ").append(findings.size())
                .append("; omitted: ").append(omittedFindings).append("\n\n")
                .append("Differences are NOT verified hardware contradictions. ")
                .append("A changed manual edition, different PDF folio scheme, ")
                .append("alias or alternate name may explain them. An equal ")
                .append("claimed checksum is NOT independent byte verification.\n")
                .append("NO symbols, memory blocks, active device profiles, ")
                .append("Ghidra projects, RAG indexes or firmware changed.\n\n");
            for(Finding f:findings)
                out.append("- ").append(f.kind()).append(" [")
                    .append(f.record()).append("]: ")
                    .append(f.description()).append("\n");
            if(omittedFindings>0)
                out.append("- ADDITIONAL_UNDISPLAYED_FINDINGS: ")
                    .append(omittedFindings)
                    .append(" (review the source manifests; never treat this comparison ")
                    .append("as complete item-by-item evidence)\n");
            return out.toString();
        }
    }
    private record Entry(String definition,String page) {}
    private static final class Accumulator {
        final List<Finding> findings=new ArrayList<>();
        int equal,changed,pages,leftOnly,rightOnly,overlaps,omitted;
        void note(String kind,String key,String explanation) {
            if(findings.size()<MAX_DISPLAY_FINDINGS)
                findings.add(new Finding(kind,key,explanation));
            else omitted++;
        }
        void compare(String type, Map<String,Entry> a, Map<String,Entry> b) {
            TreeSet<String> keys=new TreeSet<>(a.keySet());
            keys.addAll(b.keySet());
            for(String key:keys) {
                Entry left=a.get(key),right=b.get(key);
                String qualified=type+":"+key;
                if(left==null) {
                    rightOnly++;note("RIGHT_ONLY",qualified,right.definition());
                }else if(right==null) {
                    leftOnly++;note("LEFT_ONLY",qualified,left.definition());
                }else if(!left.definition().equals(right.definition())) {
                    changed++;
                    note("DEFINITION_DIFFERENCE",qualified,
                        "left="+left.definition()+"; right="+right.definition());
                }else {
                    equal++;
                }
                // Page-label changes are independently reported even when
                // structural definitions agree. A label is NOT proof of a
                // physical PDF page in either claimed edition.
                if(left!=null && right!=null && !left.page().equals(right.page())) {
                    pages++;
                    note("SOURCE_PAGE_LABEL_DIFFERENCE",qualified,
                        "left="+left.page()+"; right="+right.page());
                }
            }
        }
    }
    private static String norm(String name) {
        return name.toUpperCase(Locale.ROOT);
    }
    private static Map<String,Entry> modules(HardwareProfileManifestPreview.Preview p) {
        Map<String,Entry> map=new TreeMap<>();
        for(var m:p.modules())
            map.put(norm(m.id()),new Entry(
                String.format(Locale.ROOT,"offset=0x%04X size=0x%04X",
                    m.offset(),m.size()),m.page()));
        return map;
    }
    private static Map<String,Entry> registers(HardwareProfileManifestPreview.Preview p) {
        Map<String,Entry> map=new TreeMap<>();
        for(var r:p.registers())
            map.put(norm(r.name()),new Entry(
                String.format(Locale.ROOT,"module=%s offset=0x%04X width=%d",
                    norm(r.module()),r.offset(),r.widthBits()),r.page()));
        return map;
    }
    private static Map<String,Entry> fields(HardwareProfileManifestPreview.Preview p) {
        Map<String,Entry> map=new TreeMap<>();
        for(var f:p.fields())
            map.put(norm(f.register())+"."+norm(f.name()),new Entry(
                String.format(Locale.ROOT,"mask=0x%08X",f.mask()),f.page()));
        return map;
    }
    public static Report compare(HardwareProfileManifestPreview.Preview left,
            HardwareProfileManifestPreview.Preview right) {
        if(left==null || right==null || left.source()==null || right.source()==null)
            throw new IllegalArgumentException("Two parsed profiles required");
        if(!left.source().device().equalsIgnoreCase(right.source().device()))
            throw new IllegalArgumentException(
                "Different device labels: comparison refused; no inferred MCU identity");
        Accumulator acc=new Accumulator();
        acc.compare("MODULE",modules(left),modules(right));
        acc.compare("REGISTER",registers(left),registers(right));
        acc.compare("FIELD",fields(left),fields(right));
        // A renamed register can collide with another manifest's register
        // at the same address. This is a POSSIBLE alias, not proof of error.
        for(var a:left.registers())for(var b:right.registers())
            if(!a.name().equalsIgnoreCase(b.name()) &&
                    a.offset()<b.end() && b.offset()<a.end()) {
                acc.overlaps++;
                acc.note("CROSS_NAME_ADDRESS_OVERLAP",
                    norm(a.name())+"/"+norm(b.name()),
                    String.format(Locale.ROOT,
                        "left [0x%04X,0x%04X); right [0x%04X,0x%04X)",
                        a.offset(),a.end(),b.offset(),b.end()));
            }
        String lhs=left.source().claimedSha256(),rhs=right.source().claimedSha256();
        boolean sameDigest=lhs.matches("[0-9a-fA-F]{64}") &&
            lhs.equalsIgnoreCase(rhs);
        return new Report(left.source().device(),
            left.source().manualId()+" / "+left.source().edition(),
            right.source().manualId()+" / "+right.source().edition(),
            sameDigest,acc.equal,acc.changed,acc.pages,acc.leftOnly,
            acc.rightOnly,acc.overlaps,acc.omitted,acc.findings);
    }
}
