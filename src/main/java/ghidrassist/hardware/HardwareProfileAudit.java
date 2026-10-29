package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Read-only audit of profile *metadata*, not a verification of NXP manual
 * facts or a processor auto-detector. Existing MC68332 register definitions
 * can contain incomplete physical-page citations; those remain uncertain.
 */
public final class HardwareProfileAudit {
    private HardwareProfileAudit() {}

    public record RegisterSpec(String module,String name,int offset,int widthBits,
            String sourceUrl,String sourcePage) {}
    public record Issue(String register,String category,String detail) {}

    public record Summary(String profileId,boolean concreteDevice,int modules,
            int registerCount,int paginated,int missingPage,int fieldCount,
            int fieldPagesMissing,List<Issue> issues) {
        public Summary { issues=List.copyOf(issues); }
        public boolean collisionFree() {
            return issues.stream().noneMatch(x->x.category().contains("COLLISION") ||
                x.category().contains("OUTSIDE") || x.category().contains("WIDTH"));
        }
        public String markdown() {
            return "## Profile source-coverage audit (metadata only)\n\n" +
                "- Profile: "+profileId+"; explicitly device-scoped catalog: "+concreteDevice+
                "; module apertures: "+modules+"; register definitions: "+registerCount+".\n"+
                "- Register source labels containing physical PDF-page markers: "+paginated+
                "; missing/ambiguous physical-page labels: "+missingPage+
                "; bitfield definitions: "+fieldCount+
                "; bitfields with missing physical PDF-page labels: "+fieldPagesMissing+".\n"+
                "- Register range/width collision or aperture findings: "+
                issues.size()+"; collision-free metadata: "+collisionFree()+".\n"+
                "- These are **source citation metadata**, NOT independent validation "+
                "of the manual, MCU variant, memory map or runtime state. "+
                "Unverified/ambiguous pages must not be promoted to guaranteed facts.\n\n";
        }
    }

    public static boolean physicalPage(String provenance) {
        if(provenance==null)return false;
        String text=provenance.toLowerCase(Locale.ROOT);
        // Page labels are not enough to guarantee correctness of PDF content.
        return text.contains("pdf page") && !text.contains("to be verified") &&
            !text.contains("unverified");
    }

    /** Pure collision validator supports synthetic vendor-import test vectors. */
    public static List<Issue> overlaps(List<RegisterSpec> specs) {
        if(specs==null)throw new IllegalArgumentException("Null register catalog");
        List<Issue> issues=new ArrayList<>();
        Set<String> names=new HashSet<>();
        for(int i=0;i<specs.size();i++) {
            RegisterSpec a=specs.get(i);
            if(a==null || a.name()==null || a.module()==null) {
                issues.add(new Issue("UNKNOWN","INVALID","Missing register/module metadata"));
                continue;
            }
            if(!names.add(a.name().toUpperCase(Locale.ROOT)))
                issues.add(new Issue(a.name(),"NAME_COLLISION","Duplicate register name"));
            if(a.widthBits()!=8 && a.widthBits()!=16 && a.widthBits()!=32)
                issues.add(new Issue(a.name(),"INVALID_WIDTH","Width not 8/16/32 bits"));
            if(a.offset()<0 || (long)a.offset()+a.widthBits()/8>0x1000)
                issues.add(new Issue(a.name(),"OUTSIDE_APERTURE",
                    "Register outside 4 KiB internal module window"));
            for(int j=0;j<i;j++) {
                RegisterSpec b=specs.get(j);
                if(b==null || b.offset()<0 || b.widthBits()<8 ||
                        a.offset()<0 || a.widthBits()<8)continue;
                long ae=(long)a.offset()+a.widthBits()/8;
                long be=(long)b.offset()+b.widthBits()/8;
                if(a.offset()<be && b.offset()<ae)
                    issues.add(new Issue(a.name(),"ADDRESS_COLLISION",
                        "Overlaps "+b.name()+" at a register-byte range"));
            }
        }
        return List.copyOf(issues);
    }

    public static Summary inspect(HardwareProfiles.Profile profile) {
        if(profile==null)throw new IllegalArgumentException("Null CPU profile");
        List<RegisterSpec> specs=new ArrayList<>();
        int paginated=0,missing=0,bits=0,bitMissing=0;
        for(HardwareProfiles.Register r:profile.registers) {
            specs.add(new RegisterSpec(r.module,r.name,r.offset,r.widthBits,
                r.source,r.sourcePage));
            if(physicalPage(r.sourcePage)) paginated++;
            else missing++;
            for(HardwareProfiles.BitField f:r.fields) {
                bits++;
                if(!physicalPage(f.sourcePage))bitMissing++;
            }
        }
        List<Issue> problems=new ArrayList<>(overlaps(specs));
        for(HardwareProfiles.Register r:profile.registers) {
            boolean inside=false;
            for(HardwareProfiles.ModuleRegion module:profile.modules) {
                if(!r.module.equals(module.id))continue;
                if(r.offset>=module.offset &&
                    (long)r.offset+r.widthBits/8<=module.offset+module.sizeBytes)
                    inside=true;
            }
            if(!inside)
                problems.add(new Issue(r.name,"OUTSIDE_MODULE",
                    "Register not contained by declared MCU module aperture"));
        }
        problems.sort(Comparator.comparing(Issue::register)
            .thenComparing(Issue::category));
        return new Summary(profile.id,profile.concreteDevice,profile.modules.size(),
            specs.size(),paginated,missing,bits,bitMissing,problems);
    }
}
