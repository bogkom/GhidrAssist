package ghidrassist.hardware;

import java.util.List;

public final class HardwareProfileAuditSelfTest {
    private HardwareProfileAuditSelfTest() {}
    private static void ok(boolean flag,String message) {
        if(!flag)throw new AssertionError(message);
    }
    private static HardwareProfileAudit.RegisterSpec reg(String module,String name,
            int offset,int bits) {
        return new HardwareProfileAudit.RegisterSpec(module,name,offset,bits,
            HardwareProfiles.MC68332_MANUAL,"D-4 (PDF page 218)");
    }
    public static void main(String[] args) {
        var profile=HardwareProfileAudit.inspect(HardwareProfiles.mc68332());
        ok(profile.concreteDevice() && profile.registerCount()>150 &&
            profile.modules()==4,"MC68332 has nontrivial device-specific catalog");
        ok(profile.paginated()>0 && profile.missingPage()>0,
            "sourced and ambiguous physical-page metadata are differentiated");
        ok(profile.fieldCount()>=3 && profile.fieldPagesMissing()==0,
            "current explicitly labeled SIMCR bitfields retain their source refs");
        ok(profile.collisionFree(),
            "builtin MCU profile must have no duplicate addresses/names");
        ok(profile.markdown().contains("NOT independent validation") &&
            profile.markdown().contains("metadata only") &&
            profile.markdown().contains("NOT") &&
            profile.markdown().contains("bitfield definitions"),
            "no false documentation or hardware certainty");
        var family=HardwareProfileAudit.inspect(HardwareProfiles.cpu32Family());
        ok(!family.concreteDevice() && family.registerCount()==0 &&
            family.modules()==0,"generic CPU32 must not inherit MC68332 mapping");
        ok(HardwareProfileAudit.physicalPage("D-6 (PDF pages 218-220)") &&
            !HardwareProfileAudit.physicalPage("UNVERIFIED") &&
            !HardwareProfileAudit.physicalPage("Appendix D (page to be verified)") &&
            !HardwareProfileAudit.physicalPage(null),
            "citation parsing fails closed");
        var collisions=HardwareProfileAudit.overlaps(List.of(
            reg("SIM","SIMCR",0xa00,16),
            reg("SIM","SIM_OTHER",0xa01,8),
            reg("SIM","simcr",0xa10,8),
            reg("SIM","BAD_WIDTH",0xa11,7),
            reg("SIM","BAD_RANGE",0x1000,16)));
        ok(collisions.stream().anyMatch(x->x.category().equals("NAME_COLLISION")),
            "case-folded names must not silently overwrite");
        ok(collisions.stream().anyMatch(x->x.category().equals("ADDRESS_COLLISION")),
            "overlapping bit/byte writes must be marked");
        ok(collisions.stream().anyMatch(x->x.category().equals("INVALID_WIDTH")) &&
            collisions.stream().anyMatch(x->x.category().equals("OUTSIDE_APERTURE")),
            "untrusted profile input rejected from trusted paths");
        boolean immutable=false;
        try{collisions.clear();}catch(UnsupportedOperationException expected){immutable=true;}
        ok(immutable,"audit findings immutable");
        boolean fail=false;
        try{HardwareProfileAudit.overlaps(null);}
        catch(IllegalArgumentException expected){fail=true;}
        ok(fail,"missing catalog must be error, not empty validation");
        System.out.println("HardwareProfileAuditSelfTest OK");
    }
}
