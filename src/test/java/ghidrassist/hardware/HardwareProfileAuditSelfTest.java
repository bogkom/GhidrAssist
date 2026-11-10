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
        // A mere PDF-page substring must never inflate provenance
        // coverage when the numeric claim is malformed or ambiguous.
        for(String malformed : new String[]{
                "D-6 (PDF page abc)", "D-6 (PDF page 0)",
                "D-6 (PDF page 999999)",
                "D-6 (PDF pages 220-219)",
                "D-6 (PDF page 220/221)",
                "D-6 (PDF page 220, PDF page 220)",
                "D-6 (PDF page 220) UNVERIFIED",
                "D-6 (PDF pages 220-0)",
                "D-6 (PDF page 220-abc)",
                "D-6 (PDF page 220-221-222)"}) {
            ok(!HardwareProfileAudit.physicalPage(malformed),
                "malformed numeric physical folio must not be counted: "+malformed);
        }
        ok(HardwareProfileAudit.physicalPage("D-6 (PDF page 220)") &&
            HardwareProfileAudit.physicalPage("D-5/D-6 (PDF pages 219-220)"),
            "well-formed numeric physical-page and range claims remain accepted");
        ok(!HardwareProfileAudit.physicalPage(
                "D-4/D-7 (PDF pages 218/221)"),
            "noncontiguous slash folio references remain ambiguous for audit");
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
        // Pure source audit must never label a malformed isolated
        // register as collision-free just because no second address overlaps.
        var singleInvalid=HardwareProfileAudit.overlaps(List.of(
            reg("SIM","",0xa00,16)));
        ok(singleInvalid.stream().anyMatch(x->
                x.category().equals("INVALID_IDENTIFIER")),
            "empty register names are structurally invalid");
        var blankModule=HardwareProfileAudit.overlaps(List.of(
            reg("","REG_A",0xa00,16)));
        ok(blankModule.stream().anyMatch(x->
                x.category().equals("INVALID_IDENTIFIER")),
            "blank MCU module id is not trusted profile metadata");
        var oddWord=HardwareProfileAudit.overlaps(List.of(
            reg("SIM","ODD_WORD",0xa01,16)));
        var oddLong=HardwareProfileAudit.overlaps(List.of(
            reg("SIM","ODD_LONG",0xa02,32)));
        ok(oddWord.stream().anyMatch(x->
                x.category().equals("MISALIGNED_REGISTER")) &&
           oddLong.stream().anyMatch(x->
                x.category().equals("MISALIGNED_REGISTER")),
            "word and long registers must be naturally aligned");
        var cleanByte=HardwareProfileAudit.overlaps(List.of(
            reg("SIM","BYTE_A",0xa01,8)));
        ok(cleanByte.isEmpty(),
            "8-bit register at odd address is valid");
        var badShapeReport=new HardwareProfileAudit.Summary(
            "SYNTHETIC",true,1,1,1,0,0,0,singleInvalid);
        ok(!badShapeReport.collisionFree(),
            "INVALID issue alone prevents collision-free claim");
        var badAlignReport=new HardwareProfileAudit.Summary(
            "SYNTHETIC",true,1,1,0,1,0,0,oddWord);
        ok(!badAlignReport.collisionFree() &&
           badAlignReport.markdown().contains("collision-free metadata: false"),
            "alignment failures must be visible in markdown");
        var malformedTotals=new java.util.ArrayList<Runnable>();
        malformedTotals.add(()->new HardwareProfileAudit.Summary(
            "SYNTHETIC",true,1,1,1,1,0,0,List.of()));
        malformedTotals.add(()->new HardwareProfileAudit.Summary(
            "SYNTHETIC",true,1,1,1,0,1,2,List.of()));
        malformedTotals.add(()->new HardwareProfileAudit.Summary(
            "SYNTHETIC",true,1,-1,0,0,0,0,List.of()));
        malformedTotals.add(()->new HardwareProfileAudit.Summary(
            "SYNTHETIC",true,1,1,0,1,0,0,
            java.util.Arrays.asList((HardwareProfileAudit.Issue)null)));
        for(Runnable forged:malformedTotals) {
            boolean refused=false;
            try {forged.run();}
            catch(IllegalArgumentException expected){refused=true;}
            ok(refused,
                "forged profile coverage totals or malformed issue inventory fail closed");
        }
        boolean oversizedAuditRejected=false;
        try {
            HardwareProfileAudit.overlaps(
                java.util.Collections.nCopies(
                    HardwareProfileAudit.MAX_AUDIT_REGISTERS+1,
                    reg("SIM","REG_A",0xa00,16)));
        }catch(IllegalArgumentException expected){
            oversizedAuditRejected=true;
        }
        ok(oversizedAuditRejected,
            "unbounded external pairwise register audit input is rejected");
        System.out.println("HardwareProfileAuditSelfTest OK");
    }
}
