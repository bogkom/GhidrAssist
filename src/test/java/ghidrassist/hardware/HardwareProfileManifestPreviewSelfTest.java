package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;

public final class HardwareProfileManifestPreviewSelfTest {
    private HardwareProfileManifestPreviewSelfTest(){}
    private static void check(boolean condition,String reason){
        if(!condition)throw new AssertionError(reason);
    }
    private static void refusesPreview(Runnable task,String reason){
        boolean refused=false;
        try{task.run();}catch(IllegalArgumentException expected){refused=true;}
        check(refused,reason);
    }
    private static final String SAMPLE="""
        GHIDRASSIST_PROFILE\t1
        DOCUMENT\tMC68332\tMC68332UM\thttps://www.nxp.com/docs/en/user-guide/MC68332UM.pdf\tUNKNOWN\tUNKNOWN
        MODULE\tSIM\t0x0A00\t0x0080\tD-1 PDF page 215
        MODULE\tQSM\t0x0C00\t0x0200\tUNKNOWN
        REGISTER\tSIM\tSIMCR\t0x0A00\t16\tD-6 PDF page 220
        REGISTER\tSIM\tSYPCR\t0x0A21\t8\tUNKNOWN
        REGISTER\tQSM\tQSMCR\t0x0C00\t16\tUNKNOWN
        FIELD\tSIMCR\tMM\t0x0040\tD-6 PDF page 220
        FIELD\tSIMCR\tSUPV\t0x0080\tUNKNOWN
        """;
    private static void bad(String text,String reason){
        boolean failed=false;
        try{HardwareProfileManifestPreview.parse(text);}
        catch(IllegalArgumentException e){failed=true;}
        check(failed,reason);
    }
    public static void main(String[] args){
        var result=HardwareProfileManifestPreview.parse(SAMPLE);
        check(result.source().device().equals("MC68332") &&
            result.modules().size()==2 && result.registers().size()==3 &&
            result.fields().size()==2,"valid structure read without Ghidra APIs");
        check(result.ambiguousPages()==4,"physical-page gaps counted");
        check(result.report().contains("NOT IMPORTED into Ghidra") &&
            result.report().contains("Claimed edition: UNKNOWN") &&
            result.report().contains("No MCU identification"),
            "reports may not promote provided metadata to verified facts");
        check(result.registers().get(0).offset()==0xA00 &&
            result.fields().get(0).mask()==0x40,"hex and bitfields preserved");
        bad(SAMPLE.replace("GHIDRASSIST_PROFILE\t1","GHIDRASSIST_PROFILE\t2"),
            "reject unsupported future schema");
        bad(SAMPLE.replace("https://www.nxp.com","http://www.nxp.com"),
            "reject untrusted HTTP manual references");
        // Manifest URLs are claimed provenance, never fetched, but cannot
        // masquerade as another host through userinfo or Unicode controls.
        for(String untrusted:new String[]{
                "https://user:secret@www.nxp.com/docs/MC68332UM.pdf",
                "https://www.nxp.com@other.invalid/docs/MC68332UM.pdf",
                "https://www.nxp.com/docs/" + ((char)0x202e) + "MC68332UM.pdf",
                "https://www.nxp.com/docs/" + ((char)0x200b) + "MC68332UM.pdf",
                "https://www.nxp.com/docs/" + ((char)0x7f) + "MC68332UM.pdf",
                "https://www.nxp.com/%GG.pdf",
                "https:///docs/no-host.pdf",
                "https://bad host.invalid/docs/MC68332UM.pdf",
                "https://[unclosed-ipv6/docs/MC68332UM.pdf"}) {
            bad(SAMPLE.replace(
                    "https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf",
                    untrusted),
                "fail-closed deceptive DOCUMENT URL: "+untrusted);
        }
        var encodedUrl=HardwareProfileManifestPreview.parse(
            SAMPLE.replace("https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf",
                "https://www.nxp.com/docs/en/user-guide/MC68332%20UM.pdf?x=1#page=215"));
        check(encodedUrl.source().url().contains("%20UM.pdf"),
            "valid printable percent-encoded HTTPS PDF path preserved verbatim");
        bad(SAMPLE.replace("https://www.nxp.com/docs",
                "https://www.\rnxp.com/docs"),
            "embedded carriage return cannot silently rewrite URL");
        var crlf=HardwareProfileManifestPreview.parse(
            SAMPLE.replace("\n","\r\n"));
        check(crlf.modules().size()==2 && crlf.registers().size()==3,
            "ordinary CRLF record terminators remain accepted");
        bad(SAMPLE.replace("UNKNOWN\tUNKNOWN","UNKNOWN\t1234"),
            "reject malformed claimed PDF checksum");
        bad(SAMPLE.replace("MODULE\tQSM\t0x0C00","MODULE\tQSM\t0x0A40"),
            "reject overlapping module apertures");
        bad(SAMPLE.replace("REGISTER\tSIM\tSYPCR\t0x0A21\t8",
                           "REGISTER\tSIM\tSYPCR\t0x0A01\t8"),
            "reject overlapping register ranges");
        bad(SAMPLE.replace("REGISTER\tSIM\tSIMCR\t0x0A00\t16",
                           "REGISTER\tSIM\tSIMCR\t0x0A01\t16"),
            "reject odd word alignment");
        bad(SAMPLE.replace("FIELD\tSIMCR\tSUPV\t0x0080",
                           "FIELD\tSIMCR\tSUPV\t0x0040"),
            "reject overlapping bitfields");
        String wide=SAMPLE.replace("REGISTER\tSIM\tSIMCR\t0x0A00\t16",
                "REGISTER\tSIM\tSIMCR\t0x0A00\t32")
            .replace("REGISTER\tSIM\tSYPCR\t0x0A21\t8",
                     "REGISTER\tSIM\tSYPCR\t0x0A24\t8")
            .replace("FIELD\tSIMCR\tMM\t0x0040",
                     "FIELD\tSIMCR\tMM\t0x80000000");
        var widest=HardwareProfileManifestPreview.parse(wide);
        check(widest.fields().get(0).mask()==0x80000000L,
            "full-width 32-bit masks must be unsigned and supported");
        bad(SAMPLE.replace("FIELD\tSIMCR\tMM\t0x0040",
                           "FIELD\tSIMCR\tMM\t0x10000"),
            "reject bitfield outside register width");
        bad(SAMPLE.replace("FIELD\tSIMCR\tMM\t0x0040",
                           "FIELD\tUNKNOWN\tMM\t0x0040"),
            "reject unsupported field register");
        bad(SAMPLE.replace("REGISTER\tSIM\tSYPCR","REGISTER\tOTHER\tSYPCR"),
            "reject unknown module");
        bad(SAMPLE + "COMPUTER\tSHOULD_NOT_RUN\tcmd\n",
            "no arbitrary record execution");
        bad(SAMPLE.repeat(130),"reject duplicated definitions/unbounded input");
        bad("","reject blank file");
        var report=result.report();
        check(report.length()<1500,"preview output is bounded");
        boolean immutable=false;
        try{result.modules().clear();}
        catch(UnsupportedOperationException e){immutable=true;}
        check(immutable,"preview immutable");
        // A second module differing only in case must never silently
        // overwrite a normalized key in the comparison view.
        bad(SAMPLE.replace("MODULE\tQSM\t0x0C00\t0x0200",
                "MODULE\tsim\t0x0C00\t0x0200"),
            "case-insensitive duplicate module names must be rejected");
        var mixedCase=HardwareProfileManifestPreview.parse(
            SAMPLE.replace("REGISTER\tSIM\tSIMCR",
                "REGISTER\tsim\tSIMCR"));
        check(mixedCase.registers().get(0).module().equals("SIM"),
            "register resolves explicitly declared module regardless of case");
        for(String unsupported:new String[]{"PDF page","PDF page UNKNOWN",
                "PDF pages 2-3 AMBIGUOUS","PDF page 0",
                "Appendix D page to be verified","PDF page abc"}){
            var changed=HardwareProfileManifestPreview.parse(
                SAMPLE.replace("D-6 PDF page 220",unsupported));
            check(changed.ambiguousPages()==6,
                "unknown source page must remain counted as ambiguous: "+unsupported);
        }
        var explicit=HardwareProfileManifestPreview.parse(
            SAMPLE.replace("D-6 PDF page 220","D-6 PDF pages 220-221"));
        check(explicit.ambiguousPages()==4,
            "numeric source page range is a claim, not unverified gap");
        for(String malformed:new String[]{
                "PDF pages 220-219","PDF page 220-0",
                "PDF page 999999","PDF page 220-abc"}) {
            var replaced=HardwareProfileManifestPreview.parse(
                SAMPLE.replace("D-6 PDF page 220",malformed));
            check(replaced.ambiguousPages()==6,
                "reject false numeric PDF page claim: "+malformed);
        }
        // A semicolon is already forbidden by the strict profile-label
        // grammar; it must be rejected at parse time, not counted as an
        // otherwise syntactically valid but ambiguous page claim.
        bad(SAMPLE.replace("D-6 PDF page 220",
                "PDF page 220; PDF page 220"),
            "reject a second page claim outside the manifest label grammar");
        // Public Preview/records can be supplied without going through
        // parse(), including to the read-only two-manifest comparator.
        // They must still satisfy the exact same trusted STRUCTURAL gates.
        var same=new HardwareProfileManifestPreview.Preview(
            result.source(),result.modules(),result.registers(),
            result.fields(),result.ambiguousPages());
        check(same.equals(result) &&
            HardwareProfileManifestComparison.compare(result,same)
                .changedDefinitions()==0,
            "Valid parsed inventory round-trips the public Preview boundary");
        boolean refused=false;
        try{new HardwareProfileManifestPreview.Source(
            "MC68332","MC68332UM","https://bad@nxp.com/manual.pdf",
            "UNKNOWN","UNKNOWN");}
        catch(IllegalArgumentException expected){refused=true;}
        check(refused,"Public Source cannot bypass the HTTPS userinfo gate");
        refused=false;
        try{new HardwareProfileManifestPreview.Module(
            "SIM",0x0ff0,0x80,"PDF page 215");}
        catch(IllegalArgumentException expected){refused=true;}
        check(refused,"Public module aperture must remain inside 4 KiB");
        refused=false;
        try{new HardwareProfileManifestPreview.Register(
            "SIM","BAD",0x0a01,16,"PDF page 215");}
        catch(IllegalArgumentException expected){refused=true;}
        check(refused,"Public register cannot skip natural word alignment");
        refused=false;
        try{new HardwareProfileManifestPreview.Field(
            "SIMCR","BAD",0x100000000L,"PDF page 220");}
        catch(IllegalArgumentException expected){refused=true;}
        check(refused,"Public 64-bit field mask cannot bypass 32-bit source limit");
        var source=result.source();
        var modules=result.modules();
        var registers=result.registers();
        var fields=result.fields();
        refusesPreview(()->new HardwareProfileManifestPreview.Preview(
            source,modules,registers,fields,result.ambiguousPages()-1),
            "Forged missing-page count rejected even with correct source rows");
        var duplicateModules=new ArrayList<>(modules);
        duplicateModules.add(new HardwareProfileManifestPreview.Module(
            "sim",0x0400,0x80,"UNKNOWN"));
        refusesPreview(()->new HardwareProfileManifestPreview.Preview(
            source,duplicateModules,registers,fields,
            result.ambiguousPages()+1),
            "Case-colliding public module identities rejected");
        var overlappingModules=new ArrayList<>(modules);
        overlappingModules.add(new HardwareProfileManifestPreview.Module(
            "OTHER",0x0a40,0x20,"UNKNOWN"));
        refusesPreview(()->new HardwareProfileManifestPreview.Preview(
            source,overlappingModules,registers,fields,
            result.ambiguousPages()+1),
            "Public module apertures must not overlap");
        var missingModule=new ArrayList<>(modules);
        missingModule.remove(0);
        refusesPreview(()->new HardwareProfileManifestPreview.Preview(
            source,missingModule,registers,fields,result.ambiguousPages()-1),
            "Public register cannot borrow a missing module owner");
        var overlappingRegisters=new ArrayList<>(registers);
        overlappingRegisters.add(new HardwareProfileManifestPreview.Register(
            "SIM","ALIAS",0x0a00,16,"UNKNOWN"));
        refusesPreview(()->new HardwareProfileManifestPreview.Preview(
            source,modules,overlappingRegisters,fields,
            result.ambiguousPages()+1),
            "Public source register collision cannot bypass parser");
        var forgedOwner=new ArrayList<>(registers);
        forgedOwner.set(0,new HardwareProfileManifestPreview.Register(
            "QSM","SIMCR",0x0a00,16,"D-6 PDF page 220"));
        refusesPreview(()->new HardwareProfileManifestPreview.Preview(
            source,modules,forgedOwner,fields,result.ambiguousPages()),
            "Public register must remain inside its canonical named module");
        var forgedField=new ArrayList<>(fields);
        forgedField.add(new HardwareProfileManifestPreview.Field(
            "SIMCR","MM_ALIAS",0x0040,"UNKNOWN"));
        refusesPreview(()->new HardwareProfileManifestPreview.Preview(
            source,modules,registers,forgedField,result.ambiguousPages()+1),
            "Overlapping bit masks cannot be introduced via public field list");
        forgedField=new ArrayList<>(fields);
        forgedField.add(new HardwareProfileManifestPreview.Field(
            "SIMCR","OUTSIDE",0x10000,"UNKNOWN"));
        final var overWidth=forgedField;
        refusesPreview(()->new HardwareProfileManifestPreview.Preview(
            source,modules,registers,overWidth,result.ambiguousPages()+1),
            "Public bitfield mask must fit declared register width");
        var missingRegister=new ArrayList<>(registers);
        missingRegister.remove(0);
        refusesPreview(()->new HardwareProfileManifestPreview.Preview(
            source,modules,missingRegister,fields,result.ambiguousPages()-1),
            "Public field must retain its actual register identity");
        var nullModule=new ArrayList<>(modules);
        nullModule.set(0,null);
        refusesPreview(()->new HardwareProfileManifestPreview.Preview(
            source,nullModule,registers,fields,result.ambiguousPages()),
            "Null source module fails as invalid input, not NullPointerException");
        refusesPreview(()->new HardwareProfileManifestPreview.Preview(
            source,modules,registers,fields,99999),
            "Unbounded public page-gap count cannot be forged");
        System.out.println("HardwareProfileManifestPreviewSelfTest OK");
    }
}
