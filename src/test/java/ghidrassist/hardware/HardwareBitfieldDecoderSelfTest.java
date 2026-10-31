package ghidrassist.hardware;

/** Dependency-free negative and provenance regression for GA-10. */
public final class HardwareBitfieldDecoderSelfTest {
    private HardwareBitfieldDecoderSelfTest() {}
    private static void check(boolean ok,String message) {
        if (!ok) throw new AssertionError(message);
    }
    public static void main(String[] args) {
        var mc = HardwareProfiles.mc68332();
        var cpu = HardwareProfiles.cpu32Family();
        var known = HardwareBitfieldDecoder.decode(mc,"simcr",0x40ca,16);
        check(known.status()==HardwareBitfieldDecoder.Status.DECODED,
            "MC68332 full-word SIMCR decode");
        check(known.fields().size()==3,"only three sourced SIMCR fields");
        var mm = known.fields().stream().filter(f->f.name().equals("MM")).findFirst().orElseThrow();
        var supv = known.fields().stream().filter(f->f.name().equals("SUPV")).findFirst().orElseThrow();
        var iarb = known.fields().stream().filter(f->f.name().equals("IARB")).findFirst().orElseThrow();
        check(mm.mask()==0x40 && mm.value()==1 && mm.writeOnceAfterReset(),
            "MM bit 6 must decode as 1 with latch caveat");
        check(supv.mask()==0x80 && supv.value()==1,"SUPV bit 7");
        check(iarb.mask()==0xf && iarb.value()==0xa,"IARB nibble");
        check(mm.sourcePage().contains("PDF page") && supv.sourcePage().contains("PDF page") &&
            iarb.sourcePage().contains("PDF page"),"source pages retained");
        check(known.unspecifiedMask()==0xff30,"all non-sourced SIMCR bits remain uninterpreted");
        check(known.summary().contains("MM=1") &&
            known.summary().contains("IARB=0xA") &&
            known.summary().contains("not proven hardware state or write order"),
            "summary must be factual and conditional");
        var zero = HardwareBitfieldDecoder.decode(mc,"SIMCR",0,16);
        check(zero.fields().get(0).value()==0,"zero is a decoded bit value, not an assumed reset");
        check(HardwareBitfieldDecoder.decode(cpu,"SIMCR",0x40ca,16).status() ==
            HardwareBitfieldDecoder.Status.DEVICE_NOT_SELECTED,
            "generic CPU32 must not inherit peripherals");
        check(HardwareBitfieldDecoder.decode(null,"SIMCR",0x40ca,16).status() ==
            HardwareBitfieldDecoder.Status.DEVICE_NOT_SELECTED,"null profile must be safe");
        check(HardwareBitfieldDecoder.decode(mc,"NOT_A_REGISTER",0,16).status() ==
            HardwareBitfieldDecoder.Status.REGISTER_UNKNOWN,"unknown register");
        check(HardwareBitfieldDecoder.decode(mc,"SIMCR",null,16).status() ==
            HardwareBitfieldDecoder.Status.VALUE_UNKNOWN,"no fabricated unknown write");
        check(HardwareBitfieldDecoder.decode(mc,"SIMCR",0x40ca,8).status() ==
            HardwareBitfieldDecoder.Status.WIDTH_MISMATCH,"reject byte partial write");
        check(HardwareBitfieldDecoder.decode(mc,"SIMCR",0x10040,16).status() ==
            HardwareBitfieldDecoder.Status.VALUE_OUT_OF_RANGE,"reject non-word value");
        check(HardwareBitfieldDecoder.decode(mc,"CSOR0",0x7c30,16).status() ==
            HardwareBitfieldDecoder.Status.NO_SOURCED_FIELDS,
            "register with no sourced bitfields must stay uninterpreted");
        check(HardwareBitfieldDecoder.decode(mc,"TRAMBAR",0xfff0,16).status() ==
            HardwareBitfieldDecoder.Status.NO_SOURCED_FIELDS,
            "address metadata is not a bitfield definition");
        boolean immutable = false;
        try {known.fields().clear();} catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"no mutable evidence results");
        check(HardwareBitfieldDecoder.hasConcretePdfPageClaim(
                "D-5/D-6 (PDF pages 219-220)") &&
            HardwareBitfieldDecoder.hasConcretePdfPageClaim(
                "D-6 (PDF page 220)"),
            "current sourced SIMCR definitions have numeric physical page claims");
        for(String unsourced: new String[]{null,"","UNVERIFIED","UNKNOWN",
                "D-6", "Appendix D (page to be verified)",
                "PDF page UNKNOWN", "PDF pages 12-13 AMBIGUOUS",
                "PDF page 0", "PDF page ?",
                "PDF page 10 unverified edition"}) {
            check(!HardwareBitfieldDecoder.hasConcretePdfPageClaim(unsourced),
                "reject unsupported/ambiguous field page citation: "+unsourced);
        }
        check(known.summary().contains("source-page-claimed MC68332") &&
            known.summary().contains("PDF edition/page claim UNVERIFIED"),
            "literal field decode cannot claim physical PDF identity proof");
        System.out.println("HardwareBitfieldDecoderSelfTest OK");
    }
}
