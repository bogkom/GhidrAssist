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
        check(known.fields().size()==8,"eight page-claimed SIMCR configuration fields");
        var mm = known.fields().stream().filter(f->f.name().equals("MM")).findFirst().orElseThrow();
        var supv = known.fields().stream().filter(f->f.name().equals("SUPV")).findFirst().orElseThrow();
        var iarb = known.fields().stream().filter(f->f.name().equals("IARB")).findFirst().orElseThrow();
        check(mm.mask()==0x40 && mm.value()==1 && mm.writeOnceAfterReset(),
            "MM bit 6 must decode as 1 with latch caveat");
        check(supv.mask()==0x80 && supv.value()==1,"SUPV bit 7");
        check(iarb.mask()==0xf && iarb.value()==0xa,"IARB nibble");
        check(mm.sourcePage().contains("PDF page") && supv.sourcePage().contains("PDF page") &&
            iarb.sourcePage().contains("PDF page"),"source pages retained");
        check(known.unspecifiedMask()==0x1430,"reserved/unsourced SIMCR bits remain uninterpreted");
        var simcrFields=new java.util.HashMap<String,HardwareBitfieldDecoder.FieldEvidence>();
        for(var field:known.fields())
            check(simcrFields.put(field.name(),field)==null,
                "SIMCR sourced field labels must be unique");
        check(simcrFields.get("EXOFF").mask()==0x8000 &&
              simcrFields.get("EXOFF").value()==0 &&
              simcrFields.get("FRZSW").mask()==0x4000 &&
              simcrFields.get("FRZBM").mask()==0x2000 &&
              simcrFields.get("SLVEN").mask()==0x0800 &&
              simcrFields.get("SHEN").mask()==0x0300,
            "MC68332UM D-5 EXOFF/FRZSW/FRZBM/SLVEN/SHEN masks");
        for(var name:java.util.List.of("EXOFF","FRZSW","FRZBM","SLVEN","SHEN"))
            check(simcrFields.get(name).sourcePage().equals("D-5 (PDF page 219)") &&
                  !simcrFields.get(name).writeOnceAfterReset(),
                "new SIMCR fields require exact physical page and no write-once claim");
        check(known.fields().stream().filter(x->x.writeOnceAfterReset()).count()==1 &&
              simcrFields.get("MM").writeOnceAfterReset() &&
              mc.register("SIMCR").resetValue==null,
            "only MM is write-once; no guessed SIMCR reset value");
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
        for(String malformed:new String[]{
                "PDF pages 220-219","PDF page 220-0",
                "PDF page 999999","PDF page 220-abc",
                "PDF page 220; PDF page 220"}) {
            check(!HardwareBitfieldDecoder.hasConcretePdfPageClaim(malformed),
                "malformed/duplicate physical page claim rejected: "+malformed);
        }
        check(known.summary().contains("source-page-claimed MC68332") &&
            known.summary().contains("PDF edition/page claim UNVERIFIED"),
            "literal field decode cannot claim physical PDF identity proof");
        // Verified against NXP-hosted MC68332UM © Motorola 1995,
        // printed D-6/D-7 (physical PDF pages 220/221). Only modeled
        // configuration bits from a complete source-side literal; STATUS
        // SLIMP/SLOCK and reserved bits are intentionally not interpreted.
        var syncr=HardwareBitfieldDecoder.decode(mc,"SYNCR",0xa5a5,16);
        check(syncr.status()==HardwareBitfieldDecoder.Status.DECODED &&
            syncr.fields().size()==7 &&
            syncr.unspecifiedMask()==0x0078L,
            "SYNCR 7 known configuration fields; two status and reserved bits UNKNOWN");
        var syncrFields=new java.util.HashMap<String,HardwareBitfieldDecoder.FieldEvidence>();
        for(var field:syncr.fields())
            check(syncrFields.put(field.name(),field)==null,
                "SYNCR sourced field names unique");
        check(syncrFields.get("W").mask()==0x8000 &&
            syncrFields.get("W").value()==1 &&
            syncrFields.get("X").mask()==0x4000 &&
            syncrFields.get("X").value()==0 &&
            syncrFields.get("Y").mask()==0x3f00 &&
            syncrFields.get("Y").value()==0x25,
            "SYNCR W/X/Y fields must match MC68332UM D-6 bit positions");
        check(syncrFields.get("EDIV").mask()==0x0080 &&
            syncrFields.get("EDIV").value()==1 &&
            syncrFields.get("RSTEN").mask()==0x0004 &&
            syncrFields.get("RSTEN").value()==1 &&
            syncrFields.get("STSIM").mask()==0x0002 &&
            syncrFields.get("STSIM").value()==0 &&
            syncrFields.get("STEXT").mask()==0x0001 &&
            syncrFields.get("STEXT").value()==1,
            "SYNCR clock-divider/reset/stop configuration bit positions");
        check(syncrFields.keySet().stream().noneMatch(x->
                x.equals("SLIMP")||x.equals("SLOCK")) &&
            syncr.summary().contains("other bits UNINTERPRETED (mask 0x0078)") &&
            syncr.summary().contains("not proven hardware state or write order"),
            "read-only hardware lock/limp status is not inferred from a literal");
        for(var field:syncr.fields()){
            check(field.sourcePage().equals("D-6 (PDF page 220)") ||
                field.sourcePage().equals("D-7 (PDF page 221)"),
                "every SYNCR field must identify one exact printed/physical page");
            check(!field.writeOnceAfterReset(),
                "SYNCR fields must not acquire SIMCR MM write-once policy");
        }
        var syncrMetadata=mc.register("SYNCR");
        check(syncrMetadata!=null &&
            syncrMetadata.offset==0x0a04 &&
            syncrMetadata.resetValue==null &&
            syncrMetadata.sourcePage.equals("D-6/D-7 (PDF pages 220-221)") &&
            syncrMetadata.source.contains("Motorola 1995"),
            "SYNCR must keep exact address, claimed edition/page and UNKNOWN reset");
        check(HardwareBitfieldDecoder.decode(cpu,"SYNCR",0xa5a5,16).status()
                ==HardwareBitfieldDecoder.Status.DEVICE_NOT_SELECTED &&
            HardwareBitfieldDecoder.decode(mc,"SYNCR",0xa5a5,8).status()
                ==HardwareBitfieldDecoder.Status.WIDTH_MISMATCH &&
            HardwareBitfieldDecoder.decode(mc,"SYNCR",null,16).status()
                ==HardwareBitfieldDecoder.Status.VALUE_UNKNOWN,
            "generic CPU32, byte partial writes and unknown SYNCR remain untyped");
        var sourceZero=HardwareBitfieldDecoder.decode(mc,"SYNCR",0,16);
        check(sourceZero.status()==HardwareBitfieldDecoder.Status.DECODED &&
            sourceZero.fields().stream().allMatch(field->field.value()==0) &&
            mc.register("SYNCR").resetValue==null,
            "decoded zero value from a synthetic literal is NOT a reset assertion");
        var syp=HardwareBitfieldDecoder.decode(mc,"SYPCR",0xac,8);
        check(syp.status()==HardwareBitfieldDecoder.Status.DECODED &&
                syp.fields().size()==6 && syp.unspecifiedMask()==0 &&
                syp.fields().stream().allMatch(x->x.writeOnceAfterReset()) &&
                syp.summary().contains("first accepted write NOT PROVEN"),
            "SYPCR six 8-bit sourced fields with WRITE-ONCE caution");
        var sypVals=new java.util.HashMap<String,Integer>();
        for(var v:syp.fields())sypVals.put(v.name(),v.value());
        check(sypVals.get("SWE")==1 && sypVals.get("SWP")==0 &&
                sypVals.get("SWT")==2 && sypVals.get("HME")==1 &&
                sypVals.get("BME")==1 && sypVals.get("BMT")==0 &&
                mc.register("SYPCR").resetValue==null,
            "SYPCR 0xAC masked static values, not reset or runtime");
        check(HardwareBitfieldDecoder.decode(mc,"SYPCR",0xac,16).status()
                ==HardwareBitfieldDecoder.Status.WIDTH_MISMATCH &&
              HardwareBitfieldDecoder.decode(mc,"SYPCR",0x1ac,8).status()
                ==HardwareBitfieldDecoder.Status.VALUE_OUT_OF_RANGE &&
              HardwareBitfieldDecoder.decode(cpu,"SYPCR",0xac,8).status()
                ==HardwareBitfieldDecoder.Status.DEVICE_NOT_SELECTED,
            "reject word write, out-of-range byte and generic CPU32");
        var pic=HardwareBitfieldDecoder.decode(mc,"PICR",0x07ff,16);
        check(pic.fields().size()==2 &&
                pic.unspecifiedMask()==0xf800 &&
                pic.fields().stream().anyMatch(x->
                    x.name().equals("PIRQL") && x.value()==7) &&
                pic.fields().stream().anyMatch(x->
                    x.name().equals("PIV") && x.value()==0xff) &&
                pic.summary().contains("no active interrupt"),
            "PICR seven request levels/8-bit vector candidates, no ISR execution");
        var pit=HardwareBitfieldDecoder.decode(mc,"PITR",0x01a5,16);
        check(pit.fields().size()==2 &&
                pit.unspecifiedMask()==0xfe00 &&
                pit.fields().stream().anyMatch(x->
                    x.name().equals("PTP") && x.value()==1) &&
                pit.fields().stream().anyMatch(x->
                    x.name().equals("PITM") && x.value()==0xa5) &&
                pit.summary().contains("no active interrupt"),
            "PITR static prescaler/timing modulus without running timer");
        check(HardwareBitfieldDecoder.decode(mc,"PICR",0x07ff,8).status()
                ==HardwareBitfieldDecoder.Status.WIDTH_MISMATCH &&
              HardwareBitfieldDecoder.decode(mc,"PITR",null,16).status()
                ==HardwareBitfieldDecoder.Status.VALUE_UNKNOWN &&
              HardwareBitfieldDecoder.decode(mc,"SWSR",0x55,8).status()
                ==HardwareBitfieldDecoder.Status.NO_SOURCED_FIELDS,
            "partial PICR, unknown PITR, and SWSR service sequence never decoded as fields");
        // Public records are also consumed by evidence renderers: do
        // not accept fabricated sourced fields independent of decode().
        {
            var badEvidence=new java.util.ArrayList<Runnable>();
            badEvidence.add(()->new HardwareBitfieldDecoder.FieldEvidence(
                "FAKE",0,0,"D-6 (PDF page 220)",false));
            badEvidence.add(()->new HardwareBitfieldDecoder.FieldEvidence(
                "FAKE",0x40,2,"D-6 (PDF page 220)",false));
            badEvidence.add(()->new HardwareBitfieldDecoder.FieldEvidence(
                "FAKE",0x40,1,"PDF page UNKNOWN",false));
            badEvidence.add(()->new HardwareBitfieldDecoder.FieldEvidence(
                "FAKE",0x40,1,"PDF page 220; PDF page 221",false));
            badEvidence.add(()->new HardwareBitfieldDecoder.FieldEvidence(
                "FAKE",0x40,1,"PDF pages 220-219",false));
            badEvidence.add(()->new HardwareBitfieldDecoder.FieldEvidence(
                "BAD\\nNAME",0x40,1,"D-6 (PDF page 220)",false));
            var forgedMm=new HardwareBitfieldDecoder.FieldEvidence(
                "MM",0x40,1,"D-6 (PDF page 220)",true);
            var forgedSupv=new HardwareBitfieldDecoder.FieldEvidence(
                "SUPV",0x80,0,"D-6 (PDF page 220)",false);
            badEvidence.add(()->new HardwareBitfieldDecoder.Result(
                HardwareBitfieldDecoder.Status.DECODED,"MC68332","SIMCR",
                null,16,java.util.List.of(forgedMm),0xffbf));
            badEvidence.add(()->new HardwareBitfieldDecoder.Result(
                HardwareBitfieldDecoder.Status.DECODED,"MC68332","SIMCR",
                0x40ca,8,java.util.List.of(forgedMm),0xbf));
            badEvidence.add(()->new HardwareBitfieldDecoder.Result(
                HardwareBitfieldDecoder.Status.DECODED,"MC68332","SIMCR",
                0x40ca,16,java.util.List.of(forgedMm),0));
            badEvidence.add(()->new HardwareBitfieldDecoder.Result(
                HardwareBitfieldDecoder.Status.DECODED,"MC68332","SIMCR",
                0x40ca,16,java.util.List.of(forgedSupv),0xff7f));
            badEvidence.add(()->new HardwareBitfieldDecoder.Result(
                HardwareBitfieldDecoder.Status.DECODED,"MC68332","SIMCR",
                0x40ca,16,java.util.List.of(forgedMm,forgedMm),0xffbf));
            badEvidence.add(()->new HardwareBitfieldDecoder.Result(
                HardwareBitfieldDecoder.Status.NO_SOURCED_FIELDS,
                "MC68332","SWSR",0x55,8,
                java.util.List.of(forgedMm),0));
            badEvidence.add(()->new HardwareBitfieldDecoder.Result(
                HardwareBitfieldDecoder.Status.DECODED,"MC68332","SIMCR",
                0x40ca,16,null,0xffbf));
            for(Runnable forged:badEvidence){
                boolean denied=false;
                try{forged.run();}
                catch(IllegalArgumentException expected){denied=true;}
                check(denied,
                    "forged bitfield value, mask, PDF page or interpreted remainder rejected");
            }
            var validEvidence=new HardwareBitfieldDecoder.Result(
                HardwareBitfieldDecoder.Status.DECODED,"MC68332","SIMCR",
                0x40ca,16,java.util.List.of(forgedMm),0xffbf);
            check(validEvidence.fields().size()==1 &&
                validEvidence.unspecifiedMask()==0xffbf &&
                validEvidence.summary().contains("UNINTERPRETED"),
                "partial documented mask retains all unspecified bits and claim-only provenance");
        }
        System.out.println("HardwareBitfieldDecoderSelfTest OK");
    }
}
