package ghidrassist.hardware;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Separate 10-field MCU protection/periodic-timer source witness.
 * Source inputs synthetic unless official 265-page PDF has already
 * passed the pinned-SHA test earlier in the same Actions job.
 */
public final class HardwareSimProtectionTimerWitnessSelfTest {
    private HardwareSimProtectionTimerWitnessSelfTest(){}
    private static int checks;
    private static void ok(boolean b,String why){checks++;if(!b)throw new AssertionError(why);}
    private static void refuses(Runnable action,String why){
        boolean denied=false;
        try{action.run();}catch(IllegalArgumentException expected){denied=true;}
        ok(denied,why);
    }
    private static String fake(int page) {
        StringBuilder text=new StringBuilder(
            "MC68332 USER'S MANUAL D-"+(page-214)+"\n");
        if(page==224)text.append(
            "D.2.12 SYPCR — System Protection Control Register $YFFA21\n"+
            "15 8 7 6 5 4 3 2 1 0\n"+
            "NOT USED SWE SWP SWT HME BME BMT\n");
        else text.append(
            "D.2.13 PICR — Periodic Interrupt Control Register $YFFA22\n"+
            "15 14 13 12 11 10 8 7 0\n"+
            "0 0 0 0 0 PIRQL PIV\n");
        for(var ref:HardwareSimProtectionTimerWitness.reviewed()) {
            if(ref.physicalPage()!=page)continue;
            if(ref.register().equals("PITR"))continue;
            text.append(ref.heading()).append("\n0 = ")
                .append(ref.meaning()).append(".\n");
        }
        if(page==225) {
            text.append("D.2.14 PITR — Periodic Interrupt Timer Register $YFFA24\n"+
                "15 14 13 12 11 10 9 8 7 0\n"+
                "0 0 0 0 0 0 0 PTP PITM\n");
            for(var ref:HardwareSimProtectionTimerWitness.reviewed()) {
                if(!ref.register().equals("PITR"))continue;
                text.append(ref.heading()).append("\n0 = ")
                    .append(ref.meaning()).append(".\n");
            }
            text.append("D.2.15 SWSR — Software Service Register $YFFA27\n");
        }
        return text.toString();
    }
    private static Map<Integer,String> fakePdf(){
        return Map.of(224,fake(224),225,fake(225));
    }
    private static HardwareSimProtectionTimerWitness.Row row(
            HardwareSimProtectionTimerWitness.Report report,String name) {
        return report.rows().stream().filter(x->
            x.reviewed().key().equals(name)).findFirst().orElseThrow();
    }
    private static List<HardwareSimProtectionTimerWitness.Claim> claims() {
        var profile=HardwareProfiles.mc68332();
        var out=new ArrayList<HardwareSimProtectionTimerWitness.Claim>();
        for(var register:List.of("SYPCR","PICR","PITR")) {
            var r=profile.register(register);
            for(var field:r.fields)out.add(
                new HardwareSimProtectionTimerWitness.Claim(r.name,
                    field.name,Integer.toUnsignedLong(field.mask),r.offset,
                    r.widthBits,field.sourcePage,field.writeOnceAfterReset));
        }
        return out;
    }
    public static void main(String[] args)throws Exception {
        var profile=HardwareProfiles.mc68332();
        var good=HardwareSimProtectionTimerWitness.inspect(profile,fakePdf());
        ok(good.allTenCandidatesMatch() && good.rows().size()==10 &&
            good.expectedPublisherSha256().equals(
                HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256),
            "All 10 explicitly selected MC68332 page/diagram/meaning candidates");
        ok(row(good,"SYPCR/SWE").reviewed().mask()==0x80 &&
            row(good,"SYPCR/SWT").reviewed().mask()==0x30 &&
            row(good,"SYPCR/BMT").reviewed().mask()==0x03 &&
            row(good,"PICR/PIRQL").reviewed().mask()==0x0700 &&
            row(good,"PICR/PIV").reviewed().mask()==0xff &&
            row(good,"PITR/PTP").reviewed().mask()==0x0100 &&
            row(good,"PITR/PITM").reviewed().mask()==0xff,
            "Independently reviewed 8/16-bit diagram masks");
        ok(good.rows().stream().filter(x->x.reviewed().writeOnce()).count()==6 &&
            good.rows().stream().filter(x->x.reviewed().physicalPage()==224).count()==6 &&
            good.rows().stream().filter(x->x.reviewed().physicalPage()==225).count()==4,
            "Only six SYPCR write-once fields; two distinct printed/physical folios");
        ok(good.markdown().contains("NO PDF AUTHENTICATION") &&
            good.markdown().contains("active PIT interrupt/vector") &&
            good.markdown().contains("D-11"),
            "Source evidence warnings include no runtime timer/interrupt claims");
        var missing=new HashMap<>(fakePdf());missing.remove(224);
        ok(row(HardwareSimProtectionTimerWitness.inspect(profile,missing),
            "SYPCR/SWE").state()==
            HardwareSimProtectionTimerWitness.State.PAGE_TEXT_MISSING,
            "Missing exact source page cannot inherit an adjacent heading");
        var swapped=Map.of(224,fake(225),225,fake(224));
        ok(row(HardwareSimProtectionTimerWitness.inspect(profile,swapped),
            "SYPCR/SWE").state()==
            HardwareSimProtectionTimerWitness.State.PAGE_IDENTITY_MISMATCH,
            "Matching source text on swapped physical folio never accepted");
        var altered=new HashMap<>(fakePdf());
        altered.put(224,altered.get(224).replace(
            "SWT[1:0] - Software Watchdog Timing","SWT[1:0] - fake"));
        ok(row(HardwareSimProtectionTimerWitness.inspect(profile,altered),
            "SYPCR/SWT").state()==
            HardwareSimProtectionTimerWitness.State.FIELD_HEADING_MISSING,
            "Bit token without meaning-heading rejected");
        altered=new HashMap<>(fakePdf());
        altered.put(225,altered.get(225).replace(
            "interrupt vector number supplied by the SIM","fictional vector"));
        ok(row(HardwareSimProtectionTimerWitness.inspect(profile,altered),
            "PICR/PIV").state()==
            HardwareSimProtectionTimerWitness.State.MEANING_NOT_NEAR_HEADING,
            "Wrong described interrupt vector cannot be cited");
        altered=new HashMap<>(fakePdf());
        altered.put(225,altered.get(225).replace("PTP PITM","PTP FAKE"));
        ok(row(HardwareSimProtectionTimerWitness.inspect(profile,altered),
            "PITR/PITM").state()==
            HardwareSimProtectionTimerWitness.State.DIAGRAM_LABELS_MISSING,
            "Edited PITR diagram row cannot verify a correct field heading");
        // Additional negative tests follow outside the synthetic matching row.
        var source=claims();
        var tampered=new ArrayList<>(source);
        int at=-1;
        for(int i=0;i<tampered.size();i++)
            if(tampered.get(i).key().equals("PICR/PIRQL"))at=i;
        ok(at>=0,"PICR/PIRQL in selected source profile");
        var old=tampered.get(at);
        tampered.set(at,new HardwareSimProtectionTimerWitness.Claim(
            old.register(),old.field(),0x0300,old.offset(),old.widthBits(),
            old.pageLabel(),old.writeOnce()));
        ok(row(HardwareSimProtectionTimerWitness.compareClaims(
            "MC68332",tampered,fakePdf()),"PICR/PIRQL").state()==
            HardwareSimProtectionTimerWitness.State.MASK_WIDTH_OFFSET_OR_POLICY_DIFFERENT,
            "Wrong 16-bit priority mask refused despite matching PDF words");
        tampered=new ArrayList<>(source);
        tampered.removeIf(x->x.key().equals("SYPCR/BME"));
        ok(row(HardwareSimProtectionTimerWitness.compareClaims(
            "MC68332",tampered,fakePdf()),"SYPCR/BME").state()==
            HardwareSimProtectionTimerWitness.State.PROFILE_FIELD_MISSING,
            "Missing claimed watchdog monitor field never fabricated");
        tampered=new ArrayList<>(source);
        tampered.add(new HardwareSimProtectionTimerWitness.Claim(
            "PICR","FAKE",0x8000,0x0a22,16,"D-11 (PDF page 225)",false));
        ok(HardwareSimProtectionTimerWitness.compareClaims(
            "MC68332",tampered,fakePdf()).unexpectedClaims()==1,
            "Unsupported additional field cannot hide in 10 positives");
        ok(HardwareSimProtectionTimerWitness.inspect(
            HardwareProfiles.cpu32Family(),fakePdf()).rows().isEmpty(),
            "Generic CPU32 has no MC68332 SYPCR/PICR/PITR source");
        refuses(()->HardwareSimProtectionTimerWitness.inspect(profile,
            Map.of(0,"unsafe")),"Zero PDF page rejected");
        refuses(()->HardwareSimProtectionTimerWitness.inspect(profile,
            Map.of(224,"A".repeat(
                HardwareSimProtectionTimerWitness.MAX_PAGE_CHARS+1))),
            "Oversized document source refused");
        boolean immutable=false;
        try{good.rows().clear();}catch(UnsupportedOperationException expected){
            immutable=true;
        }
        ok(immutable,"Evidence rows are immutable");
        if(args.length!=0 && args.length!=2)
            throw new IllegalArgumentException("Expected pinned physical pages 224/225");
        if(args.length==2) {
            var publisher=HardwareSimProtectionTimerWitness.inspect(profile,
                Map.of(224,Files.readString(Path.of(args[0])),
                    225,Files.readString(Path.of(args[1]))));
            ok(publisher.allTenCandidatesMatch(),
                "NXP SHA-pinned MC68332UM exact D-10/D-11 pages: 10 field headings and meanings");
            for(var entry:publisher.rows())
                System.out.println("PINNED_SIM_PROTECTION_FIELD "+
                    entry.reviewed().key()+" PDF="+entry.reviewed().physicalPage()+
                    " mask=0x"+Long.toHexString(entry.reviewed().mask())+
                    " excerptSHA256="+entry.excerptSha256());
            System.out.println("PINNED MC68332UM SYPCR/PICR/PITR SOURCE PASS fields=10");
        }
        System.out.println("HardwareSimProtectionTimerWitnessSelfTest PASS checks="+checks);
    }
}
