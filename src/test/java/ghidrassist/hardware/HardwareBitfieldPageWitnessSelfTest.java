package ghidrassist.hardware;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Deterministic synthetic + independent pinned publisher-folio CI proof. */
public final class HardwareBitfieldPageWitnessSelfTest {
    private HardwareBitfieldPageWitnessSelfTest(){}
    private static int assertions;
    private static void check(boolean value,String label) {
        assertions++;
        if(!value)throw new AssertionError(label);
    }
    private static void denied(Runnable task,String label){
        boolean refused=false;
        try{task.run();}catch(IllegalArgumentException expected){refused=true;}
        check(refused,label);
    }
    private static HardwareBitfieldPageWitness.Row find(
            HardwareBitfieldPageWitness.Result result,String field) {
        return result.rows().stream().filter(r->r.field().equals(field))
            .findFirst().orElseThrow();
    }
    private static HardwareBitfieldPageWitness.Result republish(
            HardwareBitfieldPageWitness.Result reference,
            List<HardwareBitfieldPageWitness.Row> rows,
            int matched,int missing,int ambiguous) {
        return new HardwareBitfieldPageWitness.Result(
            reference.profile(),reference.manualUrl(),
            reference.editionClaim(),reference.publisherPdfSha256(),
            reference.sourceEntries(),matched,missing,ambiguous,rows);
    }
    public static void main(String[] args)throws Exception {
        var device=HardwareProfiles.mc68332();
        var text=new TreeMap<Integer,String>();
        text.put(219,"Appendix D-5 SIMCR EXOFF FRZSW FRZBM SLVEN SHEN");
        text.put(220,"D-6 SIMCR SUPV IARB MM SYNCR EDIV");
        text.put(221,"D-7 SYNCR RSTEN STSIM STEXT");
        var audit=HardwareBitfieldPageWitness.inspect(device,text);
        check(audit.profile().equals("MC68332") &&
                audit.manualUrl().equals(HardwareProfiles.MC68332_MANUAL) &&
                audit.sourceEntries()==15 &&
                audit.rows().size()==15,
            "All 15 explicitly scoped MC68332 bitfield page claims");
        check(find(audit,"SHEN").state()==
                HardwareBitfieldPageWitness.State.NAME_ON_CLAIMED_PAGE &&
                find(audit,"SHEN").matchedPhysicalPages().equals(java.util.List.of(219)),
            "Only exact cited physical PDF page can witness a field name");
        check(find(audit,"STEXT").state()==
                HardwareBitfieldPageWitness.State.NAME_ON_CLAIMED_PAGE &&
                find(audit,"STEXT").matchedPhysicalPages().equals(java.util.List.of(221)),
            "Text token in PDF folio 221 belongs to SYNCR source claim");
        check(find(audit,"MM").state()==
                HardwareBitfieldPageWitness.State.SHORT_NAME_AMBIGUOUS &&
                find(audit,"W").state()==
                HardwareBitfieldPageWitness.State.SHORT_NAME_AMBIGUOUS &&
                find(audit,"X").state()==
                HardwareBitfieldPageWitness.State.SHORT_NAME_AMBIGUOUS &&
                find(audit,"Y").state()==
                HardwareBitfieldPageWitness.State.SHORT_NAME_AMBIGUOUS,
            "Short words cannot masquerade as independently verified field definitions");
        check(audit.matched()==11 && audit.ambiguous()==4 &&
                audit.missing()==0,
            "All 11 discriminative synthetic tokens matched exact claimed pages");
        String markdown=audit.markdown();
        check(markdown.contains("TEXT TOKEN ONLY") &&
                markdown.contains("Local/RAG PDF bytes are NOT authenticated") &&
                markdown.contains("| SIMCR | SHEN |") &&
                markdown.contains("| SYNCR | STEXT |") &&
                markdown.contains("MC68332") &&
                !markdown.contains("VERIFIED_BITFIELD_DEFINITION"),
            "Source report never upgrades text match to mask or PDF authentication");
        var wrong=new TreeMap<>(text);
        wrong.put(219,"SIMCR and SYNCR only; SHEN absent");
        wrong.put(221,"STEXT");
        // 'SHEN absent' still contains the exact token: use wholly absent text.
        wrong.put(219,"SIMCR EXOFF FRZSW FRZBM SLVEN");
        var shifted=HardwareBitfieldPageWitness.inspect(device,wrong);
        check(find(shifted,"SHEN").state()==
                HardwareBitfieldPageWitness.State.NAME_NOT_ON_CLAIMED_PAGE &&
                find(shifted,"SHEN").matchedPhysicalPages().isEmpty(),
            "SHEN from another folio cannot repair a wrong D-5 page");
        var missing=HardwareBitfieldPageWitness.inspect(device,Map.of(
            219,text.get(219),220,text.get(220)));
        check(find(missing,"STEXT").state()==
                HardwareBitfieldPageWitness.State.PAGE_TEXT_MISSING &&
                missing.matched()<audit.matched(),
            "Absent PDF folio is not negative evidence that a bitfield is absent");
        var embedded=HardwareBitfieldPageWitness.inspect(device,Map.of(
            219,"prefixSHENsuffix but not the standalone token",
            220,"SYNCR",221,"STEXTENSION only"));
        check(find(embedded,"SHEN").state()==
                HardwareBitfieldPageWitness.State.NAME_NOT_ON_CLAIMED_PAGE &&
                find(embedded,"STEXT").state()==
                HardwareBitfieldPageWitness.State.NAME_NOT_ON_CLAIMED_PAGE,
            "Substring and prefixed identifiers rejected");
        check(HardwareBitfieldPageWitness.inspect(
                HardwareProfiles.cpu32Family(),text).rows().isEmpty(),
            "Generic CPU32 cannot inherit MC68332 document scope");
        denied(()->HardwareBitfieldPageWitness.inspect(device,
                Map.of(0,"fake source")),"Zero-based physical PDF pages rejected");
        denied(()->HardwareBitfieldPageWitness.inspect(device,
                Map.of(219,"x".repeat(
                    HardwareBitfieldPageWitness.MAX_PAGE_CHARS+1))),
            "Oversized extracted page rejected");
        denied(()->HardwareBitfieldPageWitness.inspect(null,text),
            "Missing selected MCU profile rejected");
        boolean immutable=false;
        try{audit.rows().clear();}catch(UnsupportedOperationException expected){
            immutable=true;
        }
        check(immutable,"Page witness rows immutable");

        // A public Row/Result is an untrusted source presentation boundary;
        // a caller cannot fabricate the selected publisher pin, 15 reviewed
        // identities, exact counters or a matching physical-folio list.
        check(republish(audit,audit.rows(),audit.matched(),audit.missing(),
                audit.ambiguous()).equals(audit),
            "Canonical physical page report reopens without dropped witnesses");
        var shen=find(audit,"SHEN");
        denied(()->new HardwareBitfieldPageWitness.Row(
            "SIMCR","SHEN",shen.mask(),219,219,
            HardwareBitfieldPageWitness.State.NAME_ON_CLAIMED_PAGE,List.of()),
            "Positive name token without a matching folio fails closed");
        denied(()->new HardwareBitfieldPageWitness.Row(
            "SIMCR","SHEN",shen.mask(),219,219,
            HardwareBitfieldPageWitness.State.PAGE_TEXT_MISSING,List.of(219)),
            "Missing physical page cannot carry positive source pages");
        denied(()->new HardwareBitfieldPageWitness.Row(
            "SIMCR","SHEN",shen.mask(),219,219,
            HardwareBitfieldPageWitness.State.NAME_ON_CLAIMED_PAGE,List.of(220)),
            "Claimed source folio outside exact range denied");
        denied(()->new HardwareBitfieldPageWitness.Row(
            "SIMCR","SHEN",shen.mask(),219,220,
            HardwareBitfieldPageWitness.State.NAME_ON_CLAIMED_PAGE,List.of(220,219)),
            "Unordered physical page witnesses cannot certify a field");
        denied(()->new HardwareBitfieldPageWitness.Row(
            "SIMCR","SHEN",shen.mask(),219,220,
            HardwareBitfieldPageWitness.State.NAME_ON_CLAIMED_PAGE,List.of(219,219)),
            "Duplicate physical page witnesses cannot certify a field");
        denied(()->new HardwareBitfieldPageWitness.Row(
            "SIMCR","SHEN",shen.mask(),219,219,
            HardwareBitfieldPageWitness.State.SHORT_NAME_AMBIGUOUS,List.of()),
            "Long discriminative field cannot be relabeled ambiguous");
        denied(()->republish(audit,audit.rows(),
                audit.matched()+1,audit.missing(),audit.ambiguous()),
            "Matched count must equal actual source rows");
        denied(()->republish(audit,audit.rows().subList(0,14),
                audit.matched(),audit.missing(),audit.ambiguous()),
            "A missing publisher field row cannot be presented as complete");
        var reversed=new ArrayList<>(audit.rows());
        java.util.Collections.reverse(reversed);
        denied(()->republish(audit,reversed,
                audit.matched(),audit.missing(),audit.ambiguous()),
            "Reordered reviewed field rows rejected");
        var altered=new ArrayList<>(audit.rows());
        altered.set(0,new HardwareBitfieldPageWitness.Row(
            altered.get(0).register(),altered.get(0).field(),
            altered.get(0).mask()^0x100,altered.get(0).firstPage(),
            altered.get(0).lastPage(),altered.get(0).state(),
            altered.get(0).matchedPhysicalPages()));
        denied(()->republish(audit,altered,
                audit.matched(),audit.missing(),audit.ambiguous()),
            "Forged bit-mask field source cannot inherit publisher identity");
        denied(()->new HardwareBitfieldPageWitness.Result(
            audit.profile(),audit.manualUrl(),audit.editionClaim(),
            "0".repeat(64),audit.sourceEntries(),audit.matched(),
            audit.missing(),audit.ambiguous(),audit.rows()),
            "Publisher digest claim must be the fixed reviewed pin");
        var generic=HardwareBitfieldPageWitness.inspect(
            HardwareProfiles.cpu32Family(),text);
        denied(()->new HardwareBitfieldPageWitness.Result(
            generic.profile(),HardwareProfiles.MC68332_MANUAL,
            generic.editionClaim(),generic.publisherPdfSha256(),
            0,0,0,0,List.of()),
            "Generic CPU32 report cannot borrow the MC68332 manual URL");
        denied(()->republish(audit,null,
                audit.matched(),audit.missing(),audit.ambiguous()),
            "Null rows must fail closed with explicit input error");

        if(args.length!=0 && args.length!=3)
            throw new IllegalArgumentException(
                "Expected exactly physical PDF pages 219, 220, 221");
        if(args.length==3) {
            var publisher=HardwareBitfieldPageWitness.inspect(device,Map.of(
                219,Files.readString(Path.of(args[0])),
                220,Files.readString(Path.of(args[1])),
                221,Files.readString(Path.of(args[2]))));
            // The pinned official PDF and its 265-page sequence must be
            // checked externally by this same CI workflow BEFORE running
            // this assertion. We only verify the actual extracted text
            // contains discriminative field names on their claimed folios.
            check(publisher.sourceEntries()==15 &&
                    find(publisher,"SHEN").state()==
                        HardwareBitfieldPageWitness.State.NAME_ON_CLAIMED_PAGE &&
                    find(publisher,"STEXT").state()==
                        HardwareBitfieldPageWitness.State.NAME_ON_CLAIMED_PAGE,
                "Actual SHA-verified MC68332UM: SHEN and STEXT cited folios");
            check(publisher.publisherPdfSha256().equals(
                    HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256),
                "Physical-page witnesses are strictly bound to reviewed publisher pin");
            System.out.println("MC68332UM PINNED PDF FIELD TEXT PASS: "+
                "page219 SHEN, page221 STEXT; text only, no mask/edition proof");
        }
        System.out.println("HardwareBitfieldPageWitnessSelfTest PASS checks="+assertions);
    }
}
