package ghidrassist.hardware;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** GA-06/10/16 deterministic diagram-mask cross-check; never authorizes Apply. */
public final class HardwareBitfieldLayoutWitnessSelfTest {
    private HardwareBitfieldLayoutWitnessSelfTest(){}
    private static int checks;
    private static void check(boolean condition,String why) {
        checks++;
        if(!condition)throw new AssertionError(why);
    }
    private static void rejected(Runnable test,String why) {
        boolean denied=false;
        try{test.run();}catch(IllegalArgumentException expected){denied=true;}
        check(denied,why);
    }
    private static String diagram219() {
        return "MC68332 USER'S MANUAL D-5\n"+
            "D.2.1 SIMCR — Module Configuration Register $YFFA00\n"+
            "15 14 13 12 11 10 9 8 7 6 5 4 3 0\n"+
            "EXOFF FRZSW FRZBM 0 SLVEN 0 SHEN SUPV MM 0 0 IARB\n";
    }
    private static String diagram220() {
        return "MC68332 USER'S MANUAL D-6\n"+
            "D.2.3 SYNCR — Clock Synthesizer Control Register $YFFA04\n"+
            "15 14 13 8 7 6 5 4 3 2 1 0\n"+
            "W X Y EDIV 0 0 SLIMP SLOCK RSTEN STSIM STEXT\n";
    }
    private static HardwareBitfieldLayoutWitness.Row row(
            HardwareBitfieldLayoutWitness.Report report,String name) {
        return report.rows().stream().filter(r->r.diagram().field().equals(name))
            .findFirst().orElseThrow();
    }
    private static HardwareBitfieldLayoutWitness.Report republish(
            HardwareBitfieldLayoutWitness.Report baseline,
            List<HardwareBitfieldLayoutWitness.Row> rows,
            int matches,int mismatches,int missing) {
        return new HardwareBitfieldLayoutWitness.Report(
            baseline.device(),baseline.expectedPublisherPdfSha256(),
            rows,matches,mismatches,missing,baseline.unexpectedProfileFields());
    }
    public static void main(String[] args)throws Exception {
        var text=Map.of(219,diagram219(),220,diagram220());
        var profile=HardwareProfiles.mc68332();
        var report=HardwareBitfieldLayoutWitness.inspect(profile,text);
        check(report.allReviewedMasksMatch() &&
                report.rows().size()==15 && report.matches()==15 &&
                report.unexpectedProfileFields()==0 &&
                report.expectedPublisherPdfSha256().equals(
                    HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256),
            "All 15 explicit MC68332 fields match independently reviewed bit positions");
        check(row(report,"MM").diagram().mask()==0x0040 &&
                row(report,"SHEN").diagram().mask()==0x0300 &&
                row(report,"IARB").diagram().mask()==0x000f &&
                row(report,"Y").diagram().mask()==0x3f00 &&
                row(report,"RSTEN").diagram().mask()==0x0004,
            "Specific reviewed SIMCR/SYNCR bit positions and widths");
        check(row(report,"SUPV").diagram().physicalDiagramPage()==219 &&
                row(report,"SUPV").claimedDescriptionPages().equals("220") &&
                row(report,"RSTEN").diagram().physicalDiagramPage()==220 &&
                row(report,"RSTEN").claimedDescriptionPages().equals("221"),
            "Description page is explicitly distinct from bit-diagram page");
        long simBits=report.rows().stream()
            .filter(r->r.diagram().register().equals("SIMCR"))
            .mapToLong(r->r.diagram().mask()).reduce(0,(a,b)->a|b);
        long synBits=report.rows().stream()
            .filter(r->r.diagram().register().equals("SYNCR"))
            .mapToLong(r->r.diagram().mask()).reduce(0,(a,b)->a|b);
        check(simBits==0xebcf && ((~simBits)&0xffff)==0x1430 &&
                synBits==0xff87 && ((~synBits)&0xffff)==0x0078,
            "Reserved/unknown bit masks remain untyped and exact");
        String markdown=report.markdown();
        check(markdown.contains("DIAGRAM POSITION REVIEW ONLY") &&
                markdown.contains("Review/Apply") &&
                markdown.contains("| SIMCR | MM | 6 | 0x0040 | 0x0040 | D-5 / PDF 219 | 219-220 |") &&
                markdown.contains("| SYNCR | RSTEN | 2 | 0x0004 | 0x0004 | D-6 / PDF 220 | 221 |") &&
                markdown.contains("no PDF identity"),
            "Read-only report retains separate diagram/description folios and caveat");
        var claims=HardwareBitfieldSourceLedger.inspect(profile).entries();
        var corrupted=new ArrayList<>(claims);
        int maskIndex=-1;
        for(int i=0;i<corrupted.size();i++)
            if(corrupted.get(i).register().equals("SIMCR") &&
                    corrupted.get(i).field().equals("MM"))maskIndex=i;
        check(maskIndex>=0,"Mask target in MC68332 ledger exists");
        var original=corrupted.get(maskIndex);
        corrupted.set(maskIndex,new HardwareBitfieldSourceLedger.Entry(
            "SIMCR","MM",0x0080L,original.firstPage(),
            original.lastPage(),original.label()));
        var mismatch=HardwareBitfieldLayoutWitness.compareClaims(
            "MC68332",corrupted,text);
        check(mismatch.mismatches()==1 &&
                mismatch.matches()==14 &&
                row(mismatch,"MM").state()==
                    HardwareBitfieldLayoutWitness.State.MASK_DIFFERS_FROM_DIAGRAM &&
                !mismatch.allReviewedMasksMatch(),
            "Bit mask drift is detected even if the field name and PDF page still match");
        var missing=new ArrayList<>(claims);
        missing.removeIf(r->r.field().equals("SHEN"));
        var omitted=HardwareBitfieldLayoutWitness.compareClaims(
            "MC68332",missing,text);
        check(omitted.missingOrUnverifiable()==1 &&
                row(omitted,"SHEN").state()==
                    HardwareBitfieldLayoutWitness.State.FIELD_CLAIM_MISSING,
            "Omitted reviewed field never counted as verified");
        var extra=new ArrayList<>(claims);
        extra.add(new HardwareBitfieldSourceLedger.Entry(
            "SIMCR","MADE_UP_BIT",0x0001L,219,219,"PDF page 219"));
        check(HardwareBitfieldLayoutWitness.compareClaims(
                "MC68332",extra,text).unexpectedProfileFields()==1 &&
                !HardwareBitfieldLayoutWitness.compareClaims(
                    "MC68332",extra,text).allReviewedMasksMatch(),
            "Unsupported new profile field blocks full layout claim");
        var badDiagram=HardwareBitfieldLayoutWitness.inspect(profile,
            Map.of(219,diagram219().replace(" SHEN "," FAKE "),
                220,diagram220()));
        check(badDiagram.missingOrUnverifiable()==8 &&
                row(badDiagram,"MM").state()==
                    HardwareBitfieldLayoutWitness.State.DIAGRAM_TEXT_UNAVAILABLE,
            "Edited SIMCR diagram cannot pass even with unchanged names and masks");
        var wrongFolio=HardwareBitfieldLayoutWitness.inspect(profile,
            Map.of(220,diagram219(),219,diagram220()));
        check(wrongFolio.matches()==0 &&
                wrongFolio.missingOrUnverifiable()==15,
            "Matching diagram text on the wrong physical folio is not accepted");
        check(HardwareBitfieldLayoutWitness.inspect(
                HardwareProfiles.cpu32Family(),text).rows().isEmpty(),
            "Generic CPU32 has no silently selected MC68332 bitfield index");
        rejected(()->HardwareBitfieldLayoutWitness.inspect(profile,
            Map.of(0,"bad")),"Physical PDF folios must be one-based");
        rejected(()->HardwareBitfieldLayoutWitness.inspect(profile,
            Map.of(219,"X".repeat(HardwareBitfieldLayoutWitness.MAX_PAGE_CHARS+1))),
            "Unbounded extracted page text rejected");
        rejected(()->HardwareBitfieldLayoutWitness.compareClaims(
            "MC68332",List.of(claims.get(0),claims.get(0)),text),
            "Duplicate source field from profile refused");
        check(report.rows().equals(List.copyOf(report.rows())),
            "Comparison returns fixed-order immutable reviewed rows");
        boolean immutable=false;
        try{report.rows().clear();}
        catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"Source-only report immutable");

        check(republish(report,report.rows(),report.matches(),
                report.mismatches(),report.missingOrUnverifiable()).equals(report),
            "Canonical publisher diagram comparison round-trips");
        rejected(()->new HardwareBitfieldLayoutWitness.DiagramField(
            "SIMCR","INVALID",-1,0,219,"D-5"),
            "Negative reviewed diagram bit position cannot manufacture mask");
        rejected(()->new HardwareBitfieldLayoutWitness.DiagramField(
            "SIMCR","INVALID",15,16,219,"D-5"),
            "Diagram bit outside 16-bit register rejected");
        var mm=row(report,"MM");
        rejected(()->new HardwareBitfieldLayoutWitness.Row(
            mm.diagram(),mm.diagram().mask()^0x0080L,
            mm.claimedDescriptionPages(),
            HardwareBitfieldLayoutWitness.State.CLAIM_MATCHES_REVIEWED_DIAGRAM),
            "Changed mask cannot retain positive diagram agreement");
        rejected(()->new HardwareBitfieldLayoutWitness.Row(
            mm.diagram(),mm.diagram().mask(),
            mm.claimedDescriptionPages(),
            HardwareBitfieldLayoutWitness.State.MASK_DIFFERS_FROM_DIAGRAM),
            "Correct mask cannot be presented as a mismatch");
        rejected(()->new HardwareBitfieldLayoutWitness.Row(
            mm.diagram(),null,mm.claimedDescriptionPages(),
            HardwareBitfieldLayoutWitness.State.CLAIM_MATCHES_REVIEWED_DIAGRAM),
            "Absent mask cannot claim matched publisher diagram");
        rejected(()->new HardwareBitfieldLayoutWitness.Row(
            mm.diagram(),null,mm.claimedDescriptionPages(),
            HardwareBitfieldLayoutWitness.State.FIELD_CLAIM_MISSING),
            "Missing profile claim cannot inherit physical page range");
        var alteredRow=new ArrayList<>(report.rows());
        alteredRow.set(0,new HardwareBitfieldLayoutWitness.Row(
            mm.diagram(),mm.profileMask(),mm.claimedDescriptionPages(),mm.state()));
        rejected(()->republish(report,alteredRow,report.matches(),
                report.mismatches(),report.missingOrUnverifiable()),
            "Different reviewed field order cannot certify full 15-row diagram");
        var reversed=new ArrayList<>(report.rows());
        Collections.reverse(reversed);
        rejected(()->republish(report,reversed,report.matches(),
                report.mismatches(),report.missingOrUnverifiable()),
            "Reordered diagram rows denied");
        rejected(()->republish(report,report.rows().subList(0,14),
                report.matches(),report.mismatches(),
                report.missingOrUnverifiable()),
            "Missing reviewed diagram cannot claim full match");
        rejected(()->republish(report,report.rows(),report.matches()-1,
                report.mismatches()+1,report.missingOrUnverifiable()),
            "Forged positive and mismatch counters rejected");
        rejected(()->new HardwareBitfieldLayoutWitness.Report(
            report.device(),"0".repeat(64),report.rows(),report.matches(),
            report.mismatches(),report.missingOrUnverifiable(),
            report.unexpectedProfileFields()),
            "Forged publisher digest cannot inherit reviewed diagram results");
        var generic=HardwareBitfieldLayoutWitness.inspect(
            HardwareProfiles.cpu32Family(),text);
        rejected(()->new HardwareBitfieldLayoutWitness.Report(
            generic.device(),HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256,
            List.of(),0,0,0,0),
            "Generic CPU32 scope cannot borrow MC68332 PDF identity");
        rejected(()->republish(report,null,report.matches(),
                report.mismatches(),report.missingOrUnverifiable()),
            "Null report rows produce explicit invalid-input refusal");

        if(args.length!=0 && args.length!=2)
            throw new IllegalArgumentException(
                "Expected exactly the pinned publisher PDF pages 219 and 220");
        if(args.length==2) {
            var publisher=HardwareBitfieldLayoutWitness.inspect(profile,
                Map.of(219,Files.readString(Path.of(args[0])),
                       220,Files.readString(Path.of(args[1]))));
            // CI verifies the NXP publisher bytes and exact SHA before
            // this point; a supplied string is NEVER trusted by this API.
            check(publisher.allReviewedMasksMatch(),
                "Official MC68332UM physical D-5/D-6 diagram extracted text/15 masks");
            System.out.println("PINNED MC68332UM PDF BIT DIAGRAM PASS: "+
                "SIMCR 8 + SYNCR 7 layout positions; page claims separated");
        }
        System.out.println("HardwareBitfieldLayoutWitnessSelfTest PASS checks="+checks);
    }
}
