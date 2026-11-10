package ghidrassist.hardware;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * GA-06/10/16: not just field tokens — selected profile mask + separately
 * reviewed diagram position + exact physical description folio + nearby
 * documented meaning. Pinned byte authentication remains independent CI.
 */
public final class HardwareManualFieldExcerptEvidenceSelfTest {
    private HardwareManualFieldExcerptEvidenceSelfTest(){}
    private static int checks;
    private static void check(boolean b,String msg){
        checks++;if(!b)throw new AssertionError(msg);
    }
    private static void reject(Runnable f,String msg){
        boolean bad=false;
        try{f.run();}catch(IllegalArgumentException expected){bad=true;}
        check(bad,msg);
    }
    private static final String P=HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256;
    private static String page(int n) {
        StringBuilder b=new StringBuilder("MC68332 USER'S MANUAL D-"+(n-214)+"\n");
        if(n==219)b.append(
            "D.2.1 SIMCR — Module Configuration Register $YFFA00\n"+
            "15 14 13 12 11 10 9 8 7 6 5 4 3 0\n"+
            "EXOFF FRZSW FRZBM 0 SLVEN 0 SHEN SUPV MM 0 0 IARB\n");
        if(n==220)b.append(
            "D.2.3 SYNCR — Clock Synthesizer Control Register $YFFA04\n"+
            "15 14 13 8 7 6 5 4 3 2 1 0\n"+
            "W X Y EDIV 0 0 SLIMP SLOCK RSTEN STSIM STEXT\n");
        for(var r:HardwareManualFieldExcerptEvidence.reviewed())
            if(r.descriptionPage()==n)
                b.append(r.heading().replace(" - "," — ")).append("\n")
                    .append("0 = ").append(r.nearbyText()).append(".\n");
        return b.toString();
    }
    private static Map<Integer,String> synthetic(){
        return Map.of(219,page(219),220,page(220),221,page(221));
    }
    private static HardwareManualFieldExcerptEvidence.Citation find(
            HardwareManualFieldExcerptEvidence.Report report,String key){
        return report.citations().stream()
            .filter(x->x.reviewed().key().equals(key))
            .findFirst().orElseThrow();
    }
    public static void main(String[] args)throws Exception {
        var profile=HardwareProfiles.mc68332();
        var positive=HardwareManualFieldExcerptEvidence.inspect(profile,synthetic(),P);
        check(positive.allReviewedTextCandidatesMatch() &&
            positive.citations().size()==15 && positive.matches()==15 &&
            positive.unexpected()==0,
            "All 15 independently reviewed heading+meaning text candidates");
        check(find(positive,"SIMCR/MM").reviewed().diagramPage()==219 &&
            find(positive,"SIMCR/MM").reviewed().descriptionPage()==220 &&
            find(positive,"SIMCR/MM").reviewed().printedFolio().equals("D-6") &&
            find(positive,"SIMCR/MM").excerpt().contains("INTERNAL MODULES") &&
            find(positive,"SYNCR/RSTEN").reviewed().diagramPage()==220 &&
            find(positive,"SYNCR/RSTEN").reviewed().descriptionPage()==221,
            "Description page and independent mask diagram kept separate");
        check(find(positive,"SYNCR/W").state()==
                HardwareManualFieldExcerptEvidence.State.MATCHED_TEXT_CANDIDATE &&
            find(positive,"SYNCR/X").state()==
                HardwareManualFieldExcerptEvidence.State.MATCHED_TEXT_CANDIDATE &&
            find(positive,"SYNCR/Y").state()==
                HardwareManualFieldExcerptEvidence.State.MATCHED_TEXT_CANDIDATE,
            "Short W/X/Y source witnesses require full descriptive headings");
        check(!HardwareManualPublisherExcerptPins.allPinnedExcerptsMatch(positive) &&
            HardwareManualPublisherExcerptPins.expected("SIMCR","MM")!=null &&
            !HardwareManualPublisherExcerptPins.matches(
                find(positive,"SIMCR/MM")),
            "Plausible synthetic source text cannot claim 15 pinned publisher excerpts");
        check(positive.markdown().contains("PURE TEXT COMPARISON, NOT PDF AUTHENTICATION") &&
                positive.markdown().contains("Motorola 1995") &&
                positive.markdown().contains("SIMCR/MM") &&
                positive.markdown().contains(P),
            "Complete source edition/pin/page context cannot claim PDF authentication");
        var missing=new HashMap<>(synthetic());
        missing.remove(221);
        var no221=HardwareManualFieldExcerptEvidence.inspect(profile,missing,P);
        check(find(no221,"SYNCR/RSTEN").state()==
                HardwareManualFieldExcerptEvidence.State.PAGE_TEXT_MISSING &&
            no221.matches()<15,
            "Missing description folio cannot borrow a nearby source page");
        var swapped=new HashMap<>(synthetic());
        swapped.put(221,synthetic().get(220));
        var wrong=HardwareManualFieldExcerptEvidence.inspect(profile,swapped,P);
        check(find(wrong,"SYNCR/STEXT").state()==
                HardwareManualFieldExcerptEvidence.State.FOLIO_OR_MODEL_HEADER_MISMATCH,
            "Wrong physical page with valid field token not a citation");
        var spoofed=new HashMap<>(synthetic());
        spoofed.put(220,spoofed.get(220).replace(
            "MM — Module Mapping","MM — fabricated meaning"));
        var forged=HardwareManualFieldExcerptEvidence.inspect(profile,spoofed,P);
        check(find(forged,"SIMCR/MM").state()==
                HardwareManualFieldExcerptEvidence.State.FIELD_HEADING_MISSING &&
            !forged.allReviewedTextCandidatesMatch(),
            "Bit token without reviewed section heading rejected");
        spoofed=new HashMap<>(synthetic());
        String changed=spoofed.get(220).replace(
            "Internal modules are addressed from $FFF000","another fact entirely");
        spoofed.put(220,changed);
        var noMeaning=HardwareManualFieldExcerptEvidence.inspect(profile,spoofed,P);
        check(find(noMeaning,"SIMCR/MM").state()==
                HardwareManualFieldExcerptEvidence.State.DESCRIPTION_NOT_NEAR_HEADING &&
            !noMeaning.allReviewedTextCandidatesMatch(),
            "Correct heading with changed meaning cannot pass");
        var far=new HashMap<>(synthetic());
        far.put(220,far.get(220).replace(
            "MM — Module Mapping\n0 = Internal modules are addressed from $FFF000",
            "MM — Module Mapping\n"+("OTHER CONTENT ".repeat(48))+
            "0 = Internal modules are addressed from $FFF000"));
        check(find(HardwareManualFieldExcerptEvidence.inspect(profile,far,P),
            "SIMCR/MM").state()==
                HardwareManualFieldExcerptEvidence.State.DESCRIPTION_NOT_NEAR_HEADING,
            "Meaning elsewhere on same physical page does not attach to a distant field");
        var badPin=HardwareManualFieldExcerptEvidence.inspect(
            profile,synthetic(),"0".repeat(64));
        check(!badPin.allReviewedTextCandidatesMatch() &&
            find(badPin,"SIMCR/MM").state()==
                HardwareManualFieldExcerptEvidence.State.PUBLISHER_PIN_UNMATCHED,
            "Different RAG index SHA cannot inherit publisher folio evidence");
        check(HardwareManualFieldExcerptEvidence.inspect(
            HardwareProfiles.cpu32Family(),synthetic(),P).citations().isEmpty(),
            "Generic CPU32 cannot inherit MC68332 source evidence");
        var claims=new ArrayList<>(HardwareBitfieldSourceLedger.inspect(profile).entries());
        int at=-1;for(int i=0;i<claims.size();i++)
            if(claims.get(i).register().equals("SIMCR") &&
                    claims.get(i).field().equals("MM"))at=i;
        check(at>=0,"Reviewed source claim present");
        claims.set(at,new HardwareBitfieldSourceLedger.Entry(
            "SIMCR","MM",0x0080,219,220,"PDF pages 219-220"));
        var badMask=HardwareManualFieldExcerptEvidence.compareClaims(
            "MC68332",claims,synthetic(),P);
        check(find(badMask,"SIMCR/MM").state()==
            HardwareManualFieldExcerptEvidence.State.MASK_OR_DIAGRAM_MISMATCH,
            "Forged mask fails despite matching heading and publisher digest claim");
        claims=new ArrayList<>(HardwareBitfieldSourceLedger.inspect(profile).entries());
        claims.removeIf(x->x.register().equals("SYNCR") &&
            x.field().equals("STEXT"));
        var missingClaim=HardwareManualFieldExcerptEvidence.compareClaims(
            "MC68332",claims,synthetic(),P);
        check(find(missingClaim,"SYNCR/STEXT").state()==
            HardwareManualFieldExcerptEvidence.State.PROFILE_FIELD_MISSING,
            "Missing source-backed field is not inferred from PDF prose");
        claims=new ArrayList<>(HardwareBitfieldSourceLedger.inspect(profile).entries());
        claims.add(new HardwareBitfieldSourceLedger.Entry(
            "SYNCR","EXTRA",0x10,220,220,"PDF page 220"));
        check(HardwareManualFieldExcerptEvidence.compareClaims(
            "MC68332",claims,synthetic(),P).unexpected()==1,
            "Unreviewed field cannot hide inside 15 positive rows");
        reject(()->HardwareManualFieldExcerptEvidence.inspect(profile,
            Map.of(0,"unsafe"),P),"Zero-based physical PDF pages are denied");
        reject(()->HardwareManualFieldExcerptEvidence.inspect(profile,
            Map.of(219,"X".repeat(
                HardwareManualFieldExcerptEvidence.MAX_PAGE_CHARS+1)),P),
            "Unbounded extracted PDF text denied");
        reject(()->HardwareManualFieldExcerptEvidence.inspect(null,
            synthetic(),P),"Explicit selected hardware required");
        // Public RAG citation records are also consumed outside the
        // pure inspector. Reject forged SHA, row totals and reordered
        // or duplicate field identities at the report boundary itself.
        var sourceMm=find(positive,"SIMCR/MM");
        reject(()->new HardwareManualFieldExcerptEvidence.Citation(
            sourceMm.reviewed(),
            HardwareManualFieldExcerptEvidence.State.MATCHED_TEXT_CANDIDATE,
            sourceMm.excerpt()+" edited",sourceMm.excerptSha256()),
            "matching-looking indexed text with stale SHA cannot publish a citation");
        reject(()->new HardwareManualFieldExcerptEvidence.Citation(
            sourceMm.reviewed(),
            HardwareManualFieldExcerptEvidence.State.MATCHED_TEXT_CANDIDATE,
            sourceMm.excerpt(),"0".repeat(64)),
            "caller-provided but incorrect digest cannot authenticate excerpt");
        reject(()->new HardwareManualFieldExcerptEvidence.Report(
            positive.device(),positive.editionClaim(),positive.pdfUrl(),
            positive.expectedPublisherSha256(),positive.suppliedIndexedSha256(),
            positive.citations(),15,1,0),
            "forged positive citation totals fail closed");
        reject(()->new HardwareManualFieldExcerptEvidence.Report(
            positive.device(),positive.editionClaim(),positive.pdfUrl(),
            positive.expectedPublisherSha256(),positive.suppliedIndexedSha256(),
            positive.citations(),14,1,0),
            "a missing claimed match cannot hide among fifteen matched citations");
        var swappedCitations=new ArrayList<>(positive.citations());
        java.util.Collections.swap(swappedCitations,0,1);
        reject(()->new HardwareManualFieldExcerptEvidence.Report(
            positive.device(),positive.editionClaim(),positive.pdfUrl(),
            positive.expectedPublisherSha256(),positive.suppliedIndexedSha256(),
            swappedCitations,15,0,0),
            "out-of-order reviewed field list cannot masquerade as full source review");
        var duplicateCitations=new ArrayList<>(positive.citations());
        duplicateCitations.set(1,duplicateCitations.get(0));
        reject(()->new HardwareManualFieldExcerptEvidence.Report(
            positive.device(),positive.editionClaim(),positive.pdfUrl(),
            positive.expectedPublisherSha256(),positive.suppliedIndexedSha256(),
            duplicateCitations,15,0,0),
            "duplicate field cannot replace a missing reviewed citation");
        reject(()->new HardwareManualFieldExcerptEvidence.Report(
            "CPU32","UNKNOWN","UNKNOWN",P,"UNKNOWN",
            positive.citations(),15,0,0),
            "generic ISA cannot carry indexed MC68332 publisher citations");
        var degraded=new ArrayList<>(positive.citations());
        degraded.set(0,new HardwareManualFieldExcerptEvidence.Citation(
            degraded.get(0).reviewed(),
            HardwareManualFieldExcerptEvidence.State.PAGE_TEXT_MISSING,
            null,null));
        var downgradedReport=new HardwareManualFieldExcerptEvidence.Report(
            positive.device(),positive.editionClaim(),positive.pdfUrl(),
            positive.expectedPublisherSha256(),positive.suppliedIndexedSha256(),
            degraded,14,1,0);
        check(!downgradedReport.allReviewedTextCandidatesMatch() &&
            downgradedReport.omitted()==1,
            "negative row must prevent full source completeness even with index digest");
        boolean immutable=false;
        try{positive.citations().clear();}
        catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"Source citation result immutable");

        if(args.length!=0 && args.length!=3)
            throw new IllegalArgumentException(
                "Expected three SHA-pinned MC68332UM physical PDF text pages");
        if(args.length==3) {
            var publisher=HardwareManualFieldExcerptEvidence.inspect(
                profile,Map.of(219,Files.readString(Path.of(args[0])),
                    220,Files.readString(Path.of(args[1])),
                    221,Files.readString(Path.of(args[2]))),P);
            check(publisher.allReviewedTextCandidatesMatch() &&
                HardwareManualPublisherExcerptPins.allPinnedExcerptsMatch(publisher),
                "Publisher SHA-pinned MC68332UM: 15 exact excerpt digests reproduce frozen official references");
            for(var row:publisher.citations()){
                check(row.excerptSha256()!=null &&
                    row.excerptSha256().length()==64 &&
                    HardwareManualPublisherExcerptPins.matches(row) &&
                    row.excerpt().contains(row.reviewed().heading()
                        .toUpperCase().replace(" — "," - ")),
                    "Publisher text contains bounded evidence excerpt for "+row.reviewed().key());
                System.out.println("PINNED_PUBLISHER_CITATION "+
                    row.reviewed().key()+" diagramPDF="+row.reviewed().diagramPage()+
                    " printed="+row.reviewed().printedFolio()+
                    " descriptionPDF="+row.reviewed().descriptionPage()+
                    " excerptSha256="+row.excerptSha256());
            }
            System.out.println("PINNED MC68332UM EXCERPT SOURCE PASS: fields=15");
        }
        System.out.println("HardwareManualFieldExcerptEvidenceSelfTest PASS: checks="+checks);
    }
}
