package ghidrassist.core;

import ghidrassist.hardware.HardwareManualFieldExcerptEvidence;
import ghidrassist.hardware.HardwareManualPublisherExcerptPins;
import ghidrassist.hardware.HardwareProfiles;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * GA-06/10/16 pure, bounded view of reviewed D-5/D-6/D-7 citations.
 * Native RAG provider supplies page data captured in ONE Lucene snapshot.
 * A matching INDEX-TIME SHA cannot verify arbitrary page text, the current
 * local PDF or a hardware device. No Ghidra Program or file writes.
 */
public final class RAGManualFieldCitationView {
    private RAGManualFieldCitationView(){}
    public static final List<Integer> PAGES=List.of(219,220,221);
    private static String boundedToken(String value,String name) {
        if(value==null || value.isBlank() || value.length()>240)
            throw new IllegalArgumentException("Missing/large "+name);
        for(int i=0;i<value.length();i++)
            if(Character.isISOControl(value.charAt(i)) ||
                    Character.getType(value.charAt(i))==Character.FORMAT)
                throw new IllegalArgumentException("Hidden/control source metadata");
        return value.trim();
    }
    public static String render(String device,String filename,String register,
            String field,Map<Integer,RAGIndexedPdfPageEvidence.Page> pages) {
        if(!"MC68332".equals(device))
            throw new IllegalArgumentException(
                "Explicit device=MC68332 required; CPU32 is not a device");
        String file=boundedToken(filename,"indexed filename");
        String reg=boundedToken(register,"register").toUpperCase(Locale.ROOT);
        if(!reg.equals("SIMCR") && !reg.equals("SYNCR"))
            throw new IllegalArgumentException(
                "Only reviewed SIMCR/SYNCR source definitions supported");
        String target=field==null?null:boundedToken(field,"field")
            .toUpperCase(Locale.ROOT);
        if(pages==null || !pages.keySet().equals(Set.copyOf(PAGES)))
            throw new IllegalArgumentException(
                "D-5/D-6/D-7 exact physical PDF page set required");
        RAGIndexedPdfPageEvidence.requireOneIndexedDocument(pages);
        var first=pages.get(219);
        var indexPin=RAGSourceProvenance.inspect("pdf",first.indexedSha256());
        if(indexPin.pin()!=RAGSourceProvenance.Pin
                .OFFICIAL_MC68332UM_SHA256_AT_INDEX)
            throw new IllegalArgumentException(
                "INDEX_PUBLISHER_SHA_MISMATCH: no source citation privileges");
        var sourceText=new TreeMap<Integer,String>();
        for(var item:pages.entrySet())
            sourceText.put(item.getKey(),item.getValue().text());
        HardwareManualFieldExcerptEvidence.Report report=
            HardwareManualFieldExcerptEvidence.inspect(
                HardwareProfiles.mc68332(),sourceText,first.indexedSha256());
        StringBuilder out=new StringBuilder(
            "DEVICE: MC68332 EXPLICIT; REGISTER: "+reg+
            "; INDEXED_SOURCE: "+file+
            "\nEDITION_CLAIM: "+report.editionClaim()+
            "\nINDEXED_SHA256: "+first.indexedSha256()+
            "\nSOURCE_PDF: "+report.pdfUrl()+
            "\nREVIEWED_PAGES: D-5/PDF219, D-6/PDF220, D-7/PDF221"+
            "\nFULL_15_TEXT_CANDIDATES: "+report.allReviewedTextCandidatesMatch()+
            "\nFULL_15_PINNED_PUBLISHER_EXCERPTS: "+
            HardwareManualPublisherExcerptPins.allPinnedExcerptsMatch(report)+
            "\nSOURCE_STATUS: INDEXED_TEXT_ONLY_NOT_CURRENT_PDF_AUTHENTICATION"+
            "\nCAUTION: no automatic MCU selection, hardware execution, "+
            "latched SIMCR MM, VBR/ISR, PDF edition certification or "+
            "Review/Apply/Undo. Independently recheck official publisher "+
            "PDF bytes and original page before relying on source meaning.\n");
        int count=0;
        for(var citation:report.citations()) {
            var ref=citation.reviewed();
            if(!reg.equals(ref.register()) ||
                    target!=null && !target.equals(ref.field()))continue;
            count++;
            out.append("FIELD: ").append(ref.field())
                .append(" MASK: 0x")
                .append(Long.toHexString(ref.mask()).toUpperCase(Locale.ROOT))
                .append(" DIAGRAM_PDF: ").append(ref.diagramPage())
                .append(" DESCRIPTION_PDF: ").append(ref.descriptionPage())
                .append(" PRINTED_FOLIO: ").append(ref.printedFolio())
                .append(" STATE: ").append(citation.state())
                .append(" INDEX_EXCERPT_SHA256: ")
                .append(citation.excerptSha256()==null?"UNKNOWN":
                    citation.excerptSha256())
                .append(" PINNED_PUBLISHER_EXCERPT_SHA256: ")
                .append(HardwareManualPublisherExcerptPins.expected(
                    ref.register(),ref.field()))
                .append(" MATCHES_PINNED_EXCERPT: ")
                .append(HardwareManualPublisherExcerptPins.matches(citation))
                .append("\n");
            if(citation.excerpt()!=null)
                out.append("BOUNDED_INDEXED_EXCERPT: ")
                    .append(citation.excerpt()).append("\n");
        }
        if(count==0)
            throw new IllegalArgumentException(
                "Unrecognized/unreviewed field for explicitly selected register");
        return out.toString();
    }
}
