package ghidrassist.core;

import ghidrassist.hardware.HardwareProfiles;
import ghidrassist.hardware.HardwareSimProtectionTimerWitness;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * GA-06/10/16 read-only MCU-scoped RAG candidate citation surface
 * for SYPCR/PICR/PITR, physical PDF folios D-10/224 and D-11/225.
 * Indexed source text is NOT a current-file or physical-device proof.
 */
public final class RAGSimProtectionTimerCitationView {
    private RAGSimProtectionTimerCitationView(){}
    public static final List<Integer> PAGES=List.of(224,225);
    private static String token(String in,String name) {
        if(in==null || in.isBlank() || in.length()>240)
            throw new IllegalArgumentException("Invalid "+name);
        for(int i=0;i<in.length();i++)
            if(Character.isISOControl(in.charAt(i)) ||
                    Character.getType(in.charAt(i))==Character.FORMAT)
                throw new IllegalArgumentException("Unsafe source metadata");
        return in.trim();
    }
    public static String render(String device,String filename,String register,
            String field,Map<Integer,RAGIndexedPdfPageEvidence.Page> pages) {
        if(!"MC68332".equals(device))
            throw new IllegalArgumentException(
                "Explicit device=MC68332 required, not generic CPU32");
        String file=token(filename,"filename");
        String reg=token(register,"register").toUpperCase(Locale.ROOT);
        if(!List.of("SYPCR","PICR","PITR").contains(reg))
            throw new IllegalArgumentException("Only reviewed SIM protection/timer fields supported");
        String target=field==null?null:token(field,"field")
            .toUpperCase(Locale.ROOT);
        if(pages==null || !pages.keySet().equals(Set.copyOf(PAGES)))
            throw new IllegalArgumentException("Exactly PDF 224 and 225 required");
        RAGIndexedPdfPageEvidence.requireOneIndexedDocument(pages);
        var first=pages.get(224);
        if(RAGSourceProvenance.inspect("pdf",first.indexedSha256()).pin() !=
                RAGSourceProvenance.Pin.OFFICIAL_MC68332UM_SHA256_AT_INDEX)
            throw new IllegalArgumentException(
                "INDEX_PUBLISHER_SHA_MISMATCH: no MC68332 field citations");
        Map<Integer,String> raw=new TreeMap<>();
        for(var entry:pages.entrySet())
            raw.put(entry.getKey(),entry.getValue().text());
        var result=HardwareSimProtectionTimerWitness.inspect(
            HardwareProfiles.mc68332(),raw);
        var out=new StringBuilder("DEVICE: MC68332 EXPLICIT; REGISTER: ")
            .append(reg).append("; INDEXED_SOURCE: ").append(file)
            .append("\nEDITION_CLAIM: ").append(result.expectedEdition())
            .append("\nINDEXED_PDF_SHA256: ").append(first.indexedSha256())
            .append("\nREVIEWED_FOLIOS: D-10/PDF224 D-11/PDF225")
            .append("\nALL_10_REVIEWED_TEXT_CANDIDATES: ")
            .append(result.allTenCandidatesMatch())
            .append("\nSTATUS: INDEXED_TEXT_NOT_CURRENT_FILE_AUTHENTICATION")
            .append("\nCAUTION: selected device is explicit, but no watchdog ")
            .append("running/timeout, active periodic interrupt/vector, ")
            .append("ISR execution, physical mapping, actual SYPCR first ")
            .append("write or Review/Apply is established. Publisher PDF ")
            .append("bytes and original page must be independently checked.\n");
        int count=0;
        for(var row:result.rows()) {
            var ref=row.reviewed();
            if(!ref.register().equals(reg) ||
                    target!=null && !ref.field().equals(target))continue;
            count++;
            out.append("FIELD: ").append(ref.field())
                .append(" MASK: 0x")
                .append(Long.toHexString(ref.mask()).toUpperCase(Locale.ROOT))
                .append(" REGISTER_WIDTH_BITS: ").append(ref.widthBits())
                .append(" DESCRIPTION_PDF: ").append(ref.physicalPage())
                .append(" PRINTED_FOLIO: ").append(ref.printedFolio())
                .append(" WRITE_ONCE_REGISTER: ").append(ref.writeOnce())
                .append(" STATE: ").append(row.state())
                .append(" INDEXED_EXCERPT_SHA256: ")
                .append(row.excerptSha256()==null?"UNKNOWN":row.excerptSha256())
                .append("\n");
            if(row.excerpt()!=null)
                out.append("BOUNDED_INDEXED_EXCERPT: ").append(row.excerpt())
                    .append("\n");
        }
        if(count==0)throw new IllegalArgumentException(
            "Unreviewed field cannot inherit publisher/source confidence");
        return out.toString();
    }
}
