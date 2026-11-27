package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * GA-10/16 — bounded, read-only field-to-manual citation inventory.
 *
 * A structurally valid page claim is NOT a verified PDF, edition, or
 * authenticated register definition. Never infer an active MCU or write.
 * No document/network/Ghidra access, no implicit CPU32 device selection.
 */
public final class HardwareBitfieldSourceLedger {
    private HardwareBitfieldSourceLedger() {}

    public static final String MC68332_EDITION_CLAIM="MC68332UM — Motorola 1995";
    /** Public publisher PDF digest pinned and verified by GitHub Actions.
     *  NEVER implicitly proves a user's local/RAG PDF is that same copy. */
    public static final String MC68332_PUBLIC_PDF_SHA256=
        "02c2cb99738dd45a785798bba3e7dcc34bb0d54fb5fba42900e6ecb8356bf28a";

    public record Entry(String register, String field, long mask,
                        int firstPage, int lastPage, String label) {
        public Entry {
            if(register==null || !register.matches("[A-Z][A-Z0-9_]{0,63}") ||
                    field==null || !field.matches("[A-Z][A-Z0-9_]{0,63}") ||
                    mask<=0 || mask>0xffffffffL ||
                    firstPage<1 || lastPage<firstPage || lastPage>100000 ||
                    label==null || label.length()>256)
                throw new IllegalArgumentException("Invalid bitfield citation");
            // A page number in the row is not independent evidence: it must
            // agree with the ONE bounded, unambiguous claim in its label.
            var claimed=ManualPdfPageClaim.physicalRange(label);
            if(claimed==null || claimed.first()!=firstPage ||
                    claimed.last()!=lastPage)
                throw new IllegalArgumentException(
                    "Published PDF page coordinates contradict source claim");
        }
    }

    public record Report(String device, String manualUrl, String editionClaim,
                         List<Entry> entries, int excludedFields) {
        public Report {
            if(device==null || !device.matches("[A-Za-z0-9_-]{1,64}") ||
                    manualUrl==null || editionClaim==null ||
                    entries==null || excludedFields<0 || entries.size()>256)
                throw new IllegalArgumentException("Invalid manual citation inventory");
            entries=List.copyOf(entries);
            if("MC68332".equals(device)) {
                // A hand-built report cannot borrow the publisher digest for
                // another URL, edition, incomplete set or fabricated field.
                Catalog canonical=sourceCatalog(HardwareProfiles.mc68332());
                if(!HardwareProfiles.MC68332_MANUAL.equals(manualUrl) ||
                        !MC68332_EDITION_CLAIM.equals(editionClaim) ||
                        !entries.equals(canonical.entries()) ||
                        excludedFields!=canonical.excluded())
                    throw new IllegalArgumentException(
                        "Foreign MC68332 source inventory");
            } else if(!"UNKNOWN".equals(manualUrl) ||
                    !"UNKNOWN".equals(editionClaim) ||
                    !entries.isEmpty() || excludedFields!=0)
                throw new IllegalArgumentException(
                    "Generic CPU profile cannot publish device PDF sources");
        }

        public String markdown() {
            StringBuilder out=new StringBuilder(
                "## GA-10/16 bitfield source-page ledger (CLAIMS, READ ONLY)\n\n")
                .append("- Device scope: ").append(device)
                .append("; manual URL: ").append(manualUrl)
                .append("; edition claim: ").append(editionClaim).append(".\n")
                .append("- Numeric physical PDF-page claim records: ")
                .append(entries.size()).append("; missing/ambiguous page claims: ")
                .append(excludedFields).append(".\n")
                .append("- Publisher-hosted PDF SHA-256 pin checked by CI: ")
                .append("MC68332".equals(device)?
                    MC68332_PUBLIC_PDF_SHA256:"UNKNOWN")
                .append("; not checked against any local/RAG PDF copy.\n")
                .append("- No locally supplied PDF bytes or SHA-256 authenticated here; ")
                .append("no content extraction, verified edition, runtime ")
                .append("state or reset-value proof. These are metadata ")
                .append("candidates only.\n\n");
            if(entries.isEmpty())
                return out.append("No device-sourced bitfield rows available.\n").toString();
            out.append("| Register | Field | Mask | Physical PDF page claim | Status |\n")
               .append("|---|---|---|---|---|\n");
            for(Entry e:entries) {
                out.append("| ").append(e.register())
                    .append(" | ").append(e.field())
                    .append(" | ").append(String.format(Locale.ROOT,"0x%08X",e.mask()))
                    .append(" | ").append(e.firstPage());
                if(e.lastPage()!=e.firstPage())
                    out.append("-").append(e.lastPage());
                out.append(" (").append(markdownCell(e.label())).append(")")
                    .append(" | CLAIM_ONLY; PDF BYTES UNVERIFIED |\n");
            }
            return out.toString();
        }
    }

    private static String markdownCell(String value) {
        StringBuilder out=new StringBuilder();
        for(int at=0;at<value.length();) {
            int cp=value.codePointAt(at);
            at+=Character.charCount(cp);
            if(cp=='\\' || cp=='|' || cp=='[' || cp==']' || cp==0x60 ||
                    cp=='*' || cp=='_' || cp=='~')
                out.append('\\').appendCodePoint(cp);
            else if(cp=='&')out.append("&amp;");
            else if(cp=='<')out.append("&lt;");
            else if(cp=='>')out.append("&gt;");
            else out.appendCodePoint(cp);
        }
        return out.toString();
    }

    private record Catalog(List<Entry> entries,int excluded) {}

    /** The canonical inventory is recomputed from the explicitly selected
     * built-in MCU, never a caller-provided PDF or Report row. */
    private static Catalog sourceCatalog(HardwareProfiles.Profile profile) {
        List<Entry> rows=new ArrayList<>();
        int missing=0;
        for(HardwareProfiles.Register register:profile.registers) {
            // D-10/D-11 protection/timer fields have their own audit;
            // don't silently recast them as D-5/D-7 SIMCR/SYNCR citations.
            if(!register.name.equals("SIMCR") &&
                    !register.name.equals("SYNCR"))continue;
            for(HardwareProfiles.BitField field:register.fields) {
                var range=ManualPdfPageClaim.physicalRange(field.sourcePage);
                if(range==null){missing++;continue;}
                if(rows.size()>=256)
                    throw new IllegalArgumentException("Unbounded bitfield source catalog");
                rows.add(new Entry(register.name,field.name,
                    Integer.toUnsignedLong(field.mask),range.first(),
                    range.last(),field.sourcePage));
            }
        }
        return new Catalog(List.copyOf(rows),missing);
    }

    public static Report inspect(HardwareProfiles.Profile profile) {
        if(profile==null)throw new IllegalArgumentException("Missing profile");
        if(!profile.concreteDevice || !"MC68332".equals(profile.id))
            return new Report(profile.id,"UNKNOWN","UNKNOWN",List.of(),0);
        Catalog catalog=sourceCatalog(profile);
        return new Report(profile.id,HardwareProfiles.MC68332_MANUAL,
            MC68332_EDITION_CLAIM,catalog.entries(),catalog.excluded());
    }
}
