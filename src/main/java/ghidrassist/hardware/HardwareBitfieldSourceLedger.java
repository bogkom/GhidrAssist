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

    public record Entry(String register, String field, long mask,
                        int firstPage, int lastPage, String label) {
        public Entry {
            if(register==null || register.isBlank() ||
                    field==null || field.isBlank() || mask==0 ||
                    firstPage<1 || lastPage<firstPage || lastPage>100000 ||
                    label==null || label.isBlank())
                throw new IllegalArgumentException("Invalid bitfield citation");
        }
    }

    public record Report(String device, String manualUrl, String editionClaim,
                         List<Entry> entries, int excludedFields) {
        public Report {
            if(device==null || manualUrl==null || editionClaim==null ||
                    entries==null || excludedFields<0 ||
                    entries.size()>256)
                throw new IllegalArgumentException("Invalid manual citation inventory");
            entries=List.copyOf(entries);
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
                .append("- No PDF file bytes or SHA-256 authenticated here; ")
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
                out.append(" (").append(e.label()).append(")")
                    .append(" | CLAIM_ONLY; PDF BYTES UNVERIFIED |\n");
            }
            return out.toString();
        }
    }

    public static Report inspect(HardwareProfiles.Profile profile) {
        if(profile==null)throw new IllegalArgumentException("Missing profile");
        if(!profile.concreteDevice || !"MC68332".equals(profile.id))
            return new Report(profile.id,"UNKNOWN","UNKNOWN",List.of(),0);
        List<Entry> collected=new ArrayList<>();
        int excluded=0;
        for(HardwareProfiles.Register register:profile.registers) {
            for(HardwareProfiles.BitField field:register.fields) {
                var range=ManualPdfPageClaim.physicalRange(field.sourcePage);
                if(range==null) {
                    excluded++;
                    continue;
                }
                if(collected.size()>=256)
                    throw new IllegalArgumentException("Unbounded bitfield source catalog");
                collected.add(new Entry(register.name,field.name,
                    Integer.toUnsignedLong(field.mask),range.first(),
                    range.last(),field.sourcePage));
            }
        }
        return new Report(profile.id,HardwareProfiles.MC68332_MANUAL,
            MC68332_EDITION_CLAIM,collected,excluded);
    }
}
