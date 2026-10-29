package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Conservative, read-only review provenance snapshot. Ghidra SourceType
 * expresses how a symbol is classified, not who made the edit (human, AI,
 * importer or third-party script). No persistent authorship is invented.
 */
public final class HardwareChangeProvenance {
    private HardwareChangeProvenance() {}

    public record ReviewRow(String kind, String range, String proposedName,
            String existingName, String ghidraSourceType, String decision,
            boolean selected, String evidence) {
        public ReviewRow {
            if(kind==null || range==null || proposedName==null || decision==null)
                throw new IllegalArgumentException("Required provenance fields missing");
        }
        public String displayExistingName() {
            return existingName==null || existingName.isBlank()
                ? "(no primary symbol)" : existingName;
        }
        public String sourceDescription() {
            return describeSourceType(ghidraSourceType);
        }
        public String proposalOrigin() {
            return "GhidrAssist review proposal; selected MC68332 hypothesis";
        }
    }

    public static String describeSourceType(String type) {
        if(type==null || type.isBlank())
            return "UNKNOWN — no primary symbol SourceType";
        return switch(type.toUpperCase(Locale.ROOT)) {
            case "USER_DEFINED" -> "USER_DEFINED — author UNKNOWN (human/AI/script)";
            case "ANALYSIS" -> "ANALYSIS — analyzer/tool identity UNKNOWN";
            case "IMPORTED" -> "IMPORTED — originating importer UNKNOWN";
            case "DEFAULT" -> "DEFAULT — Ghidra generated/default";
            default -> "UNKNOWN — unsupported SourceType";
        };
    }

    /** RFC-style quoted cells; source names are user data and never uploaded. */
    private static String cell(String value) {
        if(value==null)return "\"\"";
        return "\"" + value.replace("\"","\"\"").replace("\r"," ")
            .replace("\n"," ") + "\"";
    }

    public static String csv(List<ReviewRow> rows) {
        if(rows==null)throw new IllegalArgumentException("Missing provenance rows");
        StringBuilder out=new StringBuilder(
            "kind,address_range,proposed_name,existing_name,ghidra_source_type,"+
            "source_interpretation,proposed_origin,preflight_decision,selected,evidence\n");
        for(ReviewRow row:rows){
            if(row==null)throw new IllegalArgumentException("Null provenance row");
            out.append(cell(row.kind())).append(',').append(cell(row.range()))
                .append(',').append(cell(row.proposedName())).append(',')
                .append(cell(row.displayExistingName())).append(',')
                .append(cell(row.ghidraSourceType()==null?"UNKNOWN":
                    row.ghidraSourceType()))
                .append(',').append(cell(row.sourceDescription()))
                .append(',').append(cell(row.proposalOrigin()))
                .append(',').append(cell(row.decision())).append(',')
                .append(row.selected()).append(',')
                .append(cell(row.evidence())).append('\n');
        }
        return out.toString();
    }

    /** Stable unmodifiable snapshot, independent of live Ghidra mutations. */
    public static List<ReviewRow> snapshot(List<ReviewRow> rows) {
        if(rows==null || rows.stream().anyMatch(r->r==null))
            throw new IllegalArgumentException("Invalid provenance snapshot");
        return List.copyOf(new ArrayList<>(rows));
    }
}
