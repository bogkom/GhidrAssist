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

    /** Bound exported evidence independently of an untrusted Review row list. */
    public static final int MAX_CSV_ROWS=5000;
    /** Even with bounded row count, untrusted text fields must have a bound. */
    public static final int MAX_CSV_CELL_CHARS=512;
    private static final String CELL_TRUNCATION=" [SOURCE_TRUNCATED]";


    /**
     * RFC-style quoted cells. Excel/Calc may still evaluate a CSV field as a
     * formula *inside quotes*; prefix potential formulas with an apostrophe.
     * Preserve the original spelling otherwise; this is never an Apply CSV.
     */
    private static String cell(String value) {
        if(value==null)value="";
        // Bound raw input BEFORE chaining replace() (which would otherwise
        // duplicate a multi-MB string) and explicitly show evidence loss.
        if(value.length()>MAX_CSV_CELL_CHARS)
            value=value.substring(0,MAX_CSV_CELL_CHARS-CELL_TRUNCATION.length())
                +CELL_TRUNCATION;
        String normalized=value.replace("\r"," ").replace("\n"," ")
            .replace("\u0000"," ").replace("\u2028"," ")
            .replace("\u2029"," ");
        int pos=0;
        while(pos<normalized.length()) {
            char c=normalized.charAt(pos);
            if(!Character.isWhitespace(c) && !Character.isSpaceChar(c) &&
                    c!='\ufeff' && c!='\u200b')break;
            pos++;
        }
        if(pos<normalized.length() &&
                "=+-@".indexOf(normalized.charAt(pos))>=0)
            normalized="'"+normalized;
        else if(normalized.startsWith("\t"))
            normalized="'"+normalized;
        return "\"" + normalized.replace("\"","\"\"") + "\"";
    }

    public static String csv(List<ReviewRow> rows) {
        if(rows==null || rows.stream().anyMatch(r->r==null))
            throw new IllegalArgumentException("Missing/null provenance row");
        StringBuilder out=new StringBuilder(
            "kind,address_range,proposed_name,existing_name,ghidra_source_type,"+
            "source_interpretation,proposed_origin,preflight_decision,selected,evidence\n");
        int retained=Math.min(rows.size(),MAX_CSV_ROWS);
        for(int i=0;i<retained;i++){
            ReviewRow row=rows.get(i);
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
        if(rows.size()>retained){
            // A counted extra marker is explicit loss of review provenance.
            // A truncated export must NEVER be read back as complete Apply
            // input, and is not an authorship audit of the omitted items.
            out.append(cell("OMITTED_ROWS")).append(',')
                .append(cell("")).append(',').append(cell(""))
                .append(',').append(cell("")).append(',').append(cell("UNKNOWN"))
                .append(',').append(cell("EXPORT_INCOMPLETE"))
                .append(',').append(cell("LOCAL_READ_ONLY_CSV"))
                .append(',').append(cell("INCOMPLETE_EXPORT_NEVER_AUTO_APPLY"))
                .append(',').append("false").append(',')
                .append(cell((rows.size()-retained)+" rows omitted by cap"))
                .append('\n');
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
