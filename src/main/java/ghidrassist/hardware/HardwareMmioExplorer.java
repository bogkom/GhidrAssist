package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Pure, read-only presentation of existing Ghidra reference observations.
 * A reference is not proof of runtime access; register labels are hypotheses
 * until an MCU is independently identified. Does not update Ghidra or RAG.
 */
public final class HardwareMmioExplorer {
    private HardwareMmioExplorer() {}

    public record Observation(long pc, long address, String register,
            String function, String instruction, boolean candidateWrite,
            Integer directWordLiteral) {}

    public record Row(long pc, long address, String register, String function,
            String instruction, String access, String value, String evidence,
            String deviceScope) {
        public String pcHex() { return hex(pc); }
        public String addressHex() { return hex(address); }
        public boolean matches(String query) {
            if (query == null || query.isBlank()) return true;
            String needle=query.strip().toLowerCase(Locale.ROOT);
            return (pcHex()+" "+addressHex()+" "+register+" "+function+" "+
                instruction+" "+access+" "+value+" "+evidence+" "+
                deviceScope).toLowerCase(Locale.ROOT).contains(needle);
        }
    }

    /** The same deterministic filter backs the Swing table and Automation API. */
    public static List<Row> filter(List<Row> rows, String query) {
        if (rows == null)
            throw new IllegalArgumentException("Invalid MMIO row inventory");
        for (Row row : rows)
            if (row == null)
                throw new IllegalArgumentException("Null MMIO evidence row");
        if (query == null || query.isBlank()) return List.copyOf(rows);
        List<Row> matching = new ArrayList<>();
        for (Row row : rows)
            if (row.matches(query)) matching.add(row);
        return List.copyOf(matching);
    }

    /** A bounded immutable page; total counts matching sites before paging. */
    public record Page(int total, int offset, int limit, List<Row> rows) {
        public Page {
            if (total < 0 || offset < 0 || limit < 1 || limit > 200 ||
                    rows == null ||
                    rows.size() > limit || rows.size() > total)
                throw new IllegalArgumentException("Invalid MMIO page");
            for (Row row : rows)
                if (row == null)
                    throw new IllegalArgumentException("Null MMIO page row");
            rows = List.copyOf(rows);
        }
    }

    public static Page page(List<Row> rows, String query, int offset, int limit) {
        if (offset < 0 || limit < 1 || limit > 200)
            throw new IllegalArgumentException("Invalid MMIO pagination");
        List<Row> matches = filter(rows, query);
        if (offset >= matches.size())
            return new Page(matches.size(), offset, limit, List.of());
        return new Page(matches.size(), offset, limit,
            matches.subList(offset, offset + Math.min(limit, matches.size() - offset)));
    }

    public static String hex(long address) {
        return String.format(Locale.ROOT,"0x%08X",address);
    }

    /** Rows include all referenced register addresses, not only Analyze headings. */
    public static List<Row> rows(List<Observation> observations, boolean mc68332Selected) {
        if (observations == null || observations.isEmpty()) return List.of();
        List<Row> result=new ArrayList<>();
        String scope=mc68332Selected ?
            "MC68332 USER-SELECTED HYPOTHESIS" : "CPU32 ADDRESS SURVEY ONLY";
        for (Observation o : observations) {
            if (o==null || o.pc()<0 || o.address()<0) continue;
            String value="UNKNOWN";
            String evidence;
            if (o.candidateWrite() && o.directWordLiteral()!=null &&
                    o.directWordLiteral()>=0 && o.directWordLiteral()<=0xffff) {
                value=String.format(Locale.ROOT,"0x%04X",o.directWordLiteral());
                evidence="DIRECT WORD LITERAL CANDIDATE; NOT RUNTIME STATE";
            } else if (o.candidateWrite() && o.directWordLiteral()!=null) {
                // An inconsistent upstream source must not be quietly
                // truncated with &0xffff into a plausible-looking word.
                evidence="OUT-OF-RANGE WORD CANDIDATE; VALUE UNKNOWN";
            } else if (o.candidateWrite()) {
                evidence="WRITE-TARGET CANDIDATE; VALUE UNKNOWN";
            } else {
                evidence="REFERENCE ONLY; ACCESS DIRECTION UNKNOWN";
            }
            result.add(new Row(o.pc(),o.address(),safe(o.register()),safe(o.function()),
                safe(o.instruction()),o.candidateWrite()?"WRITE CANDIDATE":
                "REFERENCE / UNKNOWN",value,evidence,scope));
        }
        result.sort(Comparator.comparingLong(Row::pc)
            .thenComparingLong(Row::address));
        return List.copyOf(result);
    }

    private static String safe(String value) {
        return value==null ? "UNKNOWN" : value;
    }
}
