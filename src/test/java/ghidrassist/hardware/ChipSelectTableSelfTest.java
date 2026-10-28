package ghidrassist.hardware;

import java.util.Map;

public final class ChipSelectTableSelfTest {
    private static void check(boolean ok, String reason) {
        if (!ok) throw new AssertionError(reason);
    }
    public static void main(String[] args) {
        String empty = ChipSelectTable.markdown(Map.of(), true);
        for (int i = -1; i <= 10; i++) {
            String label = i < 0 ? "CSBOOT" : "CS" + i;
            check(empty.contains("| " + label + " | UNKNOWN | UNKNOWN | UNKNOWN |"),
                "missing independent select: " + label);
        }
        check(empty.lines().filter(x -> x.matches("\\| CS(?:BOOT|[0-9]+) \\|.*")).count() == 12,
            "exactly 12 independent selects");
        String known = ChipSelectTable.markdown(
            Map.of("CSBARBT", 0x0006, "CSORBT", 0x6830,
                   "CSBAR0", 0xf803, "CSOR0", 0x3870, "CSPAR0", 0x2f7f), true);
        check(known.contains("| CSBOOT | 0x000000 | 0x07FFFF | 512 KiB |"),
            "CSBOOT based on decoded CSBAR");
        check(known.contains("| CS0 | 0xF80000 | 0xF8FFFF | 64 KiB |"),
            "CS0 based on decoded CSBAR");
        check(known.contains("CS1 | UNKNOWN"), "unseen CS remains unknown");
        check(known.contains("CONDITIONAL"), "not a proven map");
        String generic = ChipSelectTable.markdown(Map.of("CSBAR0", 0xf803), false);
        check(!generic.contains("| CS0 |"), "generic CPU32 cannot inherit MC68332");
        System.out.println("ChipSelectTableSelfTest OK");
    }
}
