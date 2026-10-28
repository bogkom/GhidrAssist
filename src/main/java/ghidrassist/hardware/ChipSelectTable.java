package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Conditional, model-scoped snapshot table. Never represents a proven
 * execution trace or a physical external-memory configuration.
 */
public final class ChipSelectTable {
    private ChipSelectTable() {}

    public static String markdown(Map<String,Integer> observed, boolean selectedMc68332) {
        if (!selectedMc68332) {
            return "MC68332 chip-select ranges are not decoded in generic CPU32 mode; "
                + "select a documented MCU profile to enable this table.\n";
        }
        ChipSelectModel.Decoder decoder = new ChipSelectModel.Decoder(
            "MC68332", "MC68332 manual; function-local conditional candidates");
        StringBuilder md = new StringBuilder();
        md.append("| Chip Select | Start | End | Size | CSBAR | CSOR | CSPAR | Status |\n")
          .append("|---|---|---|---|---|---|---|---|\n");
        List<ChipSelectModel.Window> windows = new ArrayList<>();
        for (int cs = -1; cs <= 10; cs++) {
            String suffix = cs < 0 ? "BT" : Integer.toString(cs);
            String pinRegister = cs <= 5 ? "CSPAR0" : "CSPAR1";
            Integer bar = observed.get("CSBAR" + suffix);
            Integer or = observed.get("CSOR" + suffix);
            Integer par = observed.get(pinRegister);
            ChipSelectModel.Window window = decoder.window(cs, bar, or, par);
            String label = cs < 0 ? "CSBOOT" : "CS" + cs;
            md.append("| ").append(label).append(" | ");
            if (window == null) {
                md.append("UNKNOWN | UNKNOWN | UNKNOWN | ");
            } else {
                windows.add(window);
                md.append(ChipSelectModel.hex(window.first, 6)).append(" | ")
                  .append(ChipSelectModel.hex(window.last, 6)).append(" | ")
                  .append(window.size / 1024).append(" KiB | ");
            }
            md.append(word(bar)).append(" | ").append(word(or)).append(" | ")
              .append(word(par)).append(" | ");
            if (window == null) {
                md.append("UNKNOWN: missing CSBAR");
            } else if (or == null || par == null) {
                md.append("PARTIAL: CSOR/CSPAR unknown");
            } else if (window.eligibleForAssertion()) {
                md.append("CONDITIONAL: possible assertion");
            } else {
                md.append("NOT ELIGIBLE under observed values");
            }
            md.append(" |\n");
        }
        md.append("\nRanges are **hypotheses conditional on MC68332 interpretation**. ")
          .append("Writes grouped by code location are not guaranteed to form a single ")
          .append("execution state; CSOR, pin assignments, CPU space, byte lanes, ")
          .append("bus wiring and hardware execution are not established.\n");
        for (String overlap : ChipSelectModel.overlaps(windows)) {
            md.append("- shared address hypothesis: ").append(overlap).append("\n");
        }
        return md.toString();
    }

    private static String word(Integer v) {
        return v == null ? "UNKNOWN" : ChipSelectModel.hex(v & 0xffff, 4);
    }
}
