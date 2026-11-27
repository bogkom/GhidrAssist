package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;

/**
 * Conditional, model-scoped snapshot table. Never represents a proven
 * execution trace or a physical external-memory configuration.
 */
public final class ChipSelectTable {
    private ChipSelectTable() {}
    public static final int MAX_SNAPSHOT_WORDS=4096;
    public static final int MAX_CONTEXT_SNAPSHOTS=350;
    private static final long MAX_MCU24=0xffffffL;

    private static void checkSnapshotWords(Map<Long,Integer> input,long simBase) {
        if(input==null || input.size()>MAX_SNAPSHOT_WORDS ||
                (simBase!=0x7ff000L && simBase!=0xfff000L))
            throw new IllegalArgumentException(
                "Unbounded or non-MC68332 source snapshot");
        for(var word:input.entrySet())
            if(word.getKey()==null || word.getKey()<0 ||
                    word.getKey()>MAX_MCU24 ||
                    word.getValue()==null || word.getValue()<0 ||
                    word.getValue()>0xffff)
                throw new IllegalArgumentException(
                    "Invalid 16-bit CFG source word");
    }

    /**
     * One frozen, explicitly selected MC68332 MM0/MM1 CFG state at
     * one instruction. Not a register history, time order or active map.
     */
    public record Snapshot(long pc,long simBase,Map<Long,Integer> sourceWords) {
        public Snapshot {
            if(pc<0 || pc>MAX_MCU24 || (pc&1)!=0)
                throw new IllegalArgumentException("Invalid source instruction PC");
            checkSnapshotWords(sourceWords,simBase);
            sourceWords=Map.copyOf(sourceWords);
        }
    }
    public record SelectedSnapshot(long pc,long simBase,
            Map<String,Integer> words,int candidateContexts) {
        public SelectedSnapshot {
            if(pc<0 || pc>MAX_MCU24 || (pc&1)!=0 ||
                    (simBase!=0x7ff000L && simBase!=0xfff000L) ||
                    words==null || candidateContexts<1 ||
                    candidateContexts>MAX_CONTEXT_SNAPSHOTS)
                throw new IllegalArgumentException("Invalid selected snapshot");
            words=Map.copyOf(words);
        }
    }

    /**
     * Convert only whole, explicitly known CS word values from ONE source
     * CFG snapshot to the existing 12-row decoder. Never combine MM0 with
     * MM1, or any different instruction/function/branch snapshots.
     */
    public static Map<String,Integer> sourceWordsAtSnapshot(
            Map<Long,Integer> sourceWords,long simBase) {
        checkSnapshotWords(sourceWords,simBase);
        Map<String,Integer> known=new java.util.LinkedHashMap<>();
        for(int cs=-1;cs<=10;cs++) {
            String suffix=cs<0?"BT":Integer.toString(cs);
            long offset=cs<0?0L:4L*(cs+1);
            Integer bar=sourceWords.get(simBase+0xa48+offset);
            Integer or=sourceWords.get(simBase+0xa4a+offset);
            if(bar!=null)known.put("CSBAR"+suffix,bar);
            if(or!=null)known.put("CSOR"+suffix,or);
        }
        for(int n=0;n<2;n++) {
            Integer pin=sourceWords.get(simBase+0xa44+2*n);
            if(pin!=null)known.put("CSPAR"+n,pin);
        }
        return Map.copyOf(known);
    }

    /**
     * Choose ONE deterministically most-informative function-local
     * candidate state, not an inferred latest/first executed state.
     * A tie uses the lowest source PC and then MM0 before MM1.
     */
    public static SelectedSnapshot chooseSource(List<Snapshot> sources) {
        if(sources==null || sources.isEmpty() ||
                sources.size()>MAX_CONTEXT_SNAPSHOTS)
            throw new IllegalArgumentException("Unbounded source contexts");
        Set<String> identities=new HashSet<>();
        SelectedSnapshot best=null;
        for(Snapshot candidate:sources) {
            if(candidate==null || !identities.add(
                    candidate.pc()+":"+candidate.simBase()))
                throw new IllegalArgumentException(
                    "Ambiguous duplicate CFG snapshot identity");
            Map<String,Integer> words=sourceWordsAtSnapshot(
                candidate.sourceWords(),candidate.simBase());
            if(best==null || words.size()>best.words().size() ||
                    words.size()==best.words().size() &&
                        (candidate.pc()<best.pc() ||
                         candidate.pc()==best.pc() &&
                             candidate.simBase()<best.simBase()))
                best=new SelectedSnapshot(candidate.pc(),candidate.simBase(),
                    words,sources.size());
        }
        return best;
    }

    public static String markdown(Map<String,Integer> observed, boolean selectedMc68332) {
        if (!selectedMc68332) {
            return "MC68332 chip-select ranges are not decoded in generic CPU32 mode; "
                + "select a documented MCU profile to enable this table.\n";
        }
        if (observed == null || observed.size() > 256 ||
                observed.entrySet().stream().anyMatch(item ->
                    item.getKey() == null || item.getValue() == null ||
                    item.getValue() < 0 || item.getValue() > 0xffff))
            throw new IllegalArgumentException(
                "Invalid full-word chip-select evidence");
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
