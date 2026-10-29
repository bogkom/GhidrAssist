package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Evidence-only interpretation of 68000 big-endian vector words.
 * No VBR value, vector activity, interrupt-enable state, priority level,
 * MCU peripheral assignment or runtime ISR execution is inferred here.
 */
public final class HardwareInterruptVectors {
    private HardwareInterruptVectors() {}

    public enum Classification {
        UNREADABLE, NULL_OR_ERASED, ODD_POINTER,
        UNMAPPED_TARGET, MAPPED_TARGET, RECOGNIZED_FUNCTION_CANDIDATE
    }

    /**
     * One 32-bit vector pointer from a candidate table at an explicitly known
     * image location; null is unreadable, NOT zero. mappedTarget indicates
     * presence in Ghidra's memory map, not proof that the CPU can execute it.
     */
    public record Observation(int vectorNumber, Long pointer,
                              boolean mappedTarget, String containingFunction) {}

    public record Entry(int vectorNumber, long slotAddress, Long pointer,
                        Classification classification, String function) {
        public String label() {
            if (vectorNumber == 24) return "Spurious interrupt vector";
            if (vectorNumber >= 25 && vectorNumber <= 31)
                return "Autovector level " + (vectorNumber - 24);
            if (vectorNumber < 24) return "CPU exception / reserved candidate";
            return "Device/user vector (assignment UNKNOWN)";
        }
    }

    public record Summary(long tableAddress, int sampledSlots, int readable,
                          int plausibleMapped, int recognizedFunctions,
                          int unmapped, int odd, int unreadable, int absent,
                          boolean truncated, List<Entry> displayed) {
        public Summary { displayed=List.copyOf(displayed); }

        /** Concise source-evidence table with explicit VBR and IRQ ambiguity. */
        public String markdown() {
            StringBuilder b=new StringBuilder();
            b.append("## Exception / interrupt vector *candidates* (GA-11)\n\n")
             .append("- Inspected image bytes at candidate table address ")
             .append(hex(tableAddress)).append("; **runtime VBR UNKNOWN**. ")
             .append("No interrupt controller, pending event, enabled interrupt, ")
             .append("active ISR or executed firmware path has been verified.\n")
             .append("- Slots inspected: ").append(sampledSlots)
             .append("; readable: ").append(readable)
             .append("; non-null mapped targets: ").append(plausibleMapped)
             .append("; mapped targets within recognized functions: ")
             .append(recognizedFunctions)
             .append("; unmapped: ").append(unmapped)
             .append("; odd: ").append(odd)
             .append("; null/erased: ").append(absent)
             .append("; unreadable: ").append(unreadable).append(".\n\n");
            if (!displayed.isEmpty()) {
                b.append("| Vector | Slot | Pointer | Static classification | Function candidate | Role |\n")
                 .append("|---|---|---|---|---|---|\n");
                for (Entry e:displayed) {
                    b.append("| ").append(e.vectorNumber()).append(" | ")
                     .append(hex(e.slotAddress())).append(" | ")
                     .append(e.pointer()==null?"UNKNOWN":hex(e.pointer())).append(" | ")
                     .append(e.classification()).append(" | ")
                     .append(escape(e.function())).append(" | ")
                     .append(escape(e.label())).append(" |\n");
                }
                b.append("\n");
            } else {
                b.append("- No nonempty candidate entries in the bounded input. ")
                 .append("This does not establish an empty interrupt table.\n\n");
            }
            if(truncated)
                b.append("- Output truncated to the documented row limit; ")
                 .append("the summary counts cover all inspected slots.\n");
            b.append("- **STATIC DATA ONLY**: image-zero vector words are not ")
             .append("proof of the current VBR, a valid vector table, active ")
             .append("peripheral assignments or code execution. A mapped address ")
             .append("is not proof of an executable ISR. Vector 24 and 25–31 ")
             .append("use generic 68000 spurious/autovector numbering; ")
             .append("device-specific vector meanings are UNKNOWN.\n\n");
            return b.toString();
        }
    }

    public static Summary inspect(long tableAddress, List<Observation> input,
                                  int maximumDisplayed) {
        if(tableAddress<0 || tableAddress>0xffffffffL ||
                (tableAddress & 3)!=0 || input==null ||
                maximumDisplayed<1 || maximumDisplayed>64)
            throw new IllegalArgumentException("Invalid vector table parameters");
        List<Observation> sorted=new ArrayList<>(input);
        Set<Integer> seen=new HashSet<>();
        for(Observation o:sorted) {
            if(o==null || o.vectorNumber()<2 || o.vectorNumber()>255 ||
                    !seen.add(o.vectorNumber()) ||
                    (o.pointer()!=null &&
                      (o.pointer()<0 || o.pointer()>0xffffffffL)))
                throw new IllegalArgumentException("Invalid or duplicate vector entry");
        }
        sorted.sort(Comparator.comparingInt(Observation::vectorNumber));
        int readable=0,mapped=0,functions=0,unmapped=0,odd=0,unreadable=0,absent=0;
        List<Entry> displayed=new ArrayList<>();
        int wanted=0;
        for(Observation o:sorted) {
            long slot=tableAddress+4L*o.vectorNumber();
            Classification state;
            if(o.pointer()==null) {
                state=Classification.UNREADABLE;
                unreadable++;
            } else {
                readable++;
                long target=o.pointer();
                if(target==0 || target==0xffffffffL) {
                    state=Classification.NULL_OR_ERASED;
                    absent++;
                } else if((target&1)!=0) {
                    state=Classification.ODD_POINTER;
                    odd++;
                } else if(!o.mappedTarget()) {
                    state=Classification.UNMAPPED_TARGET;
                    unmapped++;
                } else if(o.containingFunction()!=null &&
                        !o.containingFunction().isBlank()) {
                    state=Classification.RECOGNIZED_FUNCTION_CANDIDATE;
                    mapped++;functions++;
                } else {
                    state=Classification.MAPPED_TARGET;
                    mapped++;
                }
            }
            // Null/erased values are counted but not printed as "handlers".
            if(state==Classification.NULL_OR_ERASED ||
                    state==Classification.UNREADABLE) continue;
            wanted++;
            if(displayed.size()<maximumDisplayed)
                displayed.add(new Entry(o.vectorNumber(),slot,o.pointer(),
                    state,o.containingFunction()==null?"UNKNOWN":
                        o.containingFunction()));
        }
        return new Summary(tableAddress,sorted.size(),readable,mapped,functions,
            unmapped,odd,unreadable,absent,wanted>displayed.size(),displayed);
    }

    private static String hex(long number) {
        return String.format(Locale.ROOT,"0x%08X",number);
    }
    private static String escape(String word) {
        if(word==null)return "UNKNOWN";
        return word.replace("|","\\|").replace("\r"," ").replace("\n"," ");
    }
}
