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

    // Bound untrusted Ghidra symbol names in the rendered report only.
    // Evidence rows keep the full original name for independent inspection.
    private static final int MAX_RENDERED_NAME_CODEPOINTS = 256;

    public enum Classification {
        UNREADABLE, NULL_OR_ERASED, ODD_POINTER,
        UNMAPPED_TARGET, OUTSIDE_SELECTED_MCU24_RANGE, MAPPED_TARGET,
        INTERIOR_FUNCTION_POINTER_CANDIDATE,
        RECOGNIZED_FUNCTION_CANDIDATE
    }

    /**
     * One 32-bit vector pointer from a candidate table at an explicitly known
     * image location; null is unreadable, NOT zero. mappedTarget indicates
     * presence in Ghidra's memory map, not proof that the CPU can execute it.
     */
    public record Observation(int vectorNumber, Long pointer,
                              boolean mappedTarget, String containingFunction,
                              boolean exactFunctionEntry,
                              boolean outsideSelectedMcu24Range) {
        /** Existing image-zero/generic CPU32 callers do not assume an MCU. */
        public Observation(int vectorNumber,Long pointer,boolean mappedTarget,
                String containingFunction,boolean exactFunctionEntry) {
            this(vectorNumber,pointer,mappedTarget,containingFunction,
                exactFunctionEntry,false);
        }
    }

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
                          int interiorFunctionPointers, int unmapped, int outsideMcu24,
                          int odd, int unreadable, int absent,
                          boolean truncated, List<Entry> displayed) {
        public Summary {
            if(tableAddress<0 || tableAddress>0xffffffffL ||
                    (tableAddress&3L)!=0 ||
                    sampledSlots<0 || sampledSlots>254 ||
                    readable<0 || plausibleMapped<0 ||
                    recognizedFunctions<0 || interiorFunctionPointers<0 ||
                    unmapped<0 || outsideMcu24<0 || odd<0 ||
                    unreadable<0 || absent<0 ||
                    (long)readable+unreadable!=sampledSlots ||
                    (long)plausibleMapped+unmapped+outsideMcu24+odd+absent!=readable ||
                    (long)recognizedFunctions+interiorFunctionPointers>plausibleMapped ||
                    displayed==null || displayed.size()>64 ||
                    displayed.size()>readable-absent ||
                    (truncated && displayed.isEmpty()) ||
                    truncated!=(displayed.size()<readable-absent))
                throw new IllegalArgumentException("Invalid vector evidence summary");
            displayed=List.copyOf(displayed);
            int previous=1;
            int[] counts=new int[Classification.values().length];
            for(Entry row:displayed){
                if(row.vectorNumber()<=previous || row.vectorNumber()>255 ||
                        row.classification()==Classification.UNREADABLE ||
                        row.classification()==Classification.NULL_OR_ERASED ||
                        row.pointer()==null || row.classification()==null ||
                        row.slotAddress()>0xfffffffcL || row.slotAddress()!=
                            tableAddress+4L*row.vectorNumber())
                    throw new IllegalArgumentException("Invalid displayed vector evidence");
                previous=row.vectorNumber();
                long pointer=row.pointer();
                if(pointer<=0 || pointer>=0xffffffffL ||
                        (row.classification()==Classification.OUTSIDE_SELECTED_MCU24_RANGE
                            ? pointer<=0xffffffL
                            : ((pointer&1L)!=0)!=(row.classification()==Classification.ODD_POINTER)))
                    throw new IllegalArgumentException("Invalid displayed vector pointer");
                // A published handler name must agree with the static
                // classification, including for manually constructed summaries.
                boolean functionCandidate = row.classification()==
                    Classification.RECOGNIZED_FUNCTION_CANDIDATE ||
                    row.classification()==
                    Classification.INTERIOR_FUNCTION_POINTER_CANDIDATE;
                if(functionCandidate ? (row.function()==null ||
                        row.function().isBlank()) :
                        (row.function()!=null &&
                         !"UNKNOWN".equals(row.function())))
                    throw new IllegalArgumentException(
                        "Displayed function evidence contradicts classification");
                counts[row.classification().ordinal()]++;
            }
            int[] limits={0,0,odd,unmapped,outsideMcu24,
                plausibleMapped-recognizedFunctions-interiorFunctionPointers,
                interiorFunctionPointers,recognizedFunctions};
            for(Classification state:Classification.values()) {
                int i=state.ordinal();
                if(counts[i]>limits[i] || (!truncated && counts[i]!=limits[i]))
                    throw new IllegalArgumentException("Displayed vector classification contradicts summary");
            }
        }

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
             .append("; pointers inside recognized function bodies (NOT entries): ")
             .append(interiorFunctionPointers)
             .append("; unmapped: ").append(unmapped)
             .append("; outside explicitly selected MCU24 width: ")
             .append(outsideMcu24)
             .append("; odd: ").append(odd)
             .append("; null/erased: ").append(absent)
             .append("; unreadable: ").append(unreadable).append(".\n\n");
            int abbreviatedNames=0;
            if (!displayed.isEmpty()) {
                b.append("| Vector | Slot | Pointer | Static classification | Function candidate | Role |\n")
                 .append("|---|---|---|---|---|---|\n");
                for (Entry e:displayed) {
                    RenderedName functionName=escape(e.function());
                    if(functionName.abbreviated()) abbreviatedNames++;
                    b.append("| ").append(e.vectorNumber()).append(" | ")
                     .append(hex(e.slotAddress())).append(" | ")
                     .append(e.pointer()==null?"UNKNOWN":hex(e.pointer())).append(" | ")
                     .append(e.classification()).append(" | ")
                     .append(functionName.text()).append(" | ")
                     .append(escape(e.label()).text()).append(" |\n");
                }
                b.append("\n");
            } else {
                b.append("- No nonempty candidate entries in the bounded input. ")
                 .append("This does not establish an empty interrupt table.\n\n");
            }
            if(truncated)
                b.append("- Output truncated to the documented row limit; ")
                 .append("the summary counts cover all inspected slots.\n");
            if(abbreviatedNames>0)
                b.append("- ").append(abbreviatedNames)
                 .append(" displayed function name(s) abbreviated after ")
                 .append(MAX_RENDERED_NAME_CODEPOINTS)
                 .append(" Unicode code points; original source names and ")
                 .append("static classifications remain unchanged.\n");
            b.append("- **STATIC DATA ONLY**: ")
             .append(tableAddress==0?
                 "image-zero vector words":
                 "relocated source-image vector words")
             .append(" are not proof of the current VBR, a valid vector table, active ")
             .append("peripheral assignments or code execution. A mapped address ")
             .append("is not proof of an executable ISR. A pointer into a function ") 
             .append("body is NOT a recognized handler entry. Vector 24 and 25–31 ")
             .append("use generic 68000 spurious/autovector numbering; ")
             .append("device-specific vector meanings are UNKNOWN.\n\n");
            return b.toString();
        }
    }

    public static Summary inspect(long tableAddress, List<Observation> input,
                                  int maximumDisplayed) {
        if(tableAddress<0 || tableAddress>0xffffffffL ||
                (tableAddress & 3)!=0 || input==null || input.size()>254 ||
                maximumDisplayed<1 || maximumDisplayed>64)
            throw new IllegalArgumentException("Invalid vector table parameters");
        List<Observation> sorted=new ArrayList<>(input);
        Set<Integer> seen=new HashSet<>();
        for(Observation o:sorted) {
            if(o==null || o.vectorNumber()<2 || o.vectorNumber()>255 ||
                    !seen.add(o.vectorNumber()) ||
                    (o.pointer()!=null &&
                      (o.pointer()<0 || o.pointer()>0xffffffffL)) ||
                    // An odd, missing or erased pointer cannot also be a
                    // verified mapped handler. A function name from an
                    // unmapped target must not appear as handler evidence.
                    (o.mappedTarget() &&
                        (o.pointer()==null || o.pointer()==0 ||
                         o.pointer()==0xffffffffL || (o.pointer()&1L)!=0)) ||
                    (!o.mappedTarget() && o.containingFunction()!=null) ||
                    (o.containingFunction()!=null &&
                        o.containingFunction().isBlank()) ||
                    (o.outsideSelectedMcu24Range() &&
                     (o.pointer()==null || o.pointer()<=0xffffffL ||
                      o.mappedTarget() || o.containingFunction()!=null ||
                      o.exactFunctionEntry())) ||
                    (o.exactFunctionEntry() &&
                        (!o.mappedTarget() || o.containingFunction()==null ||
                         o.containingFunction().isBlank() || o.pointer()==null ||
                         o.pointer()==0 || o.pointer()==0xffffffffL ||
                         (o.pointer()&1)!=0)))
                throw new IllegalArgumentException("Invalid or duplicate vector entry");
        }
        sorted.sort(Comparator.comparingInt(Observation::vectorNumber));
        int readable=0,mapped=0,functions=0,interior=0,unmapped=0,outside24=0,odd=0,unreadable=0,absent=0;
        List<Entry> displayed=new ArrayList<>();
        int wanted=0;
        for(Observation o:sorted) {
            long slot=tableAddress+4L*o.vectorNumber();
            if(slot>0xffffffffL)
                throw new IllegalArgumentException("Vector slot exceeds 32-bit address space");
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
                } else if(o.outsideSelectedMcu24Range()) {
                    state=Classification.OUTSIDE_SELECTED_MCU24_RANGE;
                    outside24++;
                } else if((target&1)!=0) {
                    state=Classification.ODD_POINTER;
                    odd++;
                } else if(!o.mappedTarget()) {
                    state=Classification.UNMAPPED_TARGET;
                    unmapped++;
                } else if(o.containingFunction()!=null &&
                        !o.containingFunction().isBlank()) {
                    state=o.exactFunctionEntry()?
                        Classification.RECOGNIZED_FUNCTION_CANDIDATE:
                        Classification.INTERIOR_FUNCTION_POINTER_CANDIDATE;
                    mapped++;
                    if(o.exactFunctionEntry())functions++;else interior++;
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
            interior,unmapped,outside24,odd,unreadable,absent,
            wanted>displayed.size(),displayed);
    }

    private static String hex(long number) {
        return String.format(Locale.ROOT,"0x%08X",number);
    }
    private record RenderedName(String text, boolean abbreviated) {}

    private static RenderedName escape(String word) {
        if(word==null)return new RenderedName("UNKNOWN",false);
        StringBuilder escaped=new StringBuilder();
        int at=0,codepoints=0;
        // Do not scan the rest of an attacker-controlled, arbitrarily long
        // symbol. The limit is in code points, so a valid surrogate pair is
        // never split; invalid isolated surrogates become spaces.
        while(at<word.length() && codepoints<MAX_RENDERED_NAME_CODEPOINTS) {
            int c=word.codePointAt(at);
            at+=Character.charCount(c);
            codepoints++;
            int type=Character.getType(c);
            // Names originate in an editable Ghidra symbol table, not in
            // trusted Markdown. Escape backslashes before pipes, otherwise
            // an existing backslash can cancel the pipe escape and inject a
            // new table column. Neutralize HTML, links, inline code, emphasis,
            // and strike-through without altering the source evidence.
            if(c=='\\' || c=='|' || c=='[' || c==']' || c=='`' ||
                    c=='*' || c=='_' || c=='~')
                escaped.append('\\').appendCodePoint(c);
            else if(c=='&')escaped.append("&amp;");
            else if(c=='<')escaped.append("&lt;");
            else if(c=='>')escaped.append("&gt;");
            // Isolated UTF-16 surrogates must not escape into the rendered
            // report or its JSON/HTML transport; paired Unicode stays intact.
            else if(Character.isISOControl(c) ||
                    type==Character.FORMAT ||
                    type==Character.SURROGATE ||
                    type==Character.LINE_SEPARATOR ||
                    type==Character.PARAGRAPH_SEPARATOR)
                escaped.append(' ');
            else escaped.appendCodePoint(c);
        }
        boolean abbreviated=at<word.length();
        if(abbreviated) escaped.append("… (display abbreviated)");
        return new RenderedName(escaped.toString(),abbreviated);
    }
}
