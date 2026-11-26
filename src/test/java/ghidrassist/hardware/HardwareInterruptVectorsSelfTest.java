package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;

public final class HardwareInterruptVectorsSelfTest {
    private HardwareInterruptVectorsSelfTest() {}
    private static void ok(boolean value,String message){
        if(!value)throw new AssertionError(message);
    }
    private static void rejects(Runnable attempt,String message){
        boolean denied=false;
        try{attempt.run();}
        catch(IllegalArgumentException expected){denied=true;}
        ok(denied,message);
    }
    /** Table separators, excluding a pipe escaped by an odd slash run. */
    private static int markdownColumns(String row) {
        int separators=0;
        for(int i=0;i<row.length();i++) {
            if(row.charAt(i)!='|')continue;
            int slashes=0;
            for(int j=i-1;j>=0 && row.charAt(j)=='\\';j--)slashes++;
            if((slashes&1)==0)separators++;
        }
        return separators-1;
    }
    public static void main(String[] args) {
        var input=new ArrayList<HardwareInterruptVectors.Observation>();
        input.add(new HardwareInterruptVectors.Observation(26,0x3000L,true,"isr_timer",true));
        input.add(new HardwareInterruptVectors.Observation(2,0x1001L,false,null,false));
        input.add(new HardwareInterruptVectors.Observation(24,0x2000L,true,"spurious",true));
        input.add(new HardwareInterruptVectors.Observation(25,0L,false,null,false));
        input.add(new HardwareInterruptVectors.Observation(27,0xffffffffL,false,null,false));
        input.add(new HardwareInterruptVectors.Observation(28,null,false,null,false));
        input.add(new HardwareInterruptVectors.Observation(32,0xabc000L,false,null,false));
        input.add(new HardwareInterruptVectors.Observation(35,0x4000L,true,null,false));
        input.add(new HardwareInterruptVectors.Observation(36,0x5000L,true,"A|B\nname",true));
        input.add(new HardwareInterruptVectors.Observation(37,0x5002L,true,
            "isr_timer @ 0x5000",false));
        var s=HardwareInterruptVectors.inspect(0,input,16);
        ok(s.sampledSlots()==10 && s.readable()==9 && s.plausibleMapped()==5 &&
            s.recognizedFunctions()==3 && s.interiorFunctionPointers()==1 &&
            s.unmapped()==1 &&
            s.odd()==1 && s.absent()==2 && s.unreadable()==1,
            "all input statuses counted independently");
        ok(s.displayed().size()==7 &&
            s.displayed().get(0).vectorNumber()==2 &&
            s.displayed().get(0).classification()==
                HardwareInterruptVectors.Classification.ODD_POINTER,
            "number-sorted vector rows and invalid pointers");
        ok(s.displayed().get(1).label().contains("Spurious") &&
            s.displayed().get(2).label().contains("Autovector level 2"),
            "autovector labels must remain generic CPU family labels");
        ok(s.displayed().get(3).classification()==
            HardwareInterruptVectors.Classification.UNMAPPED_TARGET,
            "unmapped is not a verified handler");
        String md=s.markdown();
        ok(md.contains("runtime VBR UNKNOWN") &&
            md.contains("not proof of") &&
            md.contains("0x00000068") &&
            md.contains("A\\|B name"),
            "table provenance, vector slot, escaping and uncertainty");
        ok(!md.contains("active ISR verified") &&
            md.contains("pointers inside recognized function bodies") &&
            md.contains("INTERIOR_FUNCTION_POINTER_CANDIDATE"),
            "interior function pointers are not handler entries");
        // A 32-bit value above MCU24 range is not the same as an
        // unmapped/odd handler. Only the selected-device scan marks it.
        var deviceOnly=HardwareInterruptVectors.inspect(0x800L,List.of(
            new HardwareInterruptVectors.Observation(
                29,0x01000000L,false,null,false,true),
            new HardwareInterruptVectors.Observation(
                30,0x01000000L,false,null,false)),8);
        ok(deviceOnly.outsideMcu24()==1 && deviceOnly.unmapped()==1 &&
            deviceOnly.displayed().get(0).classification()==
                HardwareInterruptVectors.Classification.OUTSIDE_SELECTED_MCU24_RANGE &&
            deviceOnly.displayed().get(1).classification()==
                HardwareInterruptVectors.Classification.UNMAPPED_TARGET &&
            deviceOnly.markdown().contains("outside explicitly selected MCU24 width: 1"),
            "MC68332 cannot present a 32-bit out-of-range pointer as generic unmapped ISR");
        boolean invalidDevice=false;
        try {
            HardwareInterruptVectors.inspect(0x800L,List.of(
                new HardwareInterruptVectors.Observation(
                    29,0x0000ff00L,false,null,false,true)),8);
        } catch(IllegalArgumentException expected){invalidDevice=true;}
        ok(invalidDevice,"24-bit address cannot be falsely marked out-of-range");
        invalidDevice=false;
        try {
            HardwareInterruptVectors.inspect(0x800L,List.of(
                new HardwareInterruptVectors.Observation(
                    29,0x01000000L,true,"isr",true,true)),8);
        } catch(IllegalArgumentException expected){invalidDevice=true;}
        ok(invalidDevice,"out-of-range pointer cannot simultaneously be a recognized handler");
        // Contradictory evidence must fail closed rather than formatting a
        // named ISR where no Ghidra mapped function can exist.
        rejects(()->HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(2,0x1001L,true,"odd",false)),8),
            "odd vector pointer cannot be a mapped named handler");
        rejects(()->HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(2,null,true,null,false)),8),
            "unreadable vector cannot be marked mapped");
        rejects(()->HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(2,0L,true,null,false)),8),
            "null/erased vector cannot be marked mapped");
        rejects(()->HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(2,0xffffffffL,true,null,false)),8),
            "erased vector cannot be marked mapped");
        rejects(()->HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(2,0x2000L,false,"fake",false)),8),
            "unmapped vector must not carry a Ghidra function name");
        rejects(()->HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(2,0x2000L,true,"  ",false)),8),
            "blank function is not a recognized handler candidate");
        rejects(()->new HardwareInterruptVectors.Summary(0,2,2,1,1,0,
            0,0,0,0,0,false,List.of()),
            "summary must not hide an observed nonempty vector row");
        rejects(()->new HardwareInterruptVectors.Summary(0,1,1,1,2,0,
            0,0,0,0,0,true,List.of()),
            "summary must not claim more exact function entries than mapped targets");
        rejects(()->new HardwareInterruptVectors.Summary(0,1,1,1,0,0,
            0,0,0,0,0,false,List.of()),
            "summary cannot advertise a mapped pointer with no displayed row");
        rejects(()->new HardwareInterruptVectors.Summary(0,2,2,
                Integer.MAX_VALUE,0,0,Integer.MAX_VALUE,
                4,0,0,0,true,List.of()),
            "mapped and unmapped totals cannot wrap to a fake two-slot summary");
        rejects(()->HardwareInterruptVectors.inspect(0,
                java.util.Collections.nCopies(255,
                    new HardwareInterruptVectors.Observation(
                        2,0x1000L,true,null,false)),8),
            "oversized vector inventory fails before allocating/sorting");
        rejects(()->new HardwareInterruptVectors.Summary(0,2,2,2,0,0,
                0,0,0,0,0,false,List.of(
                    new HardwareInterruptVectors.Entry(3,12,0x1000L,
                        HardwareInterruptVectors.Classification.MAPPED_TARGET,"UNKNOWN"),
                    new HardwareInterruptVectors.Entry(2,8,0x2000L,
                        HardwareInterruptVectors.Classification.MAPPED_TARGET,"UNKNOWN"))),
            "out-of-order source vector rows cannot be published");
        var mappedRow=new HardwareInterruptVectors.Entry(2,8,0x1000L,
            HardwareInterruptVectors.Classification.MAPPED_TARGET,"UNKNOWN");
        rejects(()->new HardwareInterruptVectors.Summary(0,1,1,0,0,0,
            1,0,0,0,0,false,List.of(mappedRow)),
            "displayed mapped row cannot contradict unmapped total");
        rejects(()->new HardwareInterruptVectors.Summary(0,2,2,1,1,0,
            1,0,0,0,0,true,List.of(mappedRow)),
            "truncated rows must still respect classification subtotals");
        rejects(()->new HardwareInterruptVectors.Summary(0,1,1,1,0,0,
            0,0,0,0,0,false,List.of(new HardwareInterruptVectors.Entry(
                2,8,0x1001L,HardwareInterruptVectors.Classification.MAPPED_TARGET,"UNKNOWN"))),
            "mapped display cannot contain odd pointer");
        rejects(()->new HardwareInterruptVectors.Summary(0,1,1,1,0,0,
            0,0,0,0,0,true,List.of()),
            "truncated evidence cannot conceal every observed candidate row");
        rejects(()->new HardwareInterruptVectors.Summary(0,1,1,1,1,0,
            0,0,0,0,0,false,List.of(new HardwareInterruptVectors.Entry(
                2,8,0x1000L,
                HardwareInterruptVectors.Classification.RECOGNIZED_FUNCTION_CANDIDATE,"  "))),
            "recognized handler candidate requires a nonblank function name");
        rejects(()->new HardwareInterruptVectors.Summary(0,1,1,1,0,0,
            0,0,0,0,0,false,List.of(new HardwareInterruptVectors.Entry(
                2,8,0x1000L,
                HardwareInterruptVectors.Classification.MAPPED_TARGET,"fake_handler"))),
            "generic mapped target cannot masquerade as named handler");
        var partial=new HardwareInterruptVectors.Summary(0,2,2,1,0,0,
            0,0,1,0,0,true,List.of(mappedRow));
        ok(partial.truncated() && partial.displayed().size()==1 &&
            partial.odd()==1 && partial.markdown().contains("Output truncated"),
            "bounded partial evidence preserves undisplayed classification totals");
        var consistent=new HardwareInterruptVectors.Summary(0,1,1,1,0,0,
            0,0,0,0,0,false,List.of(mappedRow));
        ok(consistent.displayed().equals(List.of(mappedRow)),
            "consistent displayed classification remains accepted");
        var validSummary=new HardwareInterruptVectors.Summary(0,0,0,0,0,0,
            0,0,0,0,0,false,List.of());
        ok(validSummary.sampledSlots()==0 && validSummary.displayed().isEmpty(),
            "legitimate empty static source summary remains valid");
        var bidi=HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(40,0x5000L,true,
                "handler\u202E\u2028name",true)),8);
        ok(bidi.markdown().contains("handler  name") &&
            !bidi.markdown().contains("\u202E") &&
            !bidi.markdown().contains("\u2028"),
            "format and line-separator controls cannot spoof vector report rows");

        // Editable function names must not inject extra Markdown columns,
        // executable HTML, links or code delimiters into GA-11 static evidence.
        String adversarial="one\\|two <img src=x> & [link](https://example.invalid) `code`";
        var guarded=HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(2,0x1000L,true,adversarial,true),
            new HardwareInterruptVectors.Observation(3,0x2000L,true,
                "double\\\\|pipe",false),
            new HardwareInterruptVectors.Observation(4,0x3000L,true,
                "normal_handler",true)),8);
        String safeMarkdown=guarded.markdown();
        String[] reportLines=safeMarkdown.split("\n");
        int vectorRows=0;
        for(String line:reportLines) {
            if(line.startsWith("| 2 |") || line.startsWith("| 3 |") ||
                    line.startsWith("| 4 |")) {
                ok(markdownColumns(line)==6,
                    "one or two input backslashes must not create extra table cells");
                vectorRows++;
            }
        }
        ok(vectorRows==3 && guarded.recognizedFunctions()==2 &&
            guarded.interiorFunctionPointers()==1,
            "adversarial names cannot alter rows or source-only classification");
        ok(safeMarkdown.contains("&lt;img src=x&gt;") &&
            safeMarkdown.contains("&amp;") &&
            safeMarkdown.contains("\\[link\\](https://example.invalid)") &&
            safeMarkdown.contains("\\`code\\`") &&
            !safeMarkdown.contains("<img src=x>") &&
            !safeMarkdown.contains(" [link](https://example.invalid)") &&
            safeMarkdown.contains("normal_handler"),
            "HTML, Markdown links and code markers must render as inert text");
        ok(adversarial.equals(guarded.displayed().get(0).function()) &&
            guarded.displayed().get(1).function().equals("double\\\\|pipe"),
            "escaping is presentation-only and never rewrites original evidence");

        var moved=HardwareInterruptVectors.inspect(0x800L,input,16);
        ok(moved.sampledSlots()==s.sampledSlots() &&
            moved.plausibleMapped()==s.plausibleMapped() &&
            moved.markdown().contains("relocated source-image vector words") &&
            !moved.markdown().contains("image-zero vector words") &&
            moved.markdown().contains("candidate table address 0x00000800"),
            "nonzero source-image table must not be mislabeled image-zero");
        var small=HardwareInterruptVectors.inspect(0,input,2);
        ok(small.truncated() && small.displayed().size()==2 &&
            small.plausibleMapped()==5,"display truncation not a scan truncation");
        var empty=HardwareInterruptVectors.inspect(0,List.of(),2);
        ok(empty.displayed().isEmpty() && empty.sampledSlots()==0,
            "empty input must not claim active ISR");
        boolean duplicate=false;
        try {
            HardwareInterruptVectors.inspect(0,List.of(
                new HardwareInterruptVectors.Observation(2,0x1000L,true,null,false),
                new HardwareInterruptVectors.Observation(2,0x2000L,true,null,false)),8);
        }catch(IllegalArgumentException expected){duplicate=true;}
        ok(duplicate,"duplicate vector cannot masquerade as two observations");
        boolean bad=false;
        try {
            HardwareInterruptVectors.inspect(0,List.of(
                new HardwareInterruptVectors.Observation(1,0x1000L,true,null,false)),8);
        }catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"SP and RESET slots excluded from exception list");
        bad=false;
        try{HardwareInterruptVectors.inspect(1,List.of(),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"unaligned candidate VBR rejected");
        bad=false;
        try{HardwareInterruptVectors.inspect(0,List.of(
                new HardwareInterruptVectors.Observation(254,0x1_0000_0000L,true,null,false)),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"reject pointer outside unsigned 32-bit address range");
        bad=false;
        try{HardwareInterruptVectors.inspect(0xfffffffCL,List.of(
            new HardwareInterruptVectors.Observation(2,0x1000L,true,null,false)),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"vector slot must not wrap 32-bit candidate table address");
        bad=false;
        try{HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(25,0x1000L,true,
                "interior",true)),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(!bad,"explicit positive entry evidence is accepted with a named function");
        bad=false;
        try{HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(25,0x1001L,true,
                "incorrect",true)),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"odd vector must not claim an exact handler entry");
        bad=false;
        try{HardwareInterruptVectors.inspect(0,List.of(
            new HardwareInterruptVectors.Observation(25,0x1000L,true,
                null,true)),8);}
        catch(IllegalArgumentException expected){bad=true;}
        ok(bad,"handler-entry proof requires a recognized named function");
        boolean immutable=false;
        try{s.displayed().clear();}catch(UnsupportedOperationException expected){
            immutable=true;
        }
        ok(immutable,"static result immutable");
        System.out.println("HardwareInterruptVectorsSelfTest OK");
    }
}
