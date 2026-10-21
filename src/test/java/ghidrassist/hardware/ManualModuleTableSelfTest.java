package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;

/** Offline synthetic geometry fixture: no firmware, PDF or Ghidra dependencies. */
public final class ManualModuleTableSelfTest {
    private static void ok(boolean v,String message){if(!v)throw new AssertionError(message);}
    private static void row(List<ManualModuleTable.Word> words, int y,
            String name, String size, String address){
        float x=90;
        for(String word:name.split(" ")){
            words.add(new ManualModuleTable.Word(word,x,x+word.length()*6,y));
            x+=word.length()*6+5;
        }
        words.add(new ManualModuleTable.Word(size,260,260+size.length()*7,y));
        words.add(new ManualModuleTable.Word(address,375,435,y));
    }
    public static void main(String[] args){
        String caption="APPENDIX D REGISTER SUMMARY\nTable D-1 Module Address Map\n"+
            "Module Size (Bytes) Base Address";
        List<ManualModuleTable.Word> glyphs=new ArrayList<>();
        row(glyphs,100,"SIM","128","$YFFA00");
        row(glyphs,120,"TPURAM CNTL","64","$YFFB00");
        row(glyphs,140,"QSM","512","$YFFC00");
        row(glyphs,160,"TPU","512","$YFFE00");
        List<ManualModuleTable.Candidate> found=
            ManualModuleTable.parsePage(215,caption,glyphs);
        ok(found.size()==4,"all four D-1 module rows");
        ok(found.get(0).candidateBase==0xfffa00L &&
            found.get(0).sizeBytes==128,"SIM geometry row");
        ok(found.get(1).module.equals("TPURAM CNTL") &&
            found.get(1).sizeBytes==64,"multiword module");
        ok(found.get(2).candidateBase==0xfffc00L &&
            found.get(3).candidateBase==0xfffe00L,"QSM/TPU");
        ok(found.stream().allMatch(c->c.pdfPage==215 && c.mmDependent &&
            c.provenance.contains("DEVICE_UNVERIFIED")),"provenance and uncertainty");
        // MC68336/376 uses a separately published Appendix D, which is
        // PDF page 1 in MC68336376UMD but PDF page 319 in the full manual.
        // Table D-1 contains a non-power-of-two 384-byte TouCAN aperture
        // restricted to the MC68376 device (not MC68336).
        List<ManualModuleTable.Word> newer=new ArrayList<>();
        row(newer,80,"SIM","128","$YFFA00");
        row(newer,100,"SRAM","8","$YFFB40");
        row(newer,120,"MRM (MC68376 Only)","32","$YFF820");
        row(newer,140,"QADC","512","$YFF200");
        row(newer,160,"QSM","512","$YFFC00");
        row(newer,180,"CTM4","256","$YFF400");
        row(newer,200,"TPU","512","$YFFE00");
        row(newer,220,"TPURAM","64","$YFFB00");
        row(newer,240,"TouCAN (MC68376 Only)","384","$YFF080");
        var chapter=ManualModuleTable.parsePage(1,caption,newer);
        var combined=ManualModuleTable.parsePage(319,caption,newer);
        ok(chapter.size()==9 && combined.size()==9,
            "MC68336/376 D-1 nine documented apertures");
        ok(chapter.get(8).sizeBytes==384 &&
            chapter.get(8).candidateBase==0xfff080L &&
            chapter.get(8).modelConstraint.equals("MC68376_ONLY"),
            "TouCAN 384-byte aperture is MC68376-only");
        ok(chapter.get(2).module.contains("MRM") &&
            chapter.get(2).modelConstraint.equals("MC68376_ONLY"),
            "MRM applicability is not common to MC68336");
        ok(combined.get(0).pdfPage==319 && chapter.get(0).pdfPage==1,
            "printed D-1 has different 1-based PDF page in book vs chapter");
        ok(ManualModuleTable.parsePage(215,"other page",glyphs).isEmpty(),
            "title required");
        List<ManualModuleTable.Word> collided=new ArrayList<>(glyphs);
        row(collided,180,"SIM","256","$YFFA00");
        ok(ManualModuleTable.parsePage(215,caption,collided).isEmpty(),
            "conflicting duplicate must not become actionable");
        List<ManualModuleTable.Word> compact=new ArrayList<>();
        compact.add(new ManualModuleTable.Word("SIM",100,130,120));
        compact.add(new ManualModuleTable.Word("128",132,153,120));
        compact.add(new ManualModuleTable.Word("$YFFA00",155,210,120));
        ok(ManualModuleTable.parsePage(215,caption,compact).isEmpty(),
            "no spatially overlapping columns");
        ok(ManualModuleTable.parsePage(215,caption,List.of()).isEmpty(),
            "without geometry there is no table");
        ok(ManualModuleTable.evidenceTail(215,caption,glyphs,2)
            .contains("device=UNVERIFIED"),"evidence must be cautionary");
        System.out.println("ManualModuleTableSelfTest OK");
    }
}
