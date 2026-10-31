package ghidrassist.hardware;

/** Negative revision tests requiring no Ghidra installation. */
public final class HardwareAnalysisRevisionSelfTest {
    private HardwareAnalysisRevisionSelfTest() {}
    private static void check(boolean truth,String why) {
        if(!truth)throw new AssertionError(why);
    }
    public static void main(String[] args) {
        Object prog=new Object(), clone=new Object();
        var original=HardwareAnalysisRevision.capture(prog,42,"68000:BE:32:CPU32",
            "original-sha",true);
        check(original.matches(prog,42,"68000:BE:32:CPU32","original-sha",true),
            "identical revision may safely reuse a read-only snapshot");
        check(!original.matches(clone,42,"68000:BE:32:CPU32","original-sha",true),
            "a distinct open project with the same metadata must not reuse");
        check(!original.matches(prog,43,"68000:BE:32:CPU32","original-sha",true),
            "Ghidra edit/undo/redo must invalidate");
        check(!original.matches(prog,42,"OTHER:LE:32:default","original-sha",true),
            "language changed");
        check(!original.matches(prog,42,"68000:BE:32:CPU32","other-sha",true),
            "source executable metadata changed");
        check(!original.matches(prog,42,"68000:BE:32:CPU32","original-sha",false),
            "CPU profile selection changed");
        check(original.same(HardwareAnalysisRevision.capture(prog,42,
            "68000:BE:32:CPU32","original-sha",true)),
            "equivalent point-in-time scan token");
        check(!original.same(null),"missing checkpoint is invalid");
        var unknownSha=HardwareAnalysisRevision.capture(prog,0,
            "68000:BE:32:CPU32",null,false);
        check(unknownSha.matches(prog,0,"68000:BE:32:CPU32",null,false),
            "original binary hash may legitimately be unavailable");
        check(!unknownSha.matches(prog,0,"68000:BE:32:CPU32","fabricated",false),
            "unknown SHA must not be replaced with a guessed hash");
        boolean bad=false;
        try{HardwareAnalysisRevision.capture(null,0,"cpu32",null,false);}
        catch(IllegalArgumentException expected){bad=true;}
        check(bad,"reject absent program identity");
        bad=false;
        try{HardwareAnalysisRevision.capture(prog,-1,"cpu32",null,false);}
        catch(IllegalArgumentException expected){bad=true;}
        check(bad,"reject negative counter");
        bad=false;
        try{HardwareAnalysisRevision.capture(prog,0,"",null,false);}
        catch(IllegalArgumentException expected){bad=true;}
        check(bad,"reject unknown language");
        check(HardwareAnalysisRevision.ALGORITHM.equals("GA12-REV1"),
            "explicit schema revision invalidation");
        System.out.println("HardwareAnalysisRevisionSelfTest OK");
    }
}
