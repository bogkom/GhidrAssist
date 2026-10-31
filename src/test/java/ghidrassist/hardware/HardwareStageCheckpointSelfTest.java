package ghidrassist.hardware;

public final class HardwareStageCheckpointSelfTest {
    private HardwareStageCheckpointSelfTest(){}
    private static void require(boolean yes,String message){
        if(!yes)throw new AssertionError(message);
    }
    public static void main(String[] args){
        var good=HardwareStageCheckpoint.complete(10,"68000:BE:32:CPU32",
            "import-sha-256",true,"read-only cfg data");
        require(good.stage().equals(HardwareStageCheckpoint.CFG_STAGE) &&
            good.schema().equals(HardwareStageCheckpoint.SCHEMA),
            "stable stage schema");
        require(good.validFor(10,"68000:BE:32:CPU32","import-sha-256",true),
            "unchanged stage can be safely reused by same program owner");
        require(!good.validFor(11,"68000:BE:32:CPU32","import-sha-256",true),
            "edit/Undo/Redo invalidate checkpoint");
        require(!good.validFor(10,"OTHER","import-sha-256",true),
            "language is part of stage token");
        require(!good.validFor(10,"68000:BE:32:CPU32","updated",true),
            "original imported executable metadata changed");
        require(!good.validFor(10,"68000:BE:32:CPU32","import-sha-256",false),
            "MCU profile change invalidates checkpoint");
        var unknown=HardwareStageCheckpoint.complete(0,
            "68000:BE:32:CPU32",null,false,"unknown importer hash");
        require(unknown.validFor(0,"68000:BE:32:CPU32",null,false) &&
            !unknown.validFor(0,"68000:BE:32:CPU32","guessed",false),
            "unknown hash remains unknown");
        require(good.evidence().equals("read-only cfg data"),
            "completed stage preserves exact evidence");
        boolean failed=false;
        try{HardwareStageCheckpoint.complete(-1,"CPU32",null,false,"evidence");}
        catch(IllegalArgumentException x){failed=true;}
        require(failed,"negative revision rejected");
        failed=false;
        try{HardwareStageCheckpoint.complete(1,"CPU32",null,false,null);}
        catch(IllegalArgumentException x){failed=true;}
        require(failed,"incomplete stage must not be cached");
        failed=false;
        try{HardwareStageCheckpoint.complete(1,"",null,false,"evidence");}
        catch(IllegalArgumentException x){failed=true;}
        require(failed,"unknown language rejected");
        System.out.println("HardwareStageCheckpointSelfTest OK");
    }
}
