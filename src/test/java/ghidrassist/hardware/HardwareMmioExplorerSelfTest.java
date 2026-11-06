package ghidrassist.hardware;

import java.util.List;

/** Standalone regression for read-only MMIO access inventory (GA-09). */
public final class HardwareMmioExplorerSelfTest {
    private HardwareMmioExplorerSelfTest() {}
    private static void check(boolean condition,String message) {
        if(!condition)throw new AssertionError(message);
    }

    public static void main(String[] args) {
        var input=List.of(
            new HardwareMmioExplorer.Observation(0x200L,0xfffa4cL,"CSBAR0",
                "FUN_B","move.w d0,(0xfffa4c).l",true,null),
            new HardwareMmioExplorer.Observation(0x100L,0xfffa00L,"SIMCR",
                "fun_reset","move.w #0x40ca,(0xfffa00).l",true,0x40ca),
            new HardwareMmioExplorer.Observation(0x300L,0xfffc00L,"QSMCR",
                "FUN_C","cmp.w (0xfffc00).l,d0",false,null));
        var generic=HardwareMmioExplorer.rows(input,false);
        check(generic.size()==3,"include all observed MMIO registers");
        check(generic.get(0).pc()==0x100 && generic.get(0).register().equals("SIMCR"),
            "rows sorted deterministically by instruction address");
        check(generic.get(0).value().equals("0x40CA"),"direct word literal");
        check(generic.get(0).evidence().contains("NOT RUNTIME STATE"),
            "never claim direct immediate is runtime execution");
        check(generic.get(1).value().equals("UNKNOWN") &&
            generic.get(1).access().equals("WRITE CANDIDATE"),
            "write with no literal is not fabricated");
        check(generic.get(2).access().equals("REFERENCE / UNKNOWN") &&
            generic.get(2).evidence().contains("ACCESS DIRECTION UNKNOWN"),
            "Ghidra reference is not an established peripheral read");
        check(generic.stream().allMatch(r->r.deviceScope().contains("SURVEY ONLY")),
            "generic CPU32 may not claim device identification");
        var selected=HardwareMmioExplorer.rows(input,true);
        check(selected.stream().allMatch(r->r.deviceScope().contains("USER-SELECTED")),
            "profile selection must be explicit hypothesis");
        check(selected.get(0).matches("0x00000100") &&
            selected.get(0).matches("SIMCR") &&
            selected.get(0).matches("fun_RESET") &&
            selected.get(0).matches("40ca") &&
            !selected.get(0).matches("csor99"),"filter all displayed columns");
        check(HardwareMmioExplorer.rows(null,false).isEmpty(),"null collection");
        check(HardwareMmioExplorer.rows(List.of(),true).isEmpty(),"empty collection");
        boolean readonly=false;
        try {generic.clear();} catch(UnsupportedOperationException e){readonly=true;}
        check(readonly,"snapshot immutable");
        check(HardwareMmioExplorer.rows(java.util.Arrays.asList(null,input.get(0)),false).size()==1,
            "ignore unrecognized null site");
        var badLiteral=HardwareMmioExplorer.rows(List.of(
            new HardwareMmioExplorer.Observation(0x400L,0xfffa00L,"SIMCR",
                "FUN_D","move.l #0x10000,(0xfffa00).l",true,0x10000),
            new HardwareMmioExplorer.Observation(0x500L,0xfffa00L,"SIMCR",
                "FUN_E","move.w #-1,(0xfffa00).l",true,-1),
            new HardwareMmioExplorer.Observation(0x600L,0xfffa00L,"SIMCR",
                "FUN_F","move.w #0xffff,(0xfffa00).l",true,0xffff)),true);
        check(badLiteral.get(0).value().equals("UNKNOWN") &&
            badLiteral.get(0).evidence().contains("OUT-OF-RANGE"),
            "65536 must not silently wrap to a known 0x0000 word");
        check(badLiteral.get(1).value().equals("UNKNOWN") &&
            badLiteral.get(1).evidence().contains("OUT-OF-RANGE"),
            "negative unnormalized candidate cannot become 0xFFFF");
        check(badLiteral.get(2).value().equals("0xFFFF") &&
            badLiteral.get(2).evidence().contains("NOT RUNTIME STATE"),
            "maximum valid unsigned word remains a source-only candidate");
        check(badLiteral.stream().allMatch(r->r.deviceScope().contains("USER-SELECTED")),
            "range validation cannot assert dynamic MM mode");
        // GUI and JSON-RPC must use the identical source ordering/filter.
        var matching=HardwareMmioExplorer.filter(selected,"simcr");
        check(matching.size()==1 && matching.get(0).pc()==0x100L,
            "shared GUI filtering is deterministic and case-insensitive");
        check(HardwareMmioExplorer.filter(selected,null).equals(selected) &&
            HardwareMmioExplorer.filter(selected,"   ").equals(selected),
            "blank query preserves complete source inventory");
        var firstPage=HardwareMmioExplorer.page(selected,"",0,2);
        var secondPage=HardwareMmioExplorer.page(selected,"",2,2);
        check(firstPage.total()==3 && secondPage.total()==3 &&
            firstPage.rows().size()==2 && secondPage.rows().size()==1 &&
            firstPage.rows().get(0).pc()==0x100 &&
            secondPage.rows().get(0).pc()==0x300,
            "paginated Automation results stitch to exactly the Swing source order");
        var filteredPage=HardwareMmioExplorer.page(selected,"simcr",0,1);
        check(filteredPage.total()==1 && filteredPage.rows().equals(matching),
            "search/page results never differ from visible GUI filter");
        var beyond=HardwareMmioExplorer.page(selected,"simcr",Integer.MAX_VALUE,5);
        check(beyond.rows().isEmpty() && beyond.total()==1,
            "page past end has truthful total and no overflow");
        boolean pageImmutable=false;
        try {firstPage.rows().clear();}
        catch(UnsupportedOperationException expected){pageImmutable=true;}
        check(pageImmutable,"page snapshot is immutable");
        for(int[] bad:new int[][]{{-1,1},{0,0},{0,201}}){
            boolean rejected=false;
            try {HardwareMmioExplorer.page(selected,"",bad[0],bad[1]);}
            catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"invalid pagination must fail before constructing JSON");
        }
        boolean badRows=false;
        try {HardwareMmioExplorer.filter(java.util.Arrays.asList((HardwareMmioExplorer.Row)null),"");}
        catch(IllegalArgumentException expected){badRows=true;}
        check(badRows,"corrupt source row list must fail closed");
        System.out.println("HardwareMmioExplorerSelfTest OK");
    }
}
