package ghidrassist.hardware;

import java.util.List;

/** Dependency-free three-part overview safety and consistency regression. */
public final class HardwareReportOverviewSelfTest {
    private HardwareReportOverviewSelfTest() {}
    private static void require(boolean ok,String message){
        if(!ok)throw new AssertionError(message);
    }
    public static void main(String[] args) {
        List<HardwareReportOverview.Site> sites=List.of(
            new HardwareReportOverview.Site("SIMCR",true,true),
            new HardwareReportOverview.Site("SIMCR",true,false),
            new HardwareReportOverview.Site("TRAMBAR",false,false),
            new HardwareReportOverview.Site("CSBAR0",true,true),
            new HardwareReportOverview.Site("CSOR0",true,false),
            new HardwareReportOverview.Site("CSPAR0",true,true),
            new HardwareReportOverview.Site("QSMCR",true,true)
        );
        String selected=HardwareReportOverview.render(true,1500,3,4,9,true,sites);
        require(selected.indexOf("## 1. Initialization") <
            selected.indexOf("## 2. Register write history") &&
            selected.indexOf("## 2. Register write history") <
            selected.indexOf("## 3. Chip Select map"),"stable three-part order");
        require(selected.contains("focused initialization register sites: 5") &&
            selected.contains("SIMCR/MM sites: 2") &&
            selected.contains("CSBAR sites: 1") &&
            selected.contains("CSOR sites: 1") &&
            selected.contains("Other/omitted register references (including CSPAR): 2"),
            "focused site counts and complete inventory count are separate");
        require(selected.contains("direct word values: 2") &&
            selected.contains("writes with UNKNOWN literal: 2") &&
            selected.contains("stores in bounded CFG pass: at least 9"),
            "known/unknown only for visible candidate writes");
        require(selected.contains("propagation cap reached: true") &&
            selected.contains("first successful write") &&
            selected.contains("remain UNKNOWN") &&
            selected.contains("NOT a single proven active CS map"),
            "status must not assert a dynamic execution history");
        String cpu=HardwareReportOverview.render(false,0,0,0,0,false,List.of());
        require(cpu.contains("CPU32 — address survey ONLY") &&
            cpu.contains("No MC68332 CS ranges are asserted") &&
            cpu.contains("focused initialization register sites: 0"),
            "generic CPU32 does not inherit MCU-specific map");
        boolean invalid=false;
        try{HardwareReportOverview.render(true,-1,0,0,0,false,sites);}
        catch(IllegalArgumentException expected){invalid=true;}
        require(invalid,"reject negative counts");
        invalid=false;
        try{HardwareReportOverview.render(true,0,0,0,0,false,null);}
        catch(IllegalArgumentException expected){invalid=true;}
        require(invalid,"reject absent source evidence");
        require(selected.contains("INCOMPLETE / TRUNCATED") &&
            selected.contains("lower bound; scan truncated"),
            "bounded CFG counts must never imply full scan coverage");
        require(cpu.contains("BOUNDED PASS COMPLETE") &&
            !cpu.contains("INCOMPLETE / TRUNCATED"),
            "nontruncated scan does not gain invented truncation");
        for(HardwareReportOverview.Site invalidSite:new HardwareReportOverview.Site[]{
                null,new HardwareReportOverview.Site(null,true,true),
                new HardwareReportOverview.Site(" ",false,false),
                new HardwareReportOverview.Site("SIMCR",false,true)
        }){
            boolean rejected=false;
            java.util.ArrayList<HardwareReportOverview.Site> badRows=
                new java.util.ArrayList<>(sites);
            badRows.add(invalidSite);
            try{HardwareReportOverview.render(true,1500,3,4,9,true,badRows);}
            catch(IllegalArgumentException expected){rejected=true;}
            require(rejected,"invalid overview evidence may not be counted as complete");
        }
        boolean tooMany=false;
        try{HardwareReportOverview.render(true,1500,3,4,9,false,
            java.util.Collections.nCopies(200001,
                new HardwareReportOverview.Site("SIMCR",true,true)));}
        catch(IllegalArgumentException expected){tooMany=true;}
        require(tooMany,"oversized source inventory must fail closed");
        System.out.println("HardwareReportOverviewSelfTest OK");
    }
}
