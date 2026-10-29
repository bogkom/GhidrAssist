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
            selected.contains("Other peripheral references: 2"),
            "focused site counts and complete inventory count are separate");
        require(selected.contains("direct word values: 2") &&
            selected.contains("writes with UNKNOWN literal: 2") &&
            selected.contains("stores in bounded CFG pass: 9"),
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
        var merged=HardwareStartupEvidenceMerge.reconcile(List.of(
            new HardwareStartupEvidenceMerge.Observation(
                0x2bc0,0x2bca,0xfffa00,"SIMCR",
                HardwareStartupEvidenceMerge.Source.LISTING_REFERENCE,
                true,16,0x40ca,false),
            new HardwareStartupEvidenceMerge.Observation(
                0x2bc0,0x2bca,0xfffa00,"SIMCR",
                HardwareStartupEvidenceMerge.Source.CFG_PCODE,
                true,16,0x40ca,false),
            new HardwareStartupEvidenceMerge.Observation(
                0x2bc0,0x2bcc,-1,"UNRESOLVED_ALIAS",
                HardwareStartupEvidenceMerge.Source.CFG_PCODE,
                true,0,null,true)));
        String unified=HardwareReportOverview.withUnifiedSources(selected,merged);
        require(unified.contains("Source-reconciled Listing + CFG/P-code candidate sites: 1") &&
            unified.contains("raw source observations: 3") &&
            unified.contains("deduplicated matches: 1") &&
            unified.contains("unresolved ANY-MMIO pointer aliases: 1") &&
            unified.contains("NOT an execution count"),
            "overview displays honest deduplicated candidate count");
        require(unified.indexOf("## 1.")<unified.indexOf("## 2.") &&
            unified.indexOf("## 2.")<unified.indexOf("## 3."),
            "unified provenance must preserve overview hierarchy");
        boolean invalid=false;
        try{HardwareReportOverview.render(true,-1,0,0,0,false,sites);}
        catch(IllegalArgumentException expected){invalid=true;}
        require(invalid,"reject negative counts");
        invalid=false;
        try{HardwareReportOverview.render(true,0,0,0,0,false,null);}
        catch(IllegalArgumentException expected){invalid=true;}
        require(invalid,"reject absent source evidence");
        System.out.println("HardwareReportOverviewSelfTest OK");
    }
}
