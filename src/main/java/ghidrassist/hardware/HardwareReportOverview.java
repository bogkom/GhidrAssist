package ghidrassist.hardware;

import java.util.List;

/**
 * Small deterministic, read-only overview derived from exactly the same
 * inventory and CFG evidence as the detailed Analyze/Export/RAG report.
 * Site counts never become inferred runtime events or MCU identification.
 */
public final class HardwareReportOverview {
    private HardwareReportOverview() {}

    public record Site(String register, boolean writeCandidate, boolean literalKnown) {}

    /**
     * The historical Listing/XREF figures stay separately labeled: adding
     * CFG-only sites to them would double-count shared source instructions.
     */
    public static String withUnifiedSources(String listingOverview,
            HardwareStartupEvidenceMerge.Report merged) {
        if(listingOverview==null || merged==null ||
                !listingOverview.contains("## 2. Register write history"))
            throw new IllegalArgumentException("Invalid overview/unified evidence");
        String marker="## 2. Register write history — static evidence\n\n";
        String note="- Source-reconciled Listing + CFG/P-code candidate sites: "+
            merged.rows().size()+" (raw source observations: "+merged.rawSites()+
            ", deduplicated matches: "+merged.duplicateSources()+
            ", conflicting sites: "+merged.conflicts()+
            ", unresolved ANY-MMIO pointer aliases: "+
            merged.unboundAliasStores()+"). These are static source "+
            "candidates, NOT an execution count or verified hardware state.\n";
        return listingOverview.replace(marker,marker+note);
    }

    public static String render(boolean userSelectedMc68332, int listingScanned,
            int initializationFunctions, int vbrCandidates, int unknownIndirectStores,
            boolean cfgLimited, List<Site> input) {
        if(listingScanned<0 || initializationFunctions<0 || vbrCandidates<0 ||
                unknownIndirectStores<0 || input==null)
            throw new IllegalArgumentException("Invalid overview evidence");
        if(input.size()>200000)
            throw new IllegalArgumentException(
                "Oversized overview evidence: counts not known to be complete");
        int visible=0,hidden=0,simcr=0,tram=0,csbar=0,csor=0,known=0,unknown=0;
        for(Site site:input) {
            if(site==null || site.register()==null || site.register().isBlank() ||
                    (site.literalKnown() && !site.writeCandidate()))
                throw new IllegalArgumentException("Invalid/inconsistent overview evidence row");
            if(!HardwareReportScope.isInitializationRegister(site.register())) {
                hidden++;
                continue;
            }
            visible++;
            String name=site.register();
            if("SIMCR".equals(name))simcr++;
            else if("TRAMBAR".equals(name))tram++;
            else if(name.startsWith("CSBAR"))csbar++;
            else if(name.startsWith("CSOR"))csor++;
            if(site.writeCandidate()) {
                if(site.literalKnown())known++;else unknown++;
            }
        }
        return "# Hardware Analyze — three-part overview (READ ONLY)\n\n" +
            "- Profile: **" + (userSelectedMc68332?
                "MC68332 — user-selected HYPOTHESIS":"CPU32 — address survey ONLY") +
            "**; firmware execution, hardware wiring and actual MM/VBR states UNKNOWN.\n" +
            "- This overview, full evidence tab, exported Markdown and RAG context " +
            "use the same current-revision evidence; scan completeness must "+
            "be checked separately. No Ghidra database or firmware writes.\n" +
            "- CFG/P-code source coverage: **" +
                (cfgLimited ? "INCOMPLETE / TRUNCATED" : "BOUNDED PASS COMPLETE") +
                "**; neither status proves dynamic execution.\n\n" +
            "## 1. Initialization candidates\n\n" +
            "- Listing instructions inspected: "+listingScanned+
            "; focused initialization register sites: "+visible+
            "; candidate functions: "+initializationFunctions+".\n"+
            "- SIMCR/MM sites: "+simcr+"; TRAMBAR sites: "+tram+
            "; CSBAR sites: "+csbar+"; CSOR sites: "+csor+
            "; VBR MOVEC sightings: "+vbrCandidates+".\n"+
            "- Other/omitted register references (including CSPAR): "+hidden+
            " (not expanded in focused overview; full register definitions are " +
            "available in Review / Apply).\n\n"+
            "## 2. Register write history — static evidence\n\n"+
            "- Focused write candidates with direct word values: "+known+
            "; writes with UNKNOWN literal: "+unknown+
            "; unresolved register-indirect stores in bounded CFG pass: "+
            (cfgLimited?"at least ":"")+unknownIndirectStores+
            (cfgLimited?" (lower bound; scan truncated)":"")+
            "; propagation cap reached: "+cfgLimited+".\n"+
            "- Local branch paths, caller effects, first successful write to " +
            "write-once MM and actual execution ordering remain UNKNOWN. " +
            "See **Full evidence** for source instruction addresses and " +
            "bounded CFG details.\n\n"+
            "## 3. Chip Select map — conditional hypothesis\n\n"+
            "- CSBAR candidates: "+csbar+"; CSOR candidates: "+csor+". "+
            (userSelectedMc68332 ?
                "The documented MC68332 interpretation may show conditional " +
                "CSBOOT/CS0–CS10 rows in **Full evidence**; rows across " +
                "functions/branches are NOT a single proven active CS map.\n" :
                "No MC68332 CS ranges are asserted in generic CPU32 mode.\n")+
            "- Address windows do not establish chip presence, bus cycles " +
            "or external wiring. Full source evidence is preserved in the " +
            "details, Markdown export and RAG context.\n";
    }
}
