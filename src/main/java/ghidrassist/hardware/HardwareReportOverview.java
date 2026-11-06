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
        String marker="## 2. Register write history — static evidence\n\n";
        // A loose prefix check accepted slightly different heading text,
        // then String.replace silently did nothing. This would present a
        // supposedly unified Overview without its reconciled Listing/CFG
        // source counts. Fail closed instead of dropping source provenance.
        if(listingOverview==null || merged==null ||
                !listingOverview.contains(marker) ||
                listingOverview.indexOf(marker)!=listingOverview.lastIndexOf(marker))
            throw new IllegalArgumentException(
                "Missing or ambiguous exact overview provenance insertion point");
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
        // GA-04/07: exactly twelve *source-coverage* rows from the
        // SAME Listing/XREF input as the three-part summary and full report.
        // These independent counts must never combine CSBAR/CSOR/CSPAR
        // literals into a fabricated active register configuration.
        String csCoverage="";
        if(userSelectedMc68332) {
            int[][] writes=new int[12][3];
            int[][] knownWords=new int[12][3];
            for(Site site:input) {
                if(!site.writeCandidate())continue;
                for(int n=0;n<12;n++) {
                    String suffix=n==0?"BT":Integer.toString(n-1);
                    String pin=n<=6?"CSPAR0":"CSPAR1";
                    String[] names={"CSBAR"+suffix,"CSOR"+suffix,pin};
                    for(int kind=0;kind<3;kind++) {
                        if(!site.register().equals(names[kind]))continue;
                        writes[n][kind]++;
                        if(site.literalKnown())knownWords[n][kind]++;
                    }
                }
            }
            StringBuilder coverage=new StringBuilder(
                "\n**Twelve-select Listing/XREF source coverage (GA-04/07; NOT a decoded map)**\n\n")
                .append("| Chip Select | CSBAR known/WRITE sites | CSOR known/WRITE sites | Shared CSPAR known/WRITE sites |\n")
                .append("|---|---|---|---|\n");
            for(int n=0;n<12;n++) {
                coverage.append("| ").append(n==0?"CSBOOT":"CS"+(n-1));
                for(int kind=0;kind<3;kind++)
                    coverage.append(" | ").append(knownWords[n][kind])
                        .append("/").append(writes[n][kind]);
                coverage.append(" |\n");
            }
            coverage.append("\n0/0 means no write source was observed in this ")
                .append("Listing/XREF inventory, NOT that the register is absent ")
                .append("or the select inactive. CSPAR0/1 sources are shared ")
                .append("by multiple rows, never independent per-select writes. ")
                .append("No CSBAR/CSOR/CSPAR literals are combined across ")
                .append("functions, MM windows or branch alternatives. ")
                .append("Consult function-local conditional snapshots in ")
                .append("Full evidence; physical CS remains UNKNOWN.\n");
            csCoverage=coverage.toString();
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
            csCoverage +
            "- Address windows do not establish chip presence, bus cycles " +
            "or external wiring. Full source evidence is preserved in the " +
            "details, Markdown export and RAG context.\n";
    }
}
