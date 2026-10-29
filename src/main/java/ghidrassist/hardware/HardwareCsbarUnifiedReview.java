package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Final read-only safety boundary for speculative CSBAR memory-window
 * proposals. Uses the already deduplicated Listing+CFG/P-code evidence.
 * It does not infer actual CPU address mode, branch execution or CS state.
 */
public final class HardwareCsbarUnifiedReview {
    private HardwareCsbarUnifiedReview() {}

    public record Review(List<HardwareCsbarReviewGate.Candidate> candidates,
                         int matchedSites, int uncertainSites,
                         int unresolvedAliasWrites, boolean deviceSelected) {
        public Review { candidates=List.copyOf(candidates); }
        public String summary() {
            return "Conditional CSBAR source proposals: "+candidates.size()+
                "; matched source sites: "+matchedSites+
                "; unsafe/unknown source sites: "+uncertainSites+
                "; unknown-address CFG stores: "+unresolvedAliasWrites+
                "; model selected: "+deviceSelected+
                ". All candidates are read-only until manual Review/Apply; "+
                "MM latch and actual chip-select assertion UNKNOWN.";
        }
    }

    private static boolean isCsbar(String name) {
        return name!=null && name.matches("CSBAR(?:BT|10|[0-9])");
    }

    public static Review inspect(boolean mc68332Selected,
            HardwareStartupEvidenceMerge.Report merged) {
        if(merged==null)
            throw new IllegalArgumentException("Missing reconciled evidence");
        int aliases=merged.unboundAliasStores();
        if(!mc68332Selected)
            return new Review(List.of(),0,0,aliases,false);

        List<HardwareCsbarReviewGate.Source> observations=new ArrayList<>();
        int sites=0,uncertain=0;
        for(HardwareStartupEvidenceMerge.Row site:merged.rows()) {
            if(!isCsbar(site.candidateRegister()))continue;
            sites++;
            // A byte/long write or any path/call/STORE uncertainty
            // poisons *that register*, rather than letting a known
            // Listing literal override the CFG/P-code observation.
            boolean trustworthy=site.possibleWrite() &&
                site.status()==HardwareStartupEvidenceMerge.Status.FULL_WORD_LITERAL_CANDIDATE &&
                site.widthBits()==16 && !site.conditionalOrUncertain();
            if(site.possibleWrite() && !trustworthy)uncertain++;
            observations.add(new HardwareCsbarReviewGate.Source(
                String.format(Locale.ROOT,"0x%08X@0x%08X",
                    site.function(),site.pc()),
                site.candidateRegister(),site.registerAddress(),
                site.possibleWrite(),trustworthy?site.literalWord():null));
        }

        // Any unknown pointer target may alias *any* CSBAR, including
        // register writes in other functions. Do not infer non-aliasing
        // from absence of an exact address in the inventory.
        if(aliases>0)
            return new Review(List.of(),sites,uncertain,aliases,true);
        var selected=HardwareCsbarReviewGate.reviewCandidates(observations);
        return new Review(selected.candidates(),sites,uncertain,aliases,true);
    }
}
