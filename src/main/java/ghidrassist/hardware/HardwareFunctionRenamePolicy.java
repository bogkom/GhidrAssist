package ghidrassist.hardware;

import java.util.Collection;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Dependency-free policy; Ghidra's mutable project is rechecked at apply time. */
public final class HardwareFunctionRenamePolicy {
    private HardwareFunctionRenamePolicy() {}
    public enum Decision { READY, NAME_CHANGED, NAME_COLLISION, WEAK_OR_UNREVIEWED, INVALID }

    public static Decision check(HardwareFunctionNamingReview.Proposal p,
            String actualName, Collection<String> allExistingNames) {
        if(p==null || actualName==null || allExistingNames==null)
            return Decision.INVALID;
        if(p.status!=HardwareNamingReview.Status.REVIEW_REQUIRED ||
                p.writeSites<3 || p.proposedName==null ||
                !p.proposedName.matches("HW_MC68332_[A-Z0-9_]+_CANDIDATE_[0-9A-F]{8}"))
            return Decision.WEAK_OR_UNREVIEWED;
        if(!actualName.equals(p.currentName) ||
                !actualName.matches("(?i)(FUN|SUB)_[0-9A-F]{4,16}"))
            return Decision.NAME_CHANGED;
        for(String reserved:allExistingNames)
            if(reserved!=null && reserved.equalsIgnoreCase(p.proposedName))
                return Decision.NAME_COLLISION;
        return Decision.READY;
    }
}
