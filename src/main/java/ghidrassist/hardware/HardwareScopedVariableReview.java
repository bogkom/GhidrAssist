package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * GA-05/08: conservative proposals for EXISTING, identity-resolved
 * Ghidra Function variables. A-register role hints are never variable
 * identities and cannot be used as Apply inputs.
 */
public final class HardwareScopedVariableReview {
    private HardwareScopedVariableReview() {}

    public enum Kind { PARAMETER, LOCAL }
    public enum Decision {
        READY, USER_NAMED, UNSUPPORTED_TYPE, UNSAFE_STORAGE, NAME_COLLISION,
        STALE_OR_CHANGED, INVALID
    }

    /** Snapshot of a Ghidra Variable; storage/ordinal must identify one row. */
    public record Observation(long functionEntry,String currentName,Kind kind,
            int ordinal,String storage,boolean pointerType,boolean userDefined,
            boolean autoParameter) {
        public Observation {
            if(functionEntry<0 || functionEntry>0xffffffL ||
                    currentName==null || currentName.isBlank() ||
                    currentName.length()>256 || kind==null ||
                    ordinal<0 || ordinal>1024 ||
                    storage==null || storage.isBlank() || storage.length()>256)
                throw new IllegalArgumentException("Invalid function-local variable evidence");
        }
    }

    /** NOT a Ghidra approval token: the live Program is rechecked at Apply. */
    public record Proposal(Observation original,String proposedName,
                           Decision decision) {
        public Proposal {
            if(original==null || proposedName==null || decision==null ||
                    proposedName.length()>128)
                throw new IllegalArgumentException("Invalid variable proposal");
        }
    }

    private static boolean generated(String name,Kind kind) {
        return kind==Kind.PARAMETER ?
            name.matches("(?i)param_[0-9]+") :
            name.matches("(?i)local_[a-z0-9_]+");
    }

    /** No implicit MCU identity, inferred pointer role, or register alias. */
    public static List<Proposal> propose(List<Observation> rows) {
        if(rows==null || rows.size()>2048)
            throw new IllegalArgumentException("Missing or excessive variable inventory");
        // Ghidra parameters and locals have FUNCTION-LOCAL namespaces.
        // Aggregate Review across multiple functions must neither reject
        // independent variables sharing an ordinal/storage nor invent a
        // collision because another function already uses the proposed name.
        java.util.Map<Long,Set<String>> usedByFunction=new java.util.HashMap<>();
        for(Observation row:rows) {
            if(row==null)throw new IllegalArgumentException("Null variable observation");
            usedByFunction.computeIfAbsent(row.functionEntry(),
                unused->new HashSet<>()).add(row.currentName().toUpperCase(Locale.ROOT));
        }
        List<Proposal> proposals=new ArrayList<>();
        Set<String> identity=new HashSet<>();
        for(Observation row:rows) {
            // One function/kind/ordinal must resolve to one exact storage.
            // Two conflicting storages under the same ordinal fail CLOSED.
            String key=row.functionEntry()+"/"+row.kind()+"/"+row.ordinal();
            if(!identity.add(key))
                throw new IllegalArgumentException("Ambiguous function variable identity");
            String candidate=row.kind()==Kind.PARAMETER ?
                "ga_arg_ptr_candidate_"+row.ordinal() :
                "ga_local_ptr_candidate_"+row.ordinal();
            Decision decision;
            if(row.userDefined() || !generated(row.currentName(),row.kind()))
                decision=Decision.USER_NAMED;
            else if(!row.pointerType())
                decision=Decision.UNSUPPORTED_TYPE;
            else if(row.autoParameter() ||
                    "UNASSIGNED".equalsIgnoreCase(row.storage()))
                decision=Decision.UNSAFE_STORAGE;
            else if(usedByFunction.get(row.functionEntry())
                    .contains(candidate.toUpperCase(Locale.ROOT)))
                decision=Decision.NAME_COLLISION;
            else decision=Decision.READY;
            proposals.add(new Proposal(row,
                decision==Decision.READY?candidate:"",decision));
        }
        return List.copyOf(proposals);
    }

    public static Decision recheck(Proposal proposal,Observation current,
                                    List<String> currentNames) {
        if(proposal==null || current==null || currentNames==null)
            return Decision.INVALID;
        if(proposal.decision()!=Decision.READY ||
                !proposal.proposedName().matches(
                    "ga_(?:arg|local)_ptr_candidate_[0-9]{1,4}"))
            return Decision.INVALID;
        if(!proposal.original().equals(current))
            return Decision.STALE_OR_CHANGED;
        // Never trust the requested READY flag: callers can construct a
        // public Proposal. Derive eligibility again from live typed data.
        Proposal recalculated=propose(List.of(current)).get(0);
        if(recalculated.decision()!=Decision.READY ||
                !recalculated.proposedName().equals(proposal.proposedName()))
            return Decision.INVALID;
        for(String n:currentNames) {
            if(n!=null && n.equalsIgnoreCase(proposal.proposedName()))
                return Decision.NAME_COLLISION;
        }
        return Decision.READY;
    }
}
