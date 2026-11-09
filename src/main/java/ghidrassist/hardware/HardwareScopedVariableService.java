package ghidrassist.hardware;

import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * GA-05/08: exact existing Ghidra Function-variable names, never inferred
 * decompiler HighVariables or A-register role annotations. Every edit must
 * be explicitly approved for the same Program revision and is undoable.
 */
public final class HardwareScopedVariableService {
    private HardwareScopedVariableService() {}

    public record Outcome(int renamed,List<String> changes) {
        public Outcome { changes=List.copyOf(changes); }
    }

    private static Variable get(Function fn,HardwareScopedVariableReview.Observation o) {
        if(fn==null || o==null ||
                fn.getEntryPoint().getOffset()!=o.functionEntry())return null;
        Variable[] variables=o.kind()==HardwareScopedVariableReview.Kind.PARAMETER
            ?fn.getParameters():fn.getLocalVariables();
        for(int i=0;i<variables.length;i++) {
            Variable v=variables[i];
            int ordinal=v instanceof Parameter p ? p.getOrdinal():i;
            if(ordinal==o.ordinal() && v.getVariableStorage()!=null &&
                    o.storage().equals(v.getVariableStorage().toString()))
                return v;
        }
        return null;
    }

    private static HardwareScopedVariableReview.Observation observe(
            Function fn,Variable v,int ordinal) {
        HardwareScopedVariableReview.Kind kind=v instanceof Parameter ?
            HardwareScopedVariableReview.Kind.PARAMETER :
            HardwareScopedVariableReview.Kind.LOCAL;
        return new HardwareScopedVariableReview.Observation(
            fn.getEntryPoint().getOffset(),v.getName(),kind,ordinal,
            v.getVariableStorage()==null?"UNASSIGNED":
                v.getVariableStorage().toString(),
            v.getDataType() instanceof Pointer,
            v.getSource()==SourceType.USER_DEFINED,
            v instanceof Parameter p && (p.isAutoParameter() || p.isForcedIndirect()));
    }

    /** Read-only proposals for actual typed pointer arguments and locals. */
    public static List<HardwareScopedVariableReview.Proposal> preview(Function fn) {
        if(fn==null)throw new IllegalArgumentException("Missing function");
        List<HardwareScopedVariableReview.Observation> observations=new ArrayList<>();
        for(Parameter p:fn.getParameters()) {
            if(p.getOrdinal()<0)continue;
            observations.add(observe(fn,p,p.getOrdinal()));
        }
        Variable[] locals=fn.getLocalVariables();
        for(int i=0;i<locals.length;i++)
            observations.add(observe(fn,locals[i],i));
        return HardwareScopedVariableReview.propose(observations);
    }

    /**
     * A single all-or-nothing Ghidra transaction. No Write before checking
     * all row identities, datatype, storage, source and namespace collisions.
     */
    public static Outcome apply(Program program,
            List<HardwareScopedVariableReview.Proposal> accepted,
            HardwareAnalysisRevision reviewed) throws Exception {
        if(program==null || accepted==null || accepted.isEmpty() ||
                accepted.size()>256)
            throw new IllegalArgumentException("Missing/oversized approval set");
        HardwareFunctionRenameRevisionGate.requireCurrent(reviewed,program,
            program.getModificationNumber(),program.getLanguageID().toString(),
            program.getExecutableSHA256(),true);
        Set<String> selected=new HashSet<>();
        for(var p:accepted) {
            if(p==null || p.decision()!=HardwareScopedVariableReview.Decision.READY ||
                    !selected.add(p.original().functionEntry()+"/"+
                        p.original().kind()+"/"+p.original().ordinal()))
                throw new IllegalArgumentException("Duplicate or unreviewed variable");
        }
        int tx=program.startTransaction("GhidrAssist: explicitly approved pointer variable names");
        boolean commit=false;
        List<String> changed=new ArrayList<>();
        try {
            HardwareFunctionRenameRevisionGate.requireCurrent(reviewed,program,
                program.getModificationNumber(),program.getLanguageID().toString(),
                program.getExecutableSHA256(),true);
            List<Variable> targets=new ArrayList<>();
            for(var p:accepted) {
                Function fn=program.getFunctionManager().getFunctionAt(
                    program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(p.original().functionEntry()));
                Variable target=get(fn,p.original());
                if(target==null)
                    throw new IllegalStateException("Variable disappeared or storage changed");
                HardwareScopedVariableReview.Observation actual=observe(
                    fn,target,p.original().ordinal());
                List<String> currentNames=new ArrayList<>();
                for(Variable other:fn.getAllVariables())
                    if(other!=target) currentNames.add(other.getName());
                if(HardwareScopedVariableReview.recheck(p,actual,currentNames)!=
                        HardwareScopedVariableReview.Decision.READY)
                    throw new IllegalStateException("Variable preview stale or name collision");
                targets.add(target);
            }
            // Selected targets within each Function must not collide.
            Set<String> newNames=new HashSet<>();
            for(var p:accepted)
                if(!newNames.add(p.original().functionEntry()+"/"+
                        p.proposedName().toUpperCase(java.util.Locale.ROOT)))
                    throw new IllegalStateException("Duplicate proposed function variable name");
            for(int i=0;i<targets.size();i++){
                Variable v=targets.get(i);
                var p=accepted.get(i);
                v.setName(p.proposedName(),SourceType.USER_DEFINED);
                changed.add(p.original().currentName()+" -> "+p.proposedName());
            }
            commit=true;
            return new Outcome(changed.size(),changed);
        } finally {
            program.endTransaction(tx,commit);
        }
    }
}
