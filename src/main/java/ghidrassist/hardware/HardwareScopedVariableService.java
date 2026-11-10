package ghidrassist.hardware;

import ghidra.framework.options.Options;
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
            v instanceof Parameter p && (p.isAutoParameter() || p.isForcedIndirect()),
            v.getDataType().getPathName()+"#length="+v.getDataType().getLength(),
            v.getFirstUseOffset());
    }

    /** Exact Function/kind/ordinal selection, to detect stale storage in audits. */
    private static Variable byOrdinal(Function fn,
            HardwareScopedVariableReview.Kind kind,int ordinal) {
        if(fn==null || kind==null)return null;
        Variable[] vars=kind==HardwareScopedVariableReview.Kind.PARAMETER?
            fn.getParameters():fn.getLocalVariables();
        for(int i=0;i<vars.length;i++) {
            Variable v=vars[i];
            int index=v instanceof Parameter p?p.getOrdinal():i;
            if(index==ordinal)return v;
        }
        return null;
    }

    /**
     * Read-only correlation of receipts stored in the Program's own Ghidra
     * Options, without fabricating an append-only user or model actor log.
     * Native Ghidra Undo can remove the receipt with the corresponding name.
     */
    public static HardwareScopedVariableReceipt.Snapshot audit(Program program) {
        if(program==null)throw new IllegalArgumentException("Missing Program");
        long before=program.getModificationNumber();
        String sha=program.getExecutableSHA256();
        if(sha==null)sha="UNKNOWN";
        List<HardwareScopedVariableReceipt.Observation> rows=new ArrayList<>();
        if(program.getOptionsNames().contains(
                HardwareScopedVariableReceipt.OPTIONS_CATEGORY)) {
            Options receipts=program.getOptions(
                HardwareScopedVariableReceipt.OPTIONS_CATEGORY);
            List<String> keys=receipts.getOptionNames();
            if(keys.size()>HardwareScopedVariableReceipt.MAX_ROWS)
                throw new IllegalStateException("Unbounded variable receipts");
            for(String key:keys) {
                if(key==null || !key.matches("PV_[0-9A-F]{8}_[PL]_[0-9]{4}"))
                    throw new IllegalStateException("Unexpected variable receipt key");
                String stored=receipts.getString(key,null);
                if(stored==null)
                    throw new IllegalStateException("Missing persisted variable receipt");
                var entry=HardwareScopedVariableReceipt.decode(stored);
                if(!entry.optionKey().equals(key))
                    throw new IllegalStateException("Mismatched variable receipt owner");
                Function fn=program.getFunctionManager().getFunctionAt(
                    program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(entry.function()));
                Variable live=byOrdinal(fn,entry.kind(),entry.ordinal());
                rows.add(new HardwareScopedVariableReceipt.Observation(
                    key,stored,live==null?null:live.getName(),
                    live==null || live.getVariableStorage()==null?
                        null:live.getVariableStorage().toString(),
                    live!=null && live.getDataType() instanceof Pointer,
                    live!=null && live.getSource()==SourceType.USER_DEFINED,
                    live instanceof Parameter p &&
                        (p.isAutoParameter() || p.isForcedIndirect()),
                    live==null || live.getDataType()==null?null:
                        live.getDataType().getPathName()+"#length="+
                            live.getDataType().getLength(),
                    live==null?Integer.MIN_VALUE:live.getFirstUseOffset()));
            }
        }
        if(program.getModificationNumber()!=before)
            throw new IllegalStateException("Stale variable receipt audit");
        var result=HardwareScopedVariableReceipt.inspect(rows,before,sha);
        if(program.getModificationNumber()!=before)
            throw new IllegalStateException("Changed variable audit Program");
        return result;
    }

    /** Current-only CSV, never a rename approval or source of actor identity. */
    public static String auditCsv(Program program) {
        if(program==null)throw new IllegalArgumentException("Missing Program");
        long revision=program.getModificationNumber();
        String sha=program.getExecutableSHA256();
        if(sha==null)sha="UNKNOWN";
        var captured=HardwareAnalysisRevision.capture(program,revision,
            program.getLanguageID().toString(),sha,true);
        var snapshot=audit(program);
        return snapshot.csvRevisionBound(captured,()->
            HardwareAnalysisRevision.capture(program,
                program.getModificationNumber(),program.getLanguageID().toString(),
                program.getExecutableSHA256()==null?
                    "UNKNOWN":program.getExecutableSHA256(),true));
    }

    /** Read-only proposals for actual typed pointer arguments and locals. */
    public static List<HardwareScopedVariableReview.Proposal> preview(Function fn) {
        if(fn==null)throw new IllegalArgumentException("Missing function");
        List<HardwareScopedVariableReview.Observation> observations=new ArrayList<>();
        Parameter[] params=fn.getParameters();
        Variable[] locals=fn.getLocalVariables();
        if(params.length+locals.length>2048)
            throw new IllegalArgumentException(
                "Function has too many typed variables for bounded Review");
        for(Parameter p:params) {
            if(p.getOrdinal()<0)continue;
            observations.add(observe(fn,p,p.getOrdinal()));
        }
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
                    !p.original().hasLiveTypeIdentity() ||
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
            // Prepare ALL versioned receipts before the first variable
            // modification. Never silently overwrite a prior approved name.
            // Persist every receipt inside the SAME native undoable Program
            // transaction as its corresponding variable rename.
            Options receipts=program.getOptions(
                HardwareScopedVariableReceipt.OPTIONS_CATEGORY);
            List<String> prepared=new ArrayList<>();
            for(var p:accepted) {
                var o=p.original();
                var entry=new HardwareScopedVariableReceipt.Entry(
                    o.functionEntry(),o.kind(),o.ordinal(),o.storage(),
                    o.currentName(),p.proposedName(),
                    reviewed.modificationNumber(),
                    reviewed.sourceSha256()==null?"UNKNOWN":
                        reviewed.sourceSha256(),
                    o.dataTypeIdentity(),o.firstUseOffset());
                String key=entry.optionKey();
                if(receipts.getString(key,null)!=null)
                    throw new IllegalStateException(
                        "Existing variable approval receipt at "+key);
                prepared.add(HardwareScopedVariableReceipt.encode(entry));
            }
            for(int i=0;i<targets.size();i++){
                Variable v=targets.get(i);
                var p=accepted.get(i);
                v.setName(p.proposedName(),SourceType.USER_DEFINED);
                // Re-resolve the exact typed Ghidra Variable after the write.
                // A symbol rename which silently changed source type, storage
                // or the Function-variable identity must roll back the
                // entire batch with its Options receipts.
                Variable persisted=get(v.getFunction(),p.original());
                if(persisted==null || !p.proposedName().equals(persisted.getName()) ||
                        persisted.getSource()!=SourceType.USER_DEFINED ||
                        !(persisted.getDataType() instanceof Pointer) ||
                        persisted instanceof Parameter arg &&
                            (arg.isAutoParameter() || arg.isForcedIndirect()) ||
                        !p.original().dataTypeIdentity().equals(
                            persisted.getDataType().getPathName()+"#length="+
                                persisted.getDataType().getLength()) ||
                        p.original().firstUseOffset()!=persisted.getFirstUseOffset())
                    throw new IllegalStateException(
                        "Scoped pointer rename did not preserve reviewed type/use identity");
                String key=HardwareScopedVariableReceipt.optionKey(
                    p.original().functionEntry(),p.original().kind(),
                    p.original().ordinal());
                receipts.setString(key,prepared.get(i));
                if(!prepared.get(i).equals(receipts.getString(key,null)))
                    throw new IllegalStateException(
                        "GhidrAssist pointer receipt write failed");
                changed.add(p.original().currentName()+" -> "+p.proposedName());
            }
            commit=true;
            return new Outcome(changed.size(),changed);
        } finally {
            program.endTransaction(tx,commit);
        }
    }
}
