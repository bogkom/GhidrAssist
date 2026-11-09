package ghidrassist.hardware;

import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Explicitly approved Ghidra function renames. No function is changed during
 * analysis or preview. Preflights are rechecked immediately before one
 * undoable Program transaction; exceptions roll back the ENTIRE selection.
 */
public final class HardwareFunctionRenameService {
    private HardwareFunctionRenameService() {}

    private static Function resolve(Program program,
            HardwareFunctionNamingReview.Proposal proposal) {
        if(program==null || proposal==null)return null;
        try {
            Address addr=program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(proposal.functionAddress);
            return program.getFunctionManager().getFunctionAt(addr);
        } catch(Exception badAddress) {return null;}
    }

    private static List<String> allSymbols(Program program) {
        List<String> names=new ArrayList<>();
        SymbolIterator symbols=program.getSymbolTable().getAllSymbols(true);
        while(symbols.hasNext()) {
            Symbol symbol=symbols.next();
            if(symbol!=null && symbol.getName()!=null)names.add(symbol.getName());
        }
        return names;
    }

    public static HardwareFunctionRenamePolicy.Decision preflight(
            Program program,HardwareFunctionNamingReview.Proposal candidate) {
        Function function=resolve(program,candidate);
        if(function==null)return HardwareFunctionRenamePolicy.Decision.INVALID;
        return HardwareFunctionRenamePolicy.check(candidate,function.getName(),
            allSymbols(program));
    }

    public record Outcome(int renamed,List<String> names) {}

    /**
     * Read-only inspection of a persisted source-operation receipt.
     * An entry records a GhidrAssist operation; it never authenticates an
     * editor, verifies execution, or replaces the live current-name check.
     */
    public static Optional<HardwareFunctionRenameReceipt.Entry> receipt(
            Program program, long functionAddress) {
        if(program==null)throw new IllegalArgumentException("No active Program");
        String key=HardwareFunctionRenameReceipt.optionKey(functionAddress);
        if(!program.getOptionsNames().contains(
                HardwareFunctionRenameReceipt.OPTIONS_CATEGORY))
            return Optional.empty();
        String stored=program.getOptions(
            HardwareFunctionRenameReceipt.OPTIONS_CATEGORY).getString(key,null);
        if(stored==null)return Optional.empty();
        HardwareFunctionRenameReceipt.Entry decoded;
        try {
            decoded=HardwareFunctionRenameReceipt.decode(stored);
        } catch(IllegalArgumentException invalid){
            throw new IllegalStateException(
                "Persisted GhidrAssist rename receipt is malformed",invalid);
        }
        if(decoded.entry()!=functionAddress)
            throw new IllegalStateException("Persisted function address mismatch");
        return Optional.of(decoded);
    }

    /**
     * Read-only inspection of ALL existing GA-13 rename receipts.
     * The native Program modification counter must not change while
     * correlating saved Options with current Function and SourceType.
     * Undo removing a receipt is NOT a durable record of an undone edit.
     */
    public static HardwareFunctionRenameAudit.Snapshot audit(Program program) {
        if(program==null)
            throw new IllegalArgumentException("No Ghidra Program to audit");
        long before=program.getModificationNumber();
        String sha=program.getExecutableSHA256();
        if(sha==null)sha="UNKNOWN";
        List<HardwareFunctionRenameAudit.Observation> observations=new ArrayList<>();
        if(program.getOptionsNames().contains(
                HardwareFunctionRenameReceipt.OPTIONS_CATEGORY)) {
            Options options=program.getOptions(
                HardwareFunctionRenameReceipt.OPTIONS_CATEGORY);
            List<String> keys=options.getOptionNames();
            if(keys.size()>HardwareFunctionRenameAudit.MAX_ROWS)
                throw new IllegalStateException("Too many stored rename receipts");
            for(String key:keys) {
                if(key==null || !key.matches("FN_[0-9A-F]{8}"))
                    throw new IllegalStateException(
                        "Unexpected GhidrAssist rename Options entry");
                String raw=options.getString(key,null);
                if(raw==null)
                    throw new IllegalStateException("Missing rename receipt value");
                var decoded=HardwareFunctionRenameReceipt.decode(raw);
                if(!HardwareFunctionRenameReceipt.optionKey(decoded.entry())
                        .equals(key))
                    throw new IllegalStateException("Rename receipt entry mismatch");
                Address address=program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(decoded.entry());
                Function function=program.getFunctionManager().getFunctionAt(address);
                observations.add(new HardwareFunctionRenameAudit.Observation(
                    key,raw,function==null?null:function.getName(),
                    function==null?"UNKNOWN":function.getSymbol().getSource().name()));
            }
        }
        if(program.getModificationNumber()!=before)
            throw new IllegalStateException(
                "Program changed while auditing function rename receipts");
        var snapshot=HardwareFunctionRenameAudit.inspect(observations,before,sha);
        if(program.getModificationNumber()!=before)
            throw new IllegalStateException("Stale function rename audit snapshot");
        return snapshot;
    }

    /**
     * Safe default for live read-only GA-13 CSV export. The existing
     * `audit()` takes a consistent snapshot; this method additionally
     * rejects edits, Undo/Redo and Program switches that occur while the
     * CSV is being assembled. No persistent state and no Apply.
     */
    public static String auditCsv(Program program) {
        if(program==null)
            throw new IllegalArgumentException("No Program for rename CSV");
        long revision=program.getModificationNumber();
        String sha=program.getExecutableSHA256();
        if(sha==null)sha="UNKNOWN";
        var fence=HardwareAnalysisRevision.capture(program,revision,
            program.getLanguageID().toString(),sha,true);
        var snapshot=audit(program);
        return snapshot.csvRevisionBound(fence,
            ()->HardwareAnalysisRevision.capture(program,
                program.getModificationNumber(),
                program.getLanguageID().toString(),
                program.getExecutableSHA256()==null?
                    "UNKNOWN":program.getExecutableSHA256(),true));
    }

    public static Outcome apply(Program program,
            List<HardwareFunctionNamingReview.Proposal> accepted,
            HardwareAnalysisRevision reviewedRevision) throws Exception {
        if(program==null || accepted==null || accepted.isEmpty())
            throw new IllegalArgumentException("No approved function proposals");
        // A valid name alone cannot prove the analysis evidence is still
        // current after edits, Undo, Redo, or a different active Program.
        HardwareFunctionRenameRevisionGate.requireCurrent(reviewedRevision,
            program,program.getModificationNumber(),
            program.getLanguageID().toString(),program.getExecutableSHA256(),true);
        // Reject duplicate addresses or target labels in one approval batch.
        Set<Long> addresses=new HashSet<>();
        Set<String> names=new HashSet<>();
        for(var p:accepted) {
            if(p==null || p.proposedName==null ||
                    !addresses.add(p.functionAddress) ||
                    !names.add(p.proposedName.toUpperCase(java.util.Locale.ROOT)))
                throw new IllegalArgumentException("Duplicate/invalid function proposal");
        }
        int tx=program.startTransaction("GhidrAssist: approved function names");
        boolean commit=false;
        List<String> applied=new ArrayList<>();
        try {
            // Revalidate the exact reviewed snapshot inside the transaction,
            // before making any changes. Later revisions are our own edits.
            HardwareFunctionRenameRevisionGate.requireCurrent(reviewedRevision,
                program,program.getModificationNumber(),
                program.getLanguageID().toString(),program.getExecutableSHA256(),true);
            // Re-read current names and full symbol table INSIDE transaction.
            // If any selected candidate is stale, abort and roll back all rows.
            List<String> reserved=allSymbols(program);
            for(var p:accepted) {
                Function fn=resolve(program,p);
                if(fn==null || HardwareFunctionRenamePolicy.check(p,
                        fn.getName(),reserved)!=HardwareFunctionRenamePolicy.Decision.READY)
                    throw new IllegalStateException("Function rename preflight failed at "+
                        Long.toHexString(p.functionAddress)+"; no partial rename");
            }
            // These receipts are part of the SAME Program transaction as
            // the actual USER_DEFINED names. An existing receipt is never
            // silently overwritten; corrupted options or a failed write
            // abort and roll back the entire selected batch.
            Options receipts=program.getOptions(
                HardwareFunctionRenameReceipt.OPTIONS_CATEGORY);
            List<String> prepared=new ArrayList<>();
            for(var p:accepted) {
                String key=HardwareFunctionRenameReceipt.optionKey(
                    p.functionAddress);
                if(receipts.getString(key,null)!=null)
                    throw new IllegalStateException(
                        "Existing GA-13 receipt at "+key+"; no rename applied");
                var row=new HardwareFunctionRenameReceipt.Entry(
                    p.functionAddress,reviewedRevision.modificationNumber(),
                    reviewedRevision.sourceSha256()==null ?
                        "UNKNOWN" : reviewedRevision.sourceSha256(),
                    p.currentName,p.proposedName,p.role,p.registers,p.writeSites);
                prepared.add(HardwareFunctionRenameReceipt.encode(row));
            }
            for(int i=0;i<accepted.size();i++) {
                var p=accepted.get(i);
                Function fn=resolve(program,p);
                if(fn==null)throw new IllegalStateException("Function disappeared");
                fn.setName(p.proposedName,SourceType.USER_DEFINED);
                String key=HardwareFunctionRenameReceipt.optionKey(
                    p.functionAddress);
                receipts.setString(key,prepared.get(i));
                // Fail closed if the transaction's persisted record differs.
                if(!prepared.get(i).equals(receipts.getString(key,null)))
                    throw new IllegalStateException(
                        "GhidrAssist rename receipt write failed");
                applied.add(p.currentName+" -> "+p.proposedName);
            }
            commit=true;
            return new Outcome(applied.size(),List.copyOf(applied));
        } finally {
            program.endTransaction(tx,commit);
        }
    }
}
