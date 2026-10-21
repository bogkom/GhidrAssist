package ghidrassist.hardware;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
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

    public static Outcome apply(Program program,
            List<HardwareFunctionNamingReview.Proposal> accepted) throws Exception {
        if(program==null || accepted==null || accepted.isEmpty())
            throw new IllegalArgumentException("No approved function proposals");
        // Reject duplicate addresses or target labels in one approval batch.
        Set<Long> addresses=new HashSet<>();
        Set<String> names=new HashSet<>();
        for(var p:accepted) {
            if(p==null || !addresses.add(p.functionAddress) ||
                    !names.add(p.proposedName.toUpperCase(java.util.Locale.ROOT)))
                throw new IllegalArgumentException("Duplicate/invalid function proposal");
        }
        int tx=program.startTransaction("GhidrAssist: approved function names");
        boolean commit=false;
        List<String> applied=new ArrayList<>();
        try {
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
            for(var p:accepted) {
                Function fn=resolve(program,p);
                if(fn==null)throw new IllegalStateException("Function disappeared");
                fn.setName(p.proposedName,SourceType.USER_DEFINED);
                applied.add(p.currentName+" -> "+p.proposedName);
            }
            commit=true;
            return new Outcome(applied.size(),List.copyOf(applied));
        } finally {
            program.endTransaction(tx,commit);
        }
    }
}
