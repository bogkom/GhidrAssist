package ghidrassist.hardware;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.HashSet;
import java.util.Set;

/**
 * Read-only adapter: obtains instruction PCs and typed effects from Ghidra's
 * Listing and p-code, never from user-supplied site coordinates.
 * No instruction is executed and no program transaction is opened.
 */
public final class HardwareGhidraEffectSiteDecoder {
    private HardwareGhidraEffectSiteDecoder() {}
    public static final int MAX_DECODED_INSTRUCTIONS=200_000;

    /**
     * Join instruction sites decoded from this Program with independently
     * supplied RESET/CALL witnesses. Incomplete Listing scans fail closed.
     * The caller must derive witnesses and function inventory from the same
     * immutable Program snapshot; this method never performs Apply.
     */
    public static HardwareResetEffectSites.Report correlate(Program program,
            HardwareResetHandlerWitness.Report witness,
            List<HardwareCallEffects.FunctionNode> functions) {
        return decode(program).correlate(witness, functions);
    }

    public static HardwareDecodedEffectSites.Result decode(Program program) {
        if(program==null)throw new IllegalArgumentException("Missing program");
        List<HardwareDecodedEffectSites.Decoded> decoded=new ArrayList<>();
        boolean incomplete=false;
        int inspectedInstructions=0;
        // Overlapping function bodies may expose the same instruction twice.
        // A PC must have one owning function or the source inventory is ambiguous.
        Set<Long> seenPcs=new HashSet<>();
        var functions=program.getFunctionManager().getFunctions(true);
        while(functions.hasNext()) {
            if(inspectedInstructions>=MAX_DECODED_INSTRUCTIONS) {
                incomplete=true;
                break;
            }
            Function function=functions.next();
            long entry=function.getEntryPoint().getOffset();
            if(entry<0 || entry>0xffffffffL || (entry&1)!=0) {
                incomplete=true;
                continue;
            }
            InstructionIterator instructions=program.getListing()
                    .getInstructions(function.getBody(),true);
            while(instructions.hasNext()) {
                if(decoded.size()>=MAX_DECODED_INSTRUCTIONS) {
                    incomplete=true;
                    break;
                }
                Instruction instruction=instructions.next();
                inspectedInstructions++;
                long pc=instruction.getAddress().getOffset();
                if(pc<entry || pc>0xffffffffL || (pc&1)!=0 || !seenPcs.add(pc)) {
                    incomplete=true;
                    continue;
                }
                boolean store=false;
                try {
                    PcodeOp[] pcode=instruction.getPcode();
                    if(pcode==null) {
                        incomplete=true;
                    } else {
                        for(PcodeOp op:pcode)
                            if(op==null) {
                                incomplete=true;
                            } else if(op.getOpcode()==PcodeOp.STORE) {
                                store=true;
                            }
                    }
                } catch(RuntimeException ex) {
                    incomplete=true;
                }
                boolean vbr=false;
                if("MOVEC".equalsIgnoreCase(instruction.getMnemonicString())) {
                    int count=instruction.getNumOperands();
                    if(count!=2) {
                        incomplete=true;
                    } else {
                        Object[] destination=instruction.getOpObjects(count-1);
                        if(destination==null || destination.length==0) {
                            incomplete=true;
                        } else {
                            boolean foundRegister=false;
                            for(Object object:destination) {
                                if(object instanceof Register register) {
                                    foundRegister=true;
                                    if("VBR".equals(register.getName().toUpperCase(Locale.ROOT)))
                                        vbr=true;
                                }
                            }
                            if(!foundRegister) incomplete=true;
                        }
                    }
                }
                decoded.add(new HardwareDecodedEffectSites.Decoded(entry,pc,store,vbr));
            }
        }
        return HardwareDecodedEffectSites.collect(decoded,incomplete);
    }
}
