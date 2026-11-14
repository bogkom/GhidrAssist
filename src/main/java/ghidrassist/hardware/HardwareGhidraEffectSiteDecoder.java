package ghidrassist.hardware;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import java.util.ArrayList;
import java.util.List;
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
                if(inspectedInstructions>=MAX_DECODED_INSTRUCTIONS) {
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
                try {
                if("MOVEC".equalsIgnoreCase(instruction.getMnemonicString())) {
                    int count=instruction.getNumOperands();
                    List<String> sourceNames=new ArrayList<>();
                    List<String> destinationNames=new ArrayList<>();
                    boolean sourceOther=false, destinationOther=false;
                    if(count==2) {
                        Object[] source=instruction.getOpObjects(0);
                        Object[] destination=instruction.getOpObjects(1);
                        if(source!=null) for(Object obj:source) {
                            if(obj instanceof Register reg) sourceNames.add(reg.getName());
                            else sourceOther=true;
                        }
                        if(destination!=null) for(Object obj:destination) {
                            if(obj instanceof Register reg) destinationNames.add(reg.getName());
                            else destinationOther=true;
                        }
                    }
                    var verdict=HardwareMovecDirectionEvidence.classify(true,count,
                            sourceNames,destinationNames,sourceOther,destinationOther);
                    if(verdict==HardwareMovecDirectionEvidence.Verdict.UNKNOWN)
                        incomplete=true;
                    vbr=verdict==HardwareMovecDirectionEvidence.Verdict.TO_VBR;
                }
                } catch(RuntimeException ex) {
                    // A failed operand decode is UNKNOWN, never a proven non-VBR MOVEC.
                    incomplete=true;
                    vbr=false;
                }
                decoded.add(new HardwareDecodedEffectSites.Decoded(entry,pc,store,vbr));
            }
        }
        return HardwareDecodedEffectSites.collect(decoded,incomplete);
    }
}
