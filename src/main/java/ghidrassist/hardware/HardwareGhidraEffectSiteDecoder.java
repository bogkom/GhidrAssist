package ghidrassist.hardware;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
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
        // No recognized functions means no negative source evidence. A raw or
        // unanalysed import must never be certified STORE/MOVEC-free.
        if(!functions.hasNext()) incomplete=true;
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
            // A function body may contain undefined bytes or embedded data.
            // Scanning only instructions must not silently certify that body
            // as a complete negative STORE/MOVEC inventory.
            AddressSet coveredInstructionAddresses=new AddressSet();
            InstructionIterator instructions=program.getListing()
                    .getInstructions(function.getBody(),true);
            while(instructions.hasNext()) {
                if(inspectedInstructions>=MAX_DECODED_INSTRUCTIONS) {
                    incomplete=true;
                    break;
                }
                Instruction instruction=instructions.next();
                inspectedInstructions++;
                // Count distinct decoded addresses, not summed instruction lengths:
                // overlapping instructions can otherwise mask undefined gaps.
                long before=coveredInstructionAddresses.getNumAddresses();
                coveredInstructionAddresses.addRange(
                        instruction.getMinAddress(), instruction.getMaxAddress());
                if(coveredInstructionAddresses.getNumAddresses()-before
                        != instruction.getLength()) incomplete=true;
                // An instruction crossing the function boundary cannot certify
                // the bytes of this function as a complete source inventory.
                if(!function.getBody().contains(instruction.getMinAddress(),
                        instruction.getMaxAddress())) incomplete=true;
                long pc=instruction.getAddress().getOffset();
                if(pc<entry || pc>0xffffffffL || (pc&1)!=0 || !seenPcs.add(pc)) {
                    incomplete=true;
                    continue;
                }
                boolean store=false;
                try {
                    PcodeOp[] pcode=instruction.getPcode();
                    if(pcode==null || pcode.length==0) {
                        incomplete=true;
                    } else {
                        for(PcodeOp op:pcode)
                            if(op==null) {
                                incomplete=true;
                            } else if(op.getOpcode()==PcodeOp.STORE) {
                                store=true;
                            } else if(op.getOpcode()==PcodeOp.COPY) {
                                // CPU32's Ghidra SLEIGH emits direct absolute
                                // memory writes as COPY with a RAM output,
                                // not necessarily as an explicit STORE op.
                                // Register and unique-space COPY outputs are
                                // not memory effects (e.g. MOVEQ and flags).
                                Varnode output=op.getOutput();
                                if(output!=null && output.getAddress()!=null &&
                                        output.getAddress().getAddressSpace().isMemorySpace()) {
                                    // A memory-space COPY is a direct write only
                                    // with a well-formed value and a CPU32-sized
                                    // destination. Invalid p-code is UNKNOWN,
                                    // not a confirmed memory effect.
                                    Varnode[] inputs=op.getInputs();
                                    int width=output.getSize();
                                    if(inputs==null || inputs.length!=1 ||
                                            inputs[0]==null || inputs[0].getSize()!=width ||
                                            (width!=1 && width!=2 && width!=4))
                                        incomplete=true;
                                    else
                                        store=true;
                                }
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
            if(coveredInstructionAddresses.getNumAddresses()
                    !=function.getBody().getNumAddresses())
                incomplete=true;
        }
        return HardwareDecodedEffectSites.collect(decoded,incomplete);
    }
}
