package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A deliberately narrow, input-independent interprocedural register summary:
 * consecutive full-register MOVE.L/MOVEA.L/MOVEQ immediate steps and exactly one RTS.
 * Reject branch paths, calls, unmodeled outputs, memory writes, RTE and
 * everything not demonstrably returning those constants on ALL paths.
 */
public final class HardwareVerifiedLeafReturn {
    private HardwareVerifiedLeafReturn(){}
    public static final int MAX_LEAF_INSTRUCTIONS=12;

    public static Map<String,Long> summarize(long entry,long bodyBytes,
            List<HardwareDataflow.Step> instructions) {
        if(entry<0 || bodyBytes<4 || instructions==null ||
                instructions.size()<2 || instructions.size()>MAX_LEAF_INSTRUCTIONS)
            return Map.of();
        long cursor=entry;
        int count=0;
        Map<String,Long> constants=new LinkedHashMap<>();
        for(int index=0;index<instructions.size();index++){
            HardwareDataflow.Step step=instructions.get(index);
            if(step==null || step.address!=cursor)return Map.of();
            boolean last=index==instructions.size()-1;
            // RTS necessarily advances the stack pointer. Only the
            // expected A7 implicit write is allowed at this return.
            if(last ? !step.sideEffectRegisters.isEmpty() &&
                    !step.sideEffectRegisters.equals(java.util.Set.of("A7")) :
                    !step.sideEffectRegisters.isEmpty())return Map.of();
            if(last){
                // Only ordinary subroutine return; RTE and RTR have
                // materially different semantics for caller state.
                if(!"RTS".equals(step.mnemonic) ||
                        step.kind!=HardwareDataflow.Kind.OTHER ||
                        !step.successors.isEmpty())return Map.of();
                count+=2;
            }else{
                boolean moveq="MOVEQ".equals(step.mnemonic);
                if(step.kind!=HardwareDataflow.Kind.SET_POINTER ||
                        step.register==null ||
                        (moveq ? !step.register.matches("D[0-7]") ||
                            // MOVEQ is a sign-extended 8-bit immediate,
                            // not a 16/32-bit move or an A-register write.
                            // Reject raw forged 0x80 (=+128) rather than
                            // silently changing it into a positive Dn.
                            (step.operand&HardwareDataflow.MASK24)!=
                                (((long)(byte)step.operand)&
                                    HardwareDataflow.MASK24) :
                            !step.register.matches("[AD][0-6]|D7") ||
                            !("MOVE.L".equals(step.mnemonic) ||
                              "MOVEA.L".equals(step.mnemonic))) ||
                        step.successors.size()!=1)
                    return Map.of();
                // The exact contiguous Ghidra Listing determines 2-byte
                // MOVEQ or 6-byte immediate long MOVE/MOVEA encoding.
                int length=moveq?2:6;
                cursor+=length;
                count+=length;
                if(step.successors.get(0)!=cursor)return Map.of();
                constants.put(step.register,step.operand&HardwareDataflow.MASK24);
            }
        }
        // Check full body coverage, not just the two endpoints. No hidden
        // undecoded bytes or extra instructions are eligible.
        return count==bodyBytes && !constants.isEmpty()?
            Map.copyOf(constants):Map.of();
    }
}
