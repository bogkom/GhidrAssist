package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A deliberately narrow, input-independent interprocedural register summary:
 * consecutive MOVE.L/MOVEA.L immediate-to-register steps and exactly one RTS.
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
            if(step==null || step.address!=cursor ||
                    !step.sideEffectRegisters.isEmpty())return Map.of();
            boolean last=index==instructions.size()-1;
            if(last){
                // Only ordinary subroutine return; RTE and RTR have
                // materially different semantics for caller state.
                if(!"RTS".equals(step.mnemonic) ||
                        step.kind!=HardwareDataflow.Kind.OTHER ||
                        !step.successors.isEmpty())return Map.of();
                count+=2;
            }else{
                if(step.kind!=HardwareDataflow.Kind.SET_POINTER ||
                        step.register==null ||
                        !step.register.matches("[AD][0-6]|D7") ||
                        !("MOVE.L".equals(step.mnemonic) ||
                          "MOVEA.L".equals(step.mnemonic)) ||
                        step.successors.size()!=1)
                    return Map.of();
                // A byte length cannot be learned solely from Step. Callers
                // supply a fully decoded contiguous body; for MOVE.L #imm
                // to Dn/An the canonical 68k encoding is exactly 6 bytes.
                // Thus any alternate encoding fails closed.
                cursor+=6;
                count+=6;
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
