package ghidrassist.hardware;

import java.util.List;
public final class HardwareSimcrLocalFirstSelfTest {
    private static void ok(boolean b,String message){if(!b)throw new AssertionError(message);}
    private static HardwareSimcrLocalFirst.Node node(long pc,HardwareSimcrLocalFirst.Effect effect,
            Integer word,long...successors){
        java.util.List<Long> next=new java.util.ArrayList<>();
        for(long x:successors)next.add(x);
        return new HardwareSimcrLocalFirst.Node(pc,next,effect,word);
    }
    public static void main(String[] args){
        var none=HardwareSimcrLocalFirst.Effect.NONE;
        var word=HardwareSimcrLocalFirst.Effect.WORD_LITERAL;
        var alias=HardwareSimcrLocalFirst.Effect.ALIAS_OR_CALL_BARRIER;
        var unknown=HardwareSimcrLocalFirst.Effect.UNKNOWN_WORD;
        var fork=HardwareSimcrLocalFirst.inspect(0x2bc0,0,
            List.of(node(0,none,null,1,2),
                node(1,word,0x40ca,3),node(2,word,0x4848,3),
                node(3,none,null)),false,20);
        ok(fork.literalCandidates().size()==2 &&
            fork.literalCandidates().get(0).pc()==1 &&
            fork.literalCandidates().get(1).word()==0x4848 &&
            !fork.unknownFirstPossible(),
            "conditional branches produce BOTH static first-site candidates");
        var barrier=HardwareSimcrLocalFirst.inspect(0x2bc0,0,
            List.of(node(0,alias,null,1),node(1,word,0x40ca)),
            false,20);
        ok(barrier.unknownFirstPossible() &&
            barrier.literalCandidates().size()==1,
            "unknown alias could write SIMCR before a later known site");
        var unknownValue=HardwareSimcrLocalFirst.inspect(0x2bc0,0,
            List.of(node(0,unknown,null,1),node(1,word,0x40ca)),
            false,20);
        ok(unknownValue.unknownFirstPossible() &&
            unknownValue.literalCandidates().isEmpty(),
            "first unknown SIMCR word is not replaced by later literal");
        var loop=HardwareSimcrLocalFirst.inspect(0,0,
            List.of(node(0,none,null,1),node(1,none,null,0,2),
                node(2,word,0x40ca)),false,20);
        ok(loop.cyclesOrIncompleteEdges() && loop.unknownFirstPossible(),
            "possible nonterminating loop must not prove first hardware write");
        var truncated=HardwareSimcrLocalFirst.inspect(0,0,
            List.of(node(0,none,null,1),node(1,word,0x40ca)),false,1);
        ok(truncated.workLimitReached() && truncated.unknownFirstPossible(),
            "work cap is uncertainty, not no-first-write");
        var gap=HardwareSimcrLocalFirst.inspect(0,0,
            List.of(node(0,none,null,1,0xff)),false,20);
        ok(gap.unknownFirstPossible() && gap.cyclesOrIncompleteEdges(),
            "missing successor is not proof of no write");
        var missing=HardwareSimcrLocalFirst.inspect(0,99,
            List.of(node(0,word,0x40ca)),false,20);
        ok(missing.unknownFirstPossible() && missing.literalCandidates().isEmpty(),
            "unrecognized entry cannot assert first site");
        var emptyExit=HardwareSimcrLocalFirst.inspect(0,0,
            List.of(node(0,none,null)),false,20);
        ok(emptyExit.exitWithoutSimcr() && emptyExit.literalCandidates().isEmpty(),
            "no known write in modeled function does not prove no hardware write");
        var report=HardwareSimcrLocalFirst.markdown(List.of(fork,barrier),0);
        ok(report.contains("not** the first") &&
            report.contains("Other functions, callees, interrupts") &&
            report.contains("0x40CA") && report.contains("0x4848"),
            "no false reset-first or MM hardware claim");
        boolean immutable=false;
        try{fork.literalCandidates().clear();}
        catch(UnsupportedOperationException e){immutable=true;}
        ok(immutable,"immutable local first-site candidates");
        System.out.println("HardwareSimcrLocalFirstSelfTest OK");
    }
}
