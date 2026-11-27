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
    private static void rejects(Runnable action,String message) {
        boolean denied=false;
        try {action.run();}
        catch(IllegalArgumentException expected){denied=true;}
        ok(denied,message);
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
        // A normal diamond and a shared suffix are not loops. Both
        // predecessor paths may reach the same literal/exit safely.
        var diamond=HardwareSimcrLocalFirst.inspect(0,0,
            List.of(node(0,none,null,1,2),
                node(1,none,null,3),node(2,none,null,3),
                node(3,none,null,4),node(4,word,0x40ca)),false,20);
        ok(diamond.literalCandidates().size()==1 &&
            !diamond.unknownFirstPossible() &&
            !diamond.cyclesOrIncompleteEdges() &&
            diamond.visitedNodes()==5,
            "joined branches must not be mislabeled as cycles");
        var sharedExit=HardwareSimcrLocalFirst.inspect(0,0,
            List.of(node(0,none,null,1,2),
                node(1,none,null,3),node(2,none,null,3),
                node(3,none,null)),false,20);
        ok(sharedExit.exitWithoutSimcr() &&
            !sharedExit.unknownFirstPossible() &&
            !sharedExit.cyclesOrIncompleteEdges(),
            "shared no-write exit is not a back-edge");
        var delayedCycle=HardwareSimcrLocalFirst.inspect(0,0,
            List.of(node(0,none,null,1,2),
                node(1,none,null,3),node(2,none,null,3),
                node(3,none,null,1,4),node(4,word,0x4848)),false,20);
        ok(delayedCycle.unknownFirstPossible() &&
            delayedCycle.cyclesOrIncompleteEdges() &&
            delayedCycle.literalCandidates().size()==1,
            "real back-edge must remain uncertain after a join");
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
        // A bounded number of source nodes is not enough to prevent
        // hundreds of thousands of duplicate CFG successor references.
        // At the exact edge limit, a real back-edge is still observed.
        var edgeAtCap=new HardwareSimcrLocalFirst.Node(
            0,java.util.Collections.nCopies(
                HardwareSimcrLocalFirst.MAX_SOURCE_EDGES,0L),
            none,null);
        var atCap=HardwareSimcrLocalFirst.inspect(0,0,
            List.of(edgeAtCap),false,5);
        ok(atCap.visitedNodes()==1 &&
            atCap.cyclesOrIncompleteEdges() &&
            atCap.unknownFirstPossible() &&
            !atCap.workLimitReached(),
            "200k duplicate source-CFG references accepted without masking cycle");
        boolean rejectedEdges=false;
        try {
            HardwareSimcrLocalFirst.inspect(0,0,List.of(
                new HardwareSimcrLocalFirst.Node(0,
                    java.util.Collections.nCopies(
                        HardwareSimcrLocalFirst.MAX_SOURCE_EDGES+1,0L),
                    none,null)),false,5);
        }catch(IllegalArgumentException expected){rejectedEdges=true;}
        ok(rejectedEdges,
            "200001 source-CFG edges must fail before search, not truncate silently");
        // The aggregate bound applies across several source nodes too.
        rejectedEdges=false;
        try {
            HardwareSimcrLocalFirst.inspect(0,0,List.of(
                new HardwareSimcrLocalFirst.Node(0,
                    java.util.Collections.nCopies(
                        HardwareSimcrLocalFirst.MAX_SOURCE_EDGES/2,1L),
                    none,null),
                new HardwareSimcrLocalFirst.Node(1,
                    java.util.Collections.nCopies(
                        HardwareSimcrLocalFirst.MAX_SOURCE_EDGES/2+1,0L),
                    none,null)),false,5);
        }catch(IllegalArgumentException expected){rejectedEdges=true;}
        ok(rejectedEdges,
            "source-CFG edge budget counts all nodes, not only the root");
        ok(diamond.literalCandidates().size()==1 &&
            !diamond.unknownFirstPossible(),
            "rejected oversized graph never poisons independent first-SIMCR result");
        // Source-only SIMCR first effects require bounded MCU24 program
        // coordinates. A host 32-bit address is not a proven MC68332 write.
        rejects(()->node(0x1000000L,none,null),
            "foreign function source PC cannot seed MC68332 SIMCR");
        rejects(()->node(0,none,null,0x1000000L),
            "foreign successor cannot be treated as a complete source path");
        rejects(()->node(0,none,null,-2),
            "negative successor invalid even if otherwise disconnected");
        rejects(()->HardwareSimcrLocalFirst.inspect(
            0x1000000L,0,List.of(node(0,none,null)),false,2),
            "foreign 32-bit function metadata not publishable as local MC68332");
        rejects(()->HardwareSimcrLocalFirst.inspect(
            0,0x1000000L,List.of(node(0,none,null)),false,2),
            "foreign first-SIMCR entry metadata not publishable as local MC68332");
        rejects(()->new HardwareSimcrLocalFirst.FirstSite(0,0x10000),
            "out-of-range 17-bit SIMCR word cannot masquerade as source literal");
        rejects(()->new HardwareSimcrLocalFirst.FirstSite(0x1000000L,0x40ca),
            "foreign physical register source location cannot be displayed");
        rejects(()->new HardwareSimcrLocalFirst.Result(
            0,List.of(new HardwareSimcrLocalFirst.FirstSite(2,0x40ca)),
            false,false,false,false,0),
            "a source result cannot have first sites without visited decoded nodes");
        rejects(()->new HardwareSimcrLocalFirst.Result(
            0,List.of(new HardwareSimcrLocalFirst.FirstSite(2,0x40ca)),
            false,false,true,false,1),
            "cycles or CFG gaps must imply unknown first-SIMCR effects");
        rejects(()->new HardwareSimcrLocalFirst.Result(
            0,List.of(new HardwareSimcrLocalFirst.FirstSite(2,0x40ca),
                new HardwareSimcrLocalFirst.FirstSite(2,0x4848)),
            false,false,false,false,2),
            "duplicate first source PC cannot claim contradictory words");
        rejects(()->new HardwareSimcrLocalFirst.Result(
            0,List.of(new HardwareSimcrLocalFirst.FirstSite(4,0x40ca),
                new HardwareSimcrLocalFirst.FirstSite(2,0x4848)),
            false,false,false,false,2),
            "public first-SIMCR result rows must have deterministic PC order");
        rejects(()->HardwareSimcrLocalFirst.markdown(
            java.util.Collections.nCopies(
                HardwareSimcrLocalFirst.MAX_LOCAL_FUNCTIONS+1,diamond),0),
            "unsupported report function count cannot be presented as complete source");
        rejects(()->HardwareSimcrLocalFirst.markdown(
            java.util.Arrays.asList(diamond,null),0),
            "null function source cannot be omitted silently");
        ok(diamond.literalCandidates().size()==1 &&
            !diamond.unknownFirstPossible() &&
            fork.literalCandidates().size()==2,
            "valid branch and convergence results survive strict source gates");
        System.out.println("HardwareSimcrLocalFirstSelfTest OK");
    }
}
