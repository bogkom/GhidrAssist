package ghidrassist.agent.react;

import java.util.List;

/** Pure Java evidence-budget regressions. Does not invoke models or Ghidra. */
public final class FindingsCacheBudgetSelfTest {
    private FindingsCacheBudgetSelfTest() {}
    private static void yes(boolean condition,String explanation) {
        if(!condition)throw new AssertionError(explanation);
    }
    private static void rejects(Runnable work,String why){
        boolean failed=false;
        try{work.run();}
        catch(IllegalArgumentException expected){failed=true;}
        yes(failed,why);
    }
    public static void main(String[] args){
        rejects(()->new FindingsCache(0),"zero capacity rejected");
        rejects(()->new FindingsCache(-1),"negative capacity rejected");
        rejects(()->new FindingsCache(FindingsCache.MAX_FINDINGS_LIMIT+1),
            "unbounded capacity rejected");
        var findings=new FindingsCache(3);
        findings.addFinding("analysis register address",null,"mcp",6);
        findings.addFinding(null,"no evidence","mcp",5);
        yes(findings.getCount()==1,"empty/null facts rejected");
        findings.addFinding("unrecognized address","", "mcp",6);
        findings.addFinding("vulnerability found","proof", "mcp",9);
        findings.addFinding("unrelated fact","", "mcp",2);
        yes(findings.getCount()==3 && findings.formatForPrompt().contains("vulnerability"),
            "maximum finding count and relevance pruning");
        for(int size:new int[]{-10,-1,0,1,2,3,4,10}){
            String prompt=findings.formatForPrompt(3,size);
            yes(prompt!=null && prompt.length()<1000,
                "bounded short prompt formatting cannot throw for limit "+size);
        }
        yes(findings.formatForPrompt(-1).isBlank(),
            "negative requested finding count yields no records");
        yes(findings.formatDetailed(-5,false).startsWith("## Key Findings"),
            "negative detailed output limit does not throw");
        var longFact="A".repeat(FindingsCache.MAX_FACT_CHARS+400);
        var longEvidence="E".repeat(FindingsCache.MAX_EVIDENCE_CHARS+400);
        var large=new FindingsCache(5);
        large.addFinding(longFact,longEvidence,"tool",99);
        yes(large.getAllFindings().get(0).getFact().length()<=
                FindingsCache.MAX_FACT_CHARS &&
            large.getAllFindings().get(0).getEvidence().length()<=
                FindingsCache.MAX_EVIDENCE_CHARS &&
            large.getAllFindings().get(0).getRelevance()==10,
            "one finding cannot retain excessive fact/evidence or unbounded score");

        // Tool-output extraction scans only a finite prefix and MUST label
        // missing source; it must never pretend to have read its omitted tail.
        large.extractFromToolOutput("mcp",("register 0xfffa00 = 0x40ca\n")
            .repeat(10000));
        yes(large.getAllFindings().stream().anyMatch(f->
            f.getFact().startsWith("SOURCE INCOMPLETE")),
            "oversize tool transcript is explicitly incomplete");
        yes(large.getAllFindings().stream().allMatch(f->
                f.getEvidence()==null ||
                f.getEvidence().length()<=FindingsCache.MAX_EVIDENCE_CHARS),
            "huge transcript not copied as evidence into each finding");

        var summary=new FindingsCache();
        for(int i=1;i<=120;i++)
            summary.addIterationSummary("summary iteration "+i+"\n"+
                "T".repeat(FindingsCache.MAX_ITERATION_SUMMARY_CHARS+25));
        List<String> retained=summary.getIterationSummaries();
        yes(retained.size()==FindingsCache.MAX_ITERATION_SUMMARIES &&
            retained.stream().allMatch(v->
                v.length()<=FindingsCache.MAX_ITERATION_SUMMARY_CHARS),
            "iteration history is bounded to last N finite summaries");
        String tail=summary.formatIterationSummaries(3);
        yes(tail.contains("### Iteration 118") &&
            tail.contains("### Iteration 120") &&
            !tail.contains("### Iteration 117"),
            "chronological ordinals survive history eviction");
        yes(summary.formatIterationSummaries(-1).isEmpty(),
            "negative summary view does not return all history");
        summary.clear();
        summary.addIterationSummary("after reset");
        yes(summary.formatIterationSummaries(1).contains("### Iteration 1"),
            "clear resets numbering and retained summaries");
        yes(summary.getCount()==0,"clear drops findings");
        System.out.println("FindingsCacheBudgetSelfTest OK");
    }
}
