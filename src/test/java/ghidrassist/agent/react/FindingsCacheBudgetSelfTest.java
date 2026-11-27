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
    private static boolean validUtf16(String input) {
        for(int i=0;i<input.length();i++) {
            char c=input.charAt(i);
            if(Character.isHighSurrogate(c)) {
                if(i+1>=input.length() ||
                        !Character.isLowSurrogate(input.charAt(i+1)))return false;
                i++;
            } else if(Character.isLowSurrogate(c))return false;
        }
        return true;
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

        // An individually truncated fact, evidence or tool name must
        // never yield complete-looking exported Agentic evidence.
        var individuallyTruncated=new FindingsCache(5);
        individuallyTruncated.addFinding(
            "F".repeat(FindingsCache.MAX_FACT_CHARS+1),"small","tool",5);
        yes(individuallyTruncated.page(0,5).sourceIncomplete() &&
            !individuallyTruncated.page(0,5).complete() &&
            individuallyTruncated.formatForPrompt().startsWith("SOURCE INCOMPLETE:"),
            "truncating a fact makes the source explicitly incomplete");
        individuallyTruncated.clear();
        individuallyTruncated.addFinding("short",
            "E".repeat(FindingsCache.MAX_EVIDENCE_CHARS+1),"tool",5);
        yes(individuallyTruncated.page(0,5).sourceIncomplete() &&
            !individuallyTruncated.page(0,5).complete(),
            "truncating evidence cannot certify a full source");
        individuallyTruncated.clear();
        individuallyTruncated.addFinding("short","proof","T".repeat(129),5);
        yes(individuallyTruncated.isSourceIncomplete() &&
            !individuallyTruncated.page(0,5).complete(),
            "truncating a tool identifier also signals provenance loss");
        individuallyTruncated.clear();
        individuallyTruncated.addFinding("short","proof","tool",5);
        yes(!individuallyTruncated.isSourceIncomplete() &&
            individuallyTruncated.page(0,5).complete(),
            "clean bounded evidence remains complete after explicit reset");

        // GA-15: surrogate safety applies to retained findings, prompts,
        // detailed evidence and even ignored tool lines, not just LLM text.
        char orphanHigh=(char)0xd83d, orphanLow=(char)0xde80;
        String rocket=new String(Character.toChars(0x1f680));
        var malformed=new FindingsCache();
        malformed.addFinding("bad"+orphanHigh+"fact",
            "proof"+orphanLow+"info","li"+orphanHigh+"sting",9);
        var damaged=malformed.page(0,10);
        yes(damaged.sourceIncomplete() && !damaged.complete() &&
            damaged.rows().get(0).fact().equals("badfact") &&
            damaged.rows().get(0).evidence().equals("proofinfo") &&
            damaged.rows().get(0).toolUsed().equals("listing") &&
            validUtf16(malformed.formatDetailed()) &&
            malformed.formatForPrompt().startsWith("SOURCE INCOMPLETE:"),
            "malformed source fields are sanitized and cannot certify completeness");
        malformed.clear();
        malformed.addFinding("clear evidence","source","listing",5);
        yes(malformed.page(0,10).complete() &&
            validUtf16(malformed.page(0,10).rows().get(0).fact()),
            "clean new source generation regains completeness after explicit reset");

        var clippedPair=new FindingsCache();
        String atBoundary="F".repeat(FindingsCache.MAX_FACT_CHARS-16)+
            rocket+"Z".repeat(40);
        clippedPair.addFinding(atBoundary,"proof","listing",5);
        String clipped=clippedPair.page(0,10).rows().get(0).fact();
        yes(clippedPair.isSourceIncomplete() &&
            clipped.contains("[TRUNCATED]") && clipped.length()<=
                FindingsCache.MAX_FACT_CHARS &&
            validUtf16(clipped) && !clipped.contains(rocket),
            "UTF-16 pair crossing retained cap is removed without orphan code unit");
        var insidePair=new FindingsCache();
        String completePair="Q".repeat(FindingsCache.MAX_FACT_CHARS-2)+rocket;
        insidePair.addFinding(completePair,"proof","listing",5);
        yes(insidePair.page(0,10).complete() &&
            insidePair.page(0,10).rows().get(0).fact().equals(completePair),
            "complete pair ending exactly at source cap is never falsely shortened");

        var promptPair=new FindingsCache();
        promptPair.addFinding(rocket+"EXTRA","proof","listing",8);
        yes(validUtf16(promptPair.formatForPrompt(1,4)) &&
            promptPair.formatForPrompt(1,4).contains("...") &&
            !promptPair.isSourceIncomplete(),
            "prompt-only preview cap never splits stored Unicode without mutating evidence");
        var evidencePair=new FindingsCache();
        evidencePair.addFinding("fact","E".repeat(199)+rocket+"TAIL","listing",8);
        String detailed=evidencePair.formatDetailed(1,false);
        yes(validUtf16(detailed) && detailed.contains("Evidence: "+
                "E".repeat(199)+"...") &&
            evidencePair.page(0,10).complete(),
            "200-char detailed evidence preview cannot split a valid pair");
        var malformedSkipped=new FindingsCache();
        malformedSkipped.extractFromToolOutput("listing","tiny"+orphanLow);
        yes(malformedSkipped.getCount()==0 &&
            malformedSkipped.page(0,10).sourceIncomplete() &&
            !malformedSkipped.page(0,10).complete() &&
            malformedSkipped.formatForPrompt().startsWith("SOURCE INCOMPLETE:"),
            "skipped malformed raw tool line cannot masquerade as complete source");
        var summaryPair=new FindingsCache();
        summaryPair.addIterationSummary(
            "S".repeat(FindingsCache.MAX_ITERATION_SUMMARY_CHARS-16)+
            rocket+"T".repeat(40));
        yes(validUtf16(summaryPair.formatIterationSummaries(1)) &&
            validUtf16(summaryPair.getIterationSummaries().get(0)),
            "bounded iteration history never serializes half an emoji");

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

        // A single line can fit inside the 128 KiB scan yet be omitted
        // entirely by the 300-character per-finding extractor threshold.
        // Neither 301 nor 501 characters may appear source-complete.
        for(int width:new int[]{301,501,1024}) {
            var skipped=new FindingsCache(2);
            skipped.extractFromToolOutput("listing","A".repeat(width));
            var view=skipped.page(0,10);
            yes(view.sourceIncomplete() && !view.complete() &&
                skipped.formatDetailed().startsWith("SOURCE INCOMPLETE:"),
                "oversized omitted tool line marks source incomplete at "+width);
        }
        var boundaryLine=new FindingsCache(2);
        boundaryLine.extractFromToolOutput("listing","A".repeat(300));
        yes(!boundaryLine.isSourceIncomplete() &&
            boundaryLine.page(0,10).complete(),
            "fully retained 300-character line is not falsely omitted");
        var boundedMixed=new FindingsCache(1);
        boundedMixed.extractFromToolOutput("listing",
            "vulnerability high priority observation\n"+"B".repeat(301));
        yes(boundedMixed.isSourceIncomplete() &&
            !boundedMixed.page(0,10).complete(),
            "omission is retained even when the budget evicts its warning");

        // A tiny 1-item cache can prune the truncation warning because
        // an earlier top-score finding wins a stable relevance tie. The
        // independent truncation receipt MUST remain visible in every
        // synthesis/prompt interface regardless of finding eviction.
        var pinned=new FindingsCache(1);
        pinned.addFinding("vulnerability high priority", "local","mcp",10);
        pinned.extractFromToolOutput("mcp",
            ("buffer overflow long source line\n").repeat(10000));
        yes(pinned.isSourceIncomplete() &&
            pinned.formatForPrompt().startsWith("SOURCE INCOMPLETE:") &&
            pinned.formatDetailed(1,false).startsWith("SOURCE INCOMPLETE:") &&
            pinned.summarize().startsWith("SOURCE INCOMPLETE:") &&
            pinned.toCompactString().contains("SOURCE INCOMPLETE"),
            "evidence incompleteness survives relevance tie and tiny budgets");
        yes(pinned.getCount()==1,"finding-count bound remains intact");
        pinned.clear();
        yes(!pinned.isSourceIncomplete() &&
            !pinned.formatForPrompt().startsWith("SOURCE INCOMPLETE:"),
            "new analysis starts with clean source-completeness state");

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
        // GA-15: page offsets are over retained evidence, not over
        // discarded source. Relevance order stable on equal scores.
        var paged=new FindingsCache(3);
        paged.addFinding("low fact","e0","tool",1);
        paged.addFinding("high-A","e1","tool",9);
        paged.addFinding("high-B","e2","tool",9);
        var first=paged.page(0,2);
        yes(first.retainedCount()==3 && first.acceptedCount()==3 &&
            first.evictedCount()==0 && first.hasMore() &&
            !first.complete() && first.rows().size()==2 &&
            first.rows().get(0).fact().equals("high-A") &&
            first.rows().get(1).fact().equals("high-B"),
            "first page is deterministic relevance-ordered and marks omitted tail");
        var last=paged.page(2,2,first.revision());
        yes(!last.hasMore() && last.rows().size()==1 &&
            last.rows().get(0).fact().equals("low fact") &&
            !last.complete(),"second page cannot independently certify all evidence");
        var entire=paged.page(0,3,first.revision());
        yes(entire.complete() && !entire.hasMore() && entire.rows().size()==3,
            "only complete retained page with no omissions may claim complete");
        boolean listImmutable=false;
        try {entire.rows().clear();}
        catch(UnsupportedOperationException expected){listImmutable=true;}
        yes(listImmutable,"page rows immutable across new cache mutations");
        paged.addFinding("high-C","e3","tool",10);
        var afterEvict=paged.page(0,3);
        yes(afterEvict.evictedCount()==1 && afterEvict.acceptedCount()==4 &&
            afterEvict.retainedCount()==3 && !afterEvict.complete(),
            "pruned evidence must remain marked omitted despite full last page");
        boolean stale=false;
        try{paged.page(2,2,first.revision());}
        catch(IllegalStateException expected){stale=true;}
        yes(stale,"relevance pages from different revisions cannot be stitched");
        rejects(()->paged.page(-1,1),"negative pagination offset refused");
        rejects(()->paged.page(0,0),"zero pagination limit refused");
        rejects(()->paged.page(0,FindingsCache.MAX_PAGE_SIZE+1),
            "oversized pagination limit refused");
        yes(paged.page(Integer.MAX_VALUE,1).rows().isEmpty() &&
            !paged.page(Integer.MAX_VALUE,1).complete(),
            "out-of-range page is empty without integer overflow or false completeness");
        // The pre-existing API exposes mutable relevance scores. Those
        // edits must invalidate pagination even if no findings are added.
        var beforeScoreEdit=paged.page(0,3);
        paged.getAllFindings().get(0).setRelevance(8);
        boolean scoreStale=false;
        try{paged.page(0,3,beforeScoreEdit.revision());}
        catch(IllegalStateException expected){scoreStale=true;}
        yes(scoreStale,"public finding relevance edits invalidate page stitching");
        paged.clear();
        yes(paged.page(0,10).complete() &&
            paged.page(0,10).acceptedCount()==0 &&
            paged.page(0,10).evictedCount()==0,
            "new analysis clears discarded-source receipts");
        var truncatedPage=new FindingsCache(1);
        truncatedPage.extractFromToolOutput("mcp",("buffer overflow x\n").repeat(10000));
        yes(truncatedPage.page(0,100).sourceIncomplete() &&
            !truncatedPage.page(0,100).complete(),
            "complete-looking page never hides omitted tool source bytes");
        // GA-15: bounded ReAct iteration history is provenance too.
        // Before this gate, summary truncation/eviction looked complete
        // to Agentic pagination after a successful terminal callback.
        var history=new FindingsCache();
        history.addFinding("identified register","verified Listing","listing",9);
        var cleanHistoryPage=history.page(0,10);
        history.addIterationSummary("  short complete summary  ");
        var shortSummaryPage=history.page(0,10);
        yes(shortSummaryPage.complete() &&
            shortSummaryPage.revision()>cleanHistoryPage.revision() &&
            history.getIterationSummaries().equals(
                List.of("short complete summary")),
            "normal short summary stays complete but advances source revision");
        boolean staleShortSummary=false;
        try{history.page(0,10,cleanHistoryPage.revision());}
        catch(IllegalStateException expected){staleShortSummary=true;}
        yes(staleShortSummary,
            "even a lossless new iteration summary invalidates stale page stitching");
        history.addIterationSummary("   ");
        yes(history.page(0,10).revision()==shortSummaryPage.revision(),
            "blank callback is not a new observation or page generation");
        history.addIterationSummary("X".repeat(
            FindingsCache.MAX_ITERATION_SUMMARY_CHARS+2));
        yes(history.isSourceIncomplete() &&
            !history.page(0,10).complete() &&
            history.formatForPrompt().startsWith("SOURCE INCOMPLETE:") &&
            history.formatIterationSummaries(2).startsWith("SOURCE INCOMPLETE:") &&
            history.getIterationSummaries().get(1).length()<=
                FindingsCache.MAX_ITERATION_SUMMARY_CHARS,
            "oversized iteration summary poisons completeness and stays bounded");
        boolean previousHistoryStale=false;
        try{history.page(0,10,cleanHistoryPage.revision());}
        catch(IllegalStateException expected){previousHistoryStale=true;}
        yes(previousHistoryStale,
            "source-loss event invalidates pre-summary paginated evidence");
        history.clear();
        history.addFinding("same register","fresh Listing","listing",9);
        history.addIterationSummary("short");
        yes(history.page(0,10).complete() &&
            !history.formatIterationSummaries(1).contains("SOURCE INCOMPLETE"),
            "new analysis clears summary loss receipts without losing bounded mode");

        var invalidSummary=new FindingsCache();
        invalidSummary.addFinding("fact","evidence","listing",8);
        invalidSummary.addIterationSummary("valid"+(char)0xd800+"broken");
        yes(invalidSummary.isSourceIncomplete() &&
            !invalidSummary.page(0,10).complete() &&
            invalidSummary.getIterationSummaries().get(0).equals("validbroken"),
            "malformed UTF-16 summary cannot certify a complete response");
        var droppedSummaries=new FindingsCache();
        droppedSummaries.addFinding("fact","evidence","listing",8);
        for(int i=0;i<=FindingsCache.MAX_ITERATION_SUMMARIES;i++)
            droppedSummaries.addIterationSummary("history "+i);
        yes(droppedSummaries.getIterationSummaries().size()==
                FindingsCache.MAX_ITERATION_SUMMARIES &&
            droppedSummaries.isSourceIncomplete() &&
            !droppedSummaries.page(0,10).complete() &&
            droppedSummaries.formatIterationSummaries(2).contains(
                "SOURCE INCOMPLETE") &&
            droppedSummaries.formatIterationSummaries(2).contains(
                "### Iteration "+(FindingsCache.MAX_ITERATION_SUMMARIES+1)),
            "ring eviction never hides missing early investigation history");
        System.out.println("FindingsCacheBudgetSelfTest OK");
    }
}
