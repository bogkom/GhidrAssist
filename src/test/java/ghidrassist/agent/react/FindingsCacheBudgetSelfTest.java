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
        yes(findings.formatForPrompt(-1).startsWith("EVIDENCE INCOMPLETE:") &&
            !findings.formatForPrompt(-1).contains("• "),
            "zero displayed findings must still disclose omitted evidence");
        yes(findings.formatDetailed(-5,false).startsWith("EVIDENCE INCOMPLETE:") &&
            findings.formatDetailed(-5,false).contains("## Key Findings"),
            "negative detailed output limit retains evidence-loss warning");
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
        // A public Finding reference can survive its budget eviction.
        // It is no longer in the ranked evidence; editing its score must
        // never invalidate new pages or reorder the retained item.
        var evictionEpoch=new FindingsCache(1);
        evictionEpoch.addFinding("evicted low","source-low","listing",1);
        var oldEvicted=evictionEpoch.getAllFindings().get(0);
        evictionEpoch.addFinding("retained high","source-high","listing",9);
        var stableAfterEviction=evictionEpoch.page(0,1);
        oldEvicted.setRelevance(10);
        yes(evictionEpoch.page(0,1,stableAfterEviction.revision()).rows()
                .get(0).fact().equals("retained high") &&
            evictionEpoch.page(0,1).revision()==stableAfterEviction.revision(),
            "editing evicted Finding cannot invalidate retained pages");
        // Same behavior after a whole cache reset. The detached reference
        // must not change the revision of an unrelated fresh investigation.
        var orphaned=evictionEpoch.getAllFindings().get(0);
        evictionEpoch.clear();
        evictionEpoch.addFinding("fresh after reset","source-new","listing",5);
        var newGeneration=evictionEpoch.page(0,1);
        orphaned.setRelevance(1);
        oldEvicted.setRelevance(0);
        yes(evictionEpoch.page(0,1,newGeneration.revision()).rows()
                .get(0).fact().equals("fresh after reset") &&
            evictionEpoch.page(0,1).revision()==newGeneration.revision(),
            "score edits from previous cache generation cannot poison new pages");
        var currentFinding=evictionEpoch.getAllFindings().get(0);
        currentFinding.setRelevance(8);
        boolean currentEditInvalidated=false;
        try {evictionEpoch.page(0,1,newGeneration.revision());}
        catch(IllegalStateException expected){currentEditInvalidated=true;}
        yes(currentEditInvalidated &&
            evictionEpoch.page(0,1).rows().get(0).relevance()==8,
            "retained score update still invalidates and updates live evidence");

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
        // GA-15: keyword-based source ranking must not silently change
        // with the operating system/UI default locale. Turkish dotted/dotless
        // I exposes the bug in String.toLowerCase() without Locale.ROOT.
        var previousLocale=java.util.Locale.getDefault();
        try {
            java.util.Locale.setDefault(java.util.Locale.forLanguageTag("tr-TR"));
            var turkish=new FindingsCache();
            turkish.extractFromToolOutput("listing",
                "INJECTION observed at MCU register address");
            turkish.extractFromToolOutput("listing",
                "IMPORT table at CPU32 address");
            var ranked=turkish.page(0,10);
            yes(ranked.rows().size()==2 &&
                ranked.rows().get(0).relevance()==FindingsCache.RELEVANCE_HIGH &&
                ranked.rows().get(1).relevance()==FindingsCache.RELEVANCE_MEDIUM &&
                ranked.rows().get(0).fact().startsWith("INJECTION"),
                "source keyword ranking must be invariant under Turkish locale");
            java.util.Locale.setDefault(java.util.Locale.ROOT);
            var rootLocale=new FindingsCache();
            rootLocale.extractFromToolOutput("listing",
                "INJECTION observed at MCU register address");
            rootLocale.extractFromToolOutput("listing",
                "IMPORT table at CPU32 address");
            yes(rootLocale.page(0,10).rows().stream()
                    .map(FindingsCache.FindingView::relevance).toList()
                    .equals(ranked.rows().stream()
                        .map(FindingsCache.FindingView::relevance).toList()),
                "identical keyword scores across locales without assuming timestamps");
        } finally {
            java.util.Locale.setDefault(previousLocale);
        }

        // Public mutable score edits are subject to the SAME 0..10
        // scale as addFinding. Out-of-range edits cannot hijack ranking,
        // and redundant clamped edits must not advance the page epoch.
        var boundedScore=new FindingsCache(2);
        boundedScore.addFinding("first source","address 0x100","listing",6);
        boundedScore.addFinding("second source","address 0x200","listing",8);
        var firstScore=boundedScore.getAllFindings().get(0);
        firstScore.setRelevance(Integer.MAX_VALUE);
        var upper=boundedScore.page(0,2);
        yes(firstScore.getRelevance()==10 &&
            upper.rows().get(0).fact().equals("first source"),
            "public score setter clamps positive overflow to ten");
        firstScore.setRelevance(11);
        yes(boundedScore.page(0,2,upper.revision()).revision()==upper.revision(),
            "second out-of-range edit with unchanged clamped score preserves cursor");
        firstScore.setRelevance(Integer.MIN_VALUE);
        var lower=boundedScore.page(0,2);
        yes(firstScore.getRelevance()==0 &&
            lower.rows().get(0).fact().equals("second source") &&
            lower.revision()>upper.revision(),
            "public negative score clamps to zero and updates current ordering");
        firstScore.setRelevance(-1);
        yes(boundedScore.page(0,2,lower.revision()).revision()==lower.revision(),
            "redundant clamped negative score does not falsely invalidate pages");
        // The versioned JSON page always disclosed these provenance gaps,
        // but the text passed to ReAct synthesis previously hid them.
        var provenanceLoss=new FindingsCache(1);
        provenanceLoss.addFinding("uncited first fact",null,"listing",4);
        provenanceLoss.addFinding("retained verified fact","raw p-code","listing",9);
        var incompletePage=provenanceLoss.page(0,1);
        yes(!incompletePage.complete() && !incompletePage.sourceIncomplete() &&
            incompletePage.evictedCount()==1 &&
            incompletePage.rows().get(0).fact().equals("retained verified fact"),
            "pure retention/provenance omissions are separate from raw text truncation");
        for(String display:List.of(provenanceLoss.formatForPrompt(),
                provenanceLoss.formatDetailed(),provenanceLoss.summarize(),
                provenanceLoss.toCompactString())) {
            yes(display.contains("EVIDENCE INCOMPLETE:") &&
                display.contains("1 accepted findings evicted") &&
                display.contains("1 accepted findings lacked evidence"),
                "all synthesis surfaces retain historical loss/provenance receipts");
        }
        provenanceLoss.clear();
        provenanceLoss.addFinding("new verified fact","source","listing",5);
        yes(provenanceLoss.page(0,1).complete() &&
            !provenanceLoss.formatForPrompt().contains("EVIDENCE INCOMPLETE") &&
            !provenanceLoss.formatDetailed().contains("EVIDENCE INCOMPLETE") &&
            !provenanceLoss.summarize().contains("EVIDENCE INCOMPLETE") &&
            !provenanceLoss.toCompactString().contains("EVIDENCE INCOMPLETE"),
            "explicit cache reset restores clean generation without stale omission warning");

        var combinedLoss=new FindingsCache(1);
        combinedLoss.addFinding("long source",
            "E".repeat(FindingsCache.MAX_EVIDENCE_CHARS+10),"listing",4);
        combinedLoss.addFinding("retained uncited",null,"listing",9);
        var text=combinedLoss.formatForPrompt();
        yes(combinedLoss.page(0,1).sourceIncomplete() &&
            text.startsWith("SOURCE INCOMPLETE:") &&
            text.contains("EVIDENCE INCOMPLETE:") &&
            !combinedLoss.page(0,1).complete(),
            "raw truncation and retention/provenance loss remain separately disclosed");
        // ReAct top-N text previews are not paginated full evidence. Do not
        // make 10/20 shown rows look like the only findings, and do not
        // change the source-complete flag for an honest short preview.
        var preview=new FindingsCache(25);
        for(int i=0;i<20;i++)
            preview.addFinding("retained fact "+i,"listing pc "+i,"listing",6);
        var fullPage=preview.page(0,20);
        yes(fullPage.complete() && fullPage.rows().size()==20 &&
            !fullPage.sourceIncomplete(),
            "lossless retained findings are still complete in versioned pages");
        String promptTen=preview.formatForPrompt();
        String detailedFive=preview.formatDetailed(5,false);
        String summaryFifteen=preview.summarize();
        yes(promptTen.startsWith(
                "PREVIEW ONLY: showing 10 of 20 retained findings; 10 retained findings omitted") &&
            detailedFive.startsWith(
                "PREVIEW ONLY: showing 5 of 20 retained findings; 15 retained findings omitted") &&
            summaryFifteen.startsWith(
                "PREVIEW ONLY: showing 15 of 20 retained findings; 5 retained findings omitted"),
            "every bounded text renderer declares exact retained-view coverage");
        yes(!promptTen.contains("SOURCE INCOMPLETE") &&
            !detailedFive.contains("EVIDENCE INCOMPLETE") &&
            preview.page(0,20,fullPage.revision()).complete(),
            "preview truncation never falsifies source completeness or revision");
        yes(preview.formatForPrompt(20).startsWith("• ") &&
            preview.formatDetailed(20,false).startsWith("## Key Findings") &&
            !preview.formatForPrompt(20).contains("PREVIEW ONLY") &&
            !preview.summarize().contains("SOURCE INCOMPLETE"),
            "full retained text view has no spurious preview or source loss warning");
        String zeroPreview=preview.formatForPrompt(-1);
        yes(zeroPreview.startsWith("PREVIEW ONLY: showing 0 of 20") &&
            !zeroPreview.contains("• ") &&
            preview.formatDetailed(0,false).contains(
                "PREVIEW ONLY: showing 0 of 20"),
            "zero-width previews still disclose all omitted retained evidence");
        preview.addFinding("new evidence","new pc","listing",7);
        yes(preview.formatForPrompt().contains(
                "PREVIEW ONLY: showing 10 of 21 retained findings; 11 retained findings omitted") &&
            preview.page(0,21).complete(),
            "preview coverage updates after an accepted finding without changing source semantics");
        preview.clear();
        preview.addFinding("only new fact","source","listing",5);
        yes(!preview.formatForPrompt().contains("PREVIEW ONLY") &&
            !preview.formatDetailed().contains("PREVIEW ONLY") &&
            !preview.summarize().contains("PREVIEW ONLY"),
            "new source generation resets bounded-preview coverage");
        var mixedPreview=new FindingsCache(2);
        mixedPreview.addFinding("missing attribution",null,"listing",1);
        mixedPreview.addFinding("retained A","source A","listing",9);
        mixedPreview.addFinding("retained B","source B","listing",8);
        String mixedText=mixedPreview.formatForPrompt(1);
        yes(mixedText.contains("EVIDENCE INCOMPLETE:") &&
            mixedText.contains("PREVIEW ONLY: showing 1 of 2") &&
            !mixedPreview.page(0,2).complete(),
            "source loss and presentation-only omissions are independently disclosed");
        System.out.println("FindingsCacheBudgetSelfTest OK");
    }
}
