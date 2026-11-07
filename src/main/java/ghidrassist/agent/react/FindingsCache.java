package ghidrassist.agent.react;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Accumulates findings/evidence during analysis.
 * Tracks what tools discovered and maintains relevance scoring.
 * Enhanced with BinAssist keyword-based scoring for automatic relevance detection.
 */
public class FindingsCache {

    // BinAssist keyword scoring constants
    public static final int RELEVANCE_HIGH = 9;
    public static final int RELEVANCE_MEDIUM = 6;
    public static final int RELEVANCE_LOW = 3;

    // High-relevance keywords (security, vulnerabilities, critical findings)
    private static final Set<String> HIGH_KEYWORDS = new HashSet<>(Arrays.asList(
        "vulnerability", "exploit", "buffer overflow", "unsafe", "injection",
        "backdoor", "malware", "shellcode", "rop chain", "heap spray",
        "use after free", "double free", "stack overflow", "format string",
        "integer overflow", "null pointer", "race condition", "privilege",
        "escalation", "arbitrary code", "remote code execution"
    ));

    // Medium-relevance keywords (structural, functional analysis)
    private static final Set<String> MEDIUM_KEYWORDS = new HashSet<>(Arrays.asList(
        "function", "address", "reference", "import", "export",
        "symbol", "call", "jump", "branch", "loop", "condition",
        "parameter", "return", "register", "stack", "heap",
        "pointer", "structure", "class", "method", "variable",
        "string", "constant", "offset", "section", "segment"
    ));

    // Default relevance for findings without keyword matches
    private static final int DEFAULT_RELEVANCE = RELEVANCE_LOW;

    public static class Finding {
        private final String fact;
        private final String evidence;
        private final String toolUsed;
        private final long timestamp;
        private int relevance;  // Mutable - can be updated
        /** Cache-owned findings invalidate page revisions on public score edits. */
        private final Runnable onRelevanceChange;
        private final Object ownerLock;

        public Finding(String fact, String evidence, String toolUsed, int relevance) {
            this(fact,evidence,toolUsed,relevance,null,null);
        }
        private Finding(String fact,String evidence,String toolUsed,
                int relevance,Runnable onRelevanceChange,Object ownerLock) {
            this.fact = fact;
            this.evidence = evidence;
            this.toolUsed = toolUsed;
            this.relevance = relevance;
            this.timestamp = System.currentTimeMillis();
            this.onRelevanceChange=onRelevanceChange;
            this.ownerLock=ownerLock;
        }

        public String getFact() { return fact; }
        public String getEvidence() { return evidence; }
        public String getToolUsed() { return toolUsed; }
        public int getRelevance() { return relevance; }
        public long getTimestamp() { return timestamp; }

        public void setRelevance(int relevance) {
            if(ownerLock!=null) {
                synchronized(ownerLock) {
                    updateRelevance(relevance);
                }
            } else updateRelevance(relevance);
        }
        private void updateRelevance(int relevance) {
            if(this.relevance!=relevance) {
                this.relevance=relevance;
                if(onRelevanceChange!=null)onRelevanceChange.run();
            }
        }
    }

    public static final int MAX_FINDINGS_LIMIT = 1000;
    public static final int MAX_FACT_CHARS = 2048;
    public static final int MAX_EVIDENCE_CHARS = 2048;
    public static final int MAX_TOOL_TEXT_SCAN = 128 * 1024;
    public static final int MAX_ITERATION_SUMMARIES = 100;
    public static final int MAX_ITERATION_SUMMARY_CHARS = 2048;
    private long totalIterationSummaries;
    private long acceptedFindings;
    private long evictedFindings;
    private long findingsRevision;
    public static final int MAX_PAGE_SIZE=100;

    /** Immutable evidence copies, not mutable references to cache Findings. */
    public record FindingView(String fact,String evidence,String toolUsed,
                              int relevance,long timestamp) {}
    public record FindingsPage(long revision,int offset,int limit,int retainedCount,
                               long acceptedCount,long evictedCount,
                               boolean sourceIncomplete,boolean hasMore,
                               boolean complete,List<FindingView> rows) {
        public FindingsPage { rows=List.copyOf(rows); }
    }

    /**
     * Refuse stale page stitching. The first page supplies its revision;
     * later pages must use exactly the same cache generation.
     */
    public synchronized FindingsPage page(int offset,int limit,long requiredRevision) {
        if(requiredRevision!=findingsRevision)
            throw new IllegalStateException("Stale findings page / analysis revision");
        return page(offset,limit);
    }

    /**
     * GA-15 deterministic relevance-ranked pagination of the RETAINED
     * evidence. Explicitly labels all omitted findings and source truncation.
     * Page coordinates do not imply stable snapshot identity across updates:
     * the caller must not stitch pages from different cache revisions.
     */
    public synchronized FindingsPage page(int offset,int limit) {
        if(offset<0 || limit<1 || limit>MAX_PAGE_SIZE)
            throw new IllegalArgumentException("Invalid bounded findings page");
        List<Finding> ordered=new ArrayList<>(findings);
        ordered.sort(Comparator.comparingInt(Finding::getRelevance).reversed());
        int start=Math.min(offset,ordered.size());
        int end=(int)Math.min((long)ordered.size(),(long)start+limit);
        List<FindingView> views=new ArrayList<>();
        for(Finding finding:ordered.subList(start,end))
            views.add(new FindingView(finding.getFact(),
                finding.getEvidence(),finding.getToolUsed(),
                finding.getRelevance(),finding.getTimestamp()));
        boolean more=end<ordered.size();
        return new FindingsPage(findingsRevision,offset,limit,ordered.size(),
            acceptedFindings,evictedFindings,sourceIncomplete,more,
            offset==0 && !more && !sourceIncomplete &&
                evictedFindings==0,
            views);
    }


    // Persist structural source truncation independently of ranked findings.
    // A 1-item findings budget may evict even a score-10 warning when another
    // score-10 finding was encountered first; it must never hide this fact.
    private boolean sourceIncomplete;
    private static final String SOURCE_INCOMPLETE_WARNING =
        "SOURCE INCOMPLETE: some tool output was not inspected; " +
        "retrieve the original tool source before claiming completeness.";
    public synchronized boolean isSourceIncomplete() { return sourceIncomplete; }

    private static String bounded(String input,int max) {
        if(input==null)return null;
        if(input.length()<=max)return input;
        return input.substring(0,max-15)+" [TRUNCATED]";
    }

    private final List<Finding> findings;
    private final List<String> iterationSummaries;
    private final int maxFindings;

    public FindingsCache() {
        this(100);  // Keep up to 100 findings
    }

    public FindingsCache(int maxFindings) {
        if(maxFindings<1 || maxFindings>MAX_FINDINGS_LIMIT)
            throw new IllegalArgumentException("maxFindings must be 1.."+MAX_FINDINGS_LIMIT);
        this.findings = new ArrayList<>();
        this.iterationSummaries = new ArrayList<>();
        this.maxFindings = maxFindings;
    }

    /**
     * Add a finding from tool observation.
     */
    public synchronized void addFinding(String fact, String evidence, String toolUsed, int relevance) {
        if(fact==null || fact.isBlank())return;
        // A bounded local copy is not the full observation. Preserve this
        // loss independently of the finding relevance budget and pagination.
        if(fact.length()>MAX_FACT_CHARS ||
                (evidence!=null && evidence.length()>MAX_EVIDENCE_CHARS) ||
                (toolUsed!=null && toolUsed.length()>128))
            sourceIncomplete=true;
        acceptedFindings++;
        findingsRevision++;
        findings.add(new Finding(bounded(fact,MAX_FACT_CHARS),
            bounded(evidence,MAX_EVIDENCE_CHARS),bounded(toolUsed,128),
            Math.max(0,Math.min(10,relevance)),()->findingsRevision++,this));

        // Prune old low-relevance findings if we exceed max
        if (findings.size() > maxFindings) {
            pruneFindings();
        }
    }

    /**
     * Add a simple finding with default relevance.
     */
    public void addFinding(String fact, String toolUsed) {
        addFinding(fact, null, toolUsed, 5);  // Default medium relevance
    }

    /**
     * Extract key findings from tool output using keyword-based scoring.
     * Enhanced with BinAssist keyword matching for automatic relevance.
     */
    public synchronized void extractFromToolOutput(String toolName, String output) {
        if (output == null || output.isEmpty()) {
            return;
        }

        // Simple heuristics for extracting important information
        // Never allocate a giant String[] or preserve the entire untrusted
        // tool transcript in every finding. Extraction is intentionally
        // bounded and cannot claim to have inspected omitted source bytes.
        int length=Math.min(MAX_TOOL_TEXT_SCAN,output.length());
        String[] lines=output.substring(0,length).split("\n");
        int scanned=0;
        for (String line : lines) {
            if(scanned++>=2000)break;
            line = line.trim();

            // Skip empty or very short lines
            if (line.length() < 10) {
                continue;
            }

            // Skip lines that are too long (likely raw data)
            if (line.length() > 500) {
                continue;
            }

            // Calculate relevance based on keywords
            int relevance = calculateRelevance(line);

            // Only add findings with reasonable length and some relevance
            if (line.length() >= 20 && line.length() <= 300) {
                addFinding(line, line, toolName, relevance);
            }
        }
        if(output.length()>length || lines.length>2000) {
            sourceIncomplete=true;
            addFinding("SOURCE INCOMPLETE: large tool output truncated for finding extraction",
                "Tool output exceeded bounded local scan; omitted content NOT analyzed",
                toolName,10); // Kept as a finding where the budget permits.
        }
    }

    /**
     * Calculate relevance score based on keyword matching.
     * Returns highest matching keyword category score.
     */
    private int calculateRelevance(String text) {
        String lowerText = text.toLowerCase();

        // Check for high-relevance keywords first
        for (String keyword : HIGH_KEYWORDS) {
            if (lowerText.contains(keyword)) {
                return RELEVANCE_HIGH;
            }
        }

        // Check for medium-relevance keywords
        for (String keyword : MEDIUM_KEYWORDS) {
            if (lowerText.contains(keyword)) {
                return RELEVANCE_MEDIUM;
            }
        }

        // Default to low relevance
        return RELEVANCE_LOW;
    }

    /**
     * Remove low-relevance findings to stay within max limit.
     */
    private void pruneFindings() {
        if (findings.size() <= maxFindings) {
            return;
        }

        // Sort by relevance (descending) and keep top findings
        findings.sort(Comparator.comparingInt(Finding::getRelevance).reversed());

        // Remove lowest relevance findings
        while (findings.size() > maxFindings) {
            findings.remove(findings.size() - 1);
            evictedFindings++;
        }
    }

    /**
     * Format findings for LLM prompt - show most relevant.
     * Default: top 10 findings, no character limit.
     */
    public String formatForPrompt() {
        return formatForPrompt(10, 0);
    }

    /**
     * Format top N findings for prompt (no character limiting).
     */
    public String formatForPrompt(int maxShow) {
        return formatForPrompt(maxShow, 0);
    }

    /**
     * Format top N findings for prompt with optional character limiting.
     * Enhanced version supporting BinAssist parity (top 50 for iterations).
     *
     * @param maxShow Maximum number of findings to show
     * @param maxCharsPerFinding Maximum characters per finding (0 = no limit)
     * @return Formatted findings string
     */
    public synchronized String formatForPrompt(int maxShow, int maxCharsPerFinding) {
        if (findings.isEmpty()) {
            return sourceIncomplete ? SOURCE_INCOMPLETE_WARNING :
                "No significant findings yet.";
        }

        String formatted=findings.stream()
            .sorted(Comparator.comparingInt(Finding::getRelevance).reversed())
            .limit(Math.max(0,Math.min(maxShow,maxFindings)))
            .map(f -> {
                String fact = f.getFact();
                // Apply character limit if specified
                if (maxCharsPerFinding > 0 && fact.length() > maxCharsPerFinding) {
                    fact = maxCharsPerFinding>3 ?
                        fact.substring(0,maxCharsPerFinding-3)+"..." :
                        fact.substring(0,maxCharsPerFinding);
                }
                return "• " + fact;
            })
            .collect(Collectors.joining("\n"));
        return sourceIncomplete ? SOURCE_INCOMPLETE_WARNING+"\n"+formatted : formatted;
    }

    /**
     * Get detailed findings with evidence.
     * Enhanced for synthesis with top 100 findings + iteration summaries (BinAssist parity).
     */
    public String formatDetailed() {
        return formatDetailed(100, true);
    }

    /**
     * Get detailed findings with custom limits.
     *
     * @param maxFindings Maximum number of findings to include
     * @param includeIterationSummaries Whether to include iteration summaries
     * @return Formatted detailed findings
     */
    public synchronized String formatDetailed(int maxFindings, boolean includeIterationSummaries) {
        StringBuilder sb = new StringBuilder();
        if(sourceIncomplete)
            sb.append(SOURCE_INCOMPLETE_WARNING).append("\n\n");

        // Add iteration summaries first (provides context)
        if (includeIterationSummaries && !iterationSummaries.isEmpty()) {
            sb.append("## Investigation History\n\n");
            sb.append(formatIterationSummaries()).append("\n");
        }

        // Add findings
        if (findings.isEmpty()) {
            sb.append("## Findings\n\nNo findings accumulated.\n");
            return sb.toString();
        }

        sb.append("## Key Findings\n\n");
        findings.stream()
            .sorted(Comparator.comparingInt(Finding::getRelevance).reversed())
            .limit(Math.max(0,Math.min(maxFindings,this.maxFindings)))
            .forEach(f -> {
                sb.append("**").append(f.getFact()).append("**");
                if (f.getToolUsed() != null) {
                    sb.append(" (from ").append(f.getToolUsed()).append(")");
                }
                sb.append("\n");
                if (f.getEvidence() != null && !f.getEvidence().isEmpty()) {
                    String truncated = f.getEvidence().length() > 200
                        ? f.getEvidence().substring(0, 200) + "..."
                        : f.getEvidence();
                    sb.append("Evidence: ").append(truncated).append("\n");
                }
                sb.append("\n");
            });

        return sb.toString();
    }

    /**
     * Summarize findings into compact form.
     * Used when context needs to be compressed.
     */
    public synchronized String summarize() {
        if (findings.isEmpty()) {
            return sourceIncomplete ? SOURCE_INCOMPLETE_WARNING :
                "No findings to summarize.";
        }

        // Get top findings by relevance
        List<Finding> topFindings = findings.stream()
            .sorted(Comparator.comparingInt(Finding::getRelevance).reversed())
            .limit(15)
            .collect(Collectors.toList());

        StringBuilder sb = new StringBuilder();
        if(sourceIncomplete)
            sb.append(SOURCE_INCOMPLETE_WARNING).append("\n");
        sb.append("Key Findings Summary:\n");
        for (Finding f : topFindings) {
            sb.append("- ").append(f.getFact()).append("\n");
        }

        return sb.toString();
    }

    /**
     * Get count of findings.
     */
    public synchronized int getCount() {
        return findings.size();
    }

    /**
     * Get all findings.
     */
    public synchronized List<Finding> getAllFindings() {
        return new ArrayList<>(findings);
    }

    /**
     * Clear all findings (for context reset).
     */
    public synchronized void clear() {
        findingsRevision++;
        findings.clear();
        iterationSummaries.clear();
        totalIterationSummaries=0;
        acceptedFindings=0;
        evictedFindings=0;
        sourceIncomplete=false;
    }

    /**
     * Get compact representation for progress tracking.
     */
    public synchronized String toCompactString() {
        return String.format("%d findings accumulated%s", findings.size(),
            sourceIncomplete?"; SOURCE INCOMPLETE":"");
    }

    /**
     * Add a summary from an iteration.
     * This captures the LLM's analytical summary after each iteration.
     */
    public synchronized void addIterationSummary(String summary) {
        if (summary != null && !summary.trim().isEmpty()) {
            iterationSummaries.add(bounded(summary.trim(),
                MAX_ITERATION_SUMMARY_CHARS));
            totalIterationSummaries++;
            if(iterationSummaries.size()>MAX_ITERATION_SUMMARIES)
                iterationSummaries.remove(0);
        }
    }

    /**
     * Format iteration summaries for synthesis prompt.
     * Shows last 10 iterations by default.
     */
    public String formatIterationSummaries() {
        return formatIterationSummaries(10);
    }

    /**
     * Format iteration summaries with custom limit.
     */
    public synchronized String formatIterationSummaries(int maxIterations) {
        if (iterationSummaries.isEmpty()) {
            return "No iteration summaries available.";
        }

        // Get last N iterations (most recent)
        int startIdx = Math.max(0, iterationSummaries.size() -
            Math.max(0,Math.min(maxIterations,MAX_ITERATION_SUMMARIES)));
        List<String> recent = iterationSummaries.subList(startIdx, iterationSummaries.size());

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < recent.size(); i++) {
            sb.append("### Iteration ")
                .append(totalIterationSummaries-iterationSummaries.size()+startIdx+i+1)
                .append("\n");
            sb.append(recent.get(i)).append("\n\n");
        }
        return sb.toString();
    }

    /**
     * Get all iteration summaries.
     * @return Copy of iteration summaries list
     */
    public synchronized List<String> getIterationSummaries() {
        return new ArrayList<>(iterationSummaries);
    }
}
