package ghidrassist.core;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.GhidrAssistPlugin.CodeViewType;

public class QueryProcessor {

    private static final Pattern RANGE_PATTERN = Pattern.compile("#range\\(([^,]+),\\s*([^\\)]+)\\)");
    private static final int MAX_SEARCH_RESULTS = 5;

    /**
     * Process all macros in the query and replace them with actual content.
     * @param query The original query containing macros
     * @param plugin The GhidrAssist plugin instance
     * @return Processed query with macros replaced
     */
    public static String processMacrosInQuery(String query, GhidrAssistPlugin plugin) {
        String processedQuery = query;
        
        try {
            CodeViewType viewType = plugin.checkLastActiveCodeView();
            TaskMonitor monitor = TaskMonitor.DUMMY;

            // Process #line macro
            if (processedQuery.contains("#line")) {
                String codeLine = getCurrentLine(plugin, viewType, monitor);
                if (codeLine != null) {
                    processedQuery = processedQuery.replace("#line", codeLine);
                }
            }

            // Process #func macro
            if (processedQuery.contains("#func")) {
                String functionCode = getCurrentFunction(plugin, viewType, monitor);
                if (functionCode != null) {
                    processedQuery = processedQuery.replace("#func", functionCode);
                }
            }

            // Process #addr macro
            if (processedQuery.contains("#addr")) {
                String addressString = getCurrentAddress(plugin);
                processedQuery = processedQuery.replace("#addr", addressString);
            }

            // Process #range macros
            processedQuery = processRangeMacros(processedQuery, plugin);

        } catch (Exception e) {
            throw new RuntimeException("Failed to process macros: " + e.getMessage(), e);
        }

        return processedQuery;
    }

    /**
     * Append RAG context to the query based on similarity search.
     * @param query The original query
     * @return Query with RAG context prepended
     * @throws Exception if RAG search fails
     */
    public static String appendRAGContext(String query, GhidrAssistPlugin plugin) throws Exception {
        // Hardware addresses require literal evidence rather than nearest-neighbor
        // semantic ranking. Unrelated prose continues to use hybrid search.
        boolean precise = java.util.regex.Pattern.compile(
            "(?iu)(?:\\b(?:0x[0-9a-f]{4,8}|[0-9a-f]{6,8}|SIMCR|TPURAM|CSPAR|CSBAR|QSM|TOUCAN)\\b|\\$[0-9a-fy]{5,8})")
            .matcher(query).find();
        List<SearchResult> results = precise ?
            RAGEngine.search(query, MAX_SEARCH_RESULTS, RAGLibraries.active(plugin.getCurrentProgram())) :
            RAGEngine.hybridSearch(query, MAX_SEARCH_RESULTS, RAGLibraries.active(plugin.getCurrentProgram()));
        if (results.isEmpty()) {
            return query;
        }

        StringBuilder contextBuilder = new StringBuilder();
        contextBuilder.append("<context>\n");
        
        for (SearchResult result : results) {
            contextBuilder.append("<result>\n");
            contextBuilder.append("</br><file>").append(result.getFilename()).append("</file>\n");
            contextBuilder.append("</br><chunkid>").append(result.getChunkId()).append("</chunkid>\n");
            if (result.getPageNumber() > 0)
                contextBuilder.append("<page>").append(result.getPageNumber()).append("</page>\n");
            if (result.getSourcePath() != null)
                contextBuilder.append("<source>").append(result.getSourcePath()).append("</source>\n");
            if (result.isUncertainTable())
                contextBuilder.append("<warning>TABLE/COLUMN LAYOUT UNVERIFIED. Do not infer exact bit-to-description mappings without checking source PDF page.</warning>\n");
            contextBuilder.append("</br><score>").append(result.getScore()).append("</score>\n");
            contextBuilder.append("</br><content>\n").append(result.getSnippet()).append("\n</content>\n");
            contextBuilder.append("\n</result>\n\n");
        }
        
        contextBuilder.append("\n</context>\n");
        return contextBuilder.toString() + query;
    }

    /**
     * Get the current line based on view type.
     */
    private static String getCurrentLine(GhidrAssistPlugin plugin, CodeViewType viewType, TaskMonitor monitor) {
        Address currentAddress = plugin.getCurrentAddress();
        if (currentAddress == null) {
            return "No current address available.";
        }

        if (viewType == CodeViewType.IS_DECOMPILER) {
            return CodeUtils.getLineCode(currentAddress, monitor, plugin.getCurrentProgram());
        } else if (viewType == CodeViewType.IS_DISASSEMBLER) {
            return CodeUtils.getLineDisassembly(currentAddress, plugin.getCurrentProgram());
        }
        
        return "Unknown code view type.";
    }

    /**
     * Get the current function based on view type.
     */
    private static String getCurrentFunction(GhidrAssistPlugin plugin, CodeViewType viewType, TaskMonitor monitor) {
        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            return "No function at current location.";
        }

        if (viewType == CodeViewType.IS_DECOMPILER) {
            return CodeUtils.getFunctionCode(currentFunction, monitor);
        } else if (viewType == CodeViewType.IS_DISASSEMBLER) {
            return CodeUtils.getFunctionDisassembly(currentFunction);
        }
        
        return "Unknown code view type.";
    }

    /**
     * Get the current address as a string.
     */
    private static String getCurrentAddress(GhidrAssistPlugin plugin) {
        Address currentAddress = plugin.getCurrentAddress();
        return (currentAddress != null) ? currentAddress.toString() : "No address available.";
    }

    /**
     * Process all #range macros in the query.
     */
    private static String processRangeMacros(String query, GhidrAssistPlugin plugin) {
        Matcher matcher = RANGE_PATTERN.matcher(query);
        while (matcher.find()) {
            String startStr = matcher.group(1);
            String endStr = matcher.group(2);
            String rangeData = getRangeData(startStr.trim(), endStr.trim(), plugin);
            query = query.replace(matcher.group(0), rangeData);
            matcher = RANGE_PATTERN.matcher(query);
        }
        return query;
    }

    /**
     * Get the data for a specific address range.
     */
    private static String getRangeData(String startStr, String endStr, GhidrAssistPlugin plugin) {
        try {
            Program program = plugin.getCurrentProgram();
            if (program == null) {
                return "No program loaded.";
            }

            AddressFactory addressFactory = program.getAddressFactory();
            Address startAddr = addressFactory.getAddress(startStr);
            Address endAddr = addressFactory.getAddress(endStr);

            if (startAddr == null || endAddr == null) {
                return "Invalid addresses.";
            }

            // Get the bytes in the range
            long size = endAddr.getOffset() - startAddr.getOffset() + 1;
            if (size <= 0 || size > 1024) { // Limit to reasonable size
                return "Invalid range size.";
            }

            byte[] bytes = new byte[(int) size];
            program.getMemory().getBytes(startAddr, bytes);

            // Convert bytes to hex string
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02X ", b));
            }
            return sb.toString().trim();

        } catch (Exception e) {
            return "Failed to get range data: " + e.getMessage();
        }
    }
}
