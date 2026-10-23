package ghidrassist.tools.native_;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidrassist.core.RAGEngine;
import ghidrassist.core.SearchResult;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolProvider;
import ghidrassist.tools.api.ToolResult;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/** Search the indexed PDF/text manual library, not firmware GraphRAG. */
public final class RAGSearchToolProvider implements ToolProvider {
    private static final String TOOL_NAME="ga_search_documents";
    @Override public String getProviderName(){return "Documentation RAG";}
    @Override public List<Tool> getTools(){
        JsonObject schema=new JsonObject();
        schema.addProperty("type","object");
        JsonObject properties=new JsonObject();
        JsonObject query=new JsonObject();
        query.addProperty("type","string");
        query.addProperty("description","Manual/PDF text query");
        properties.add("query",query);
        schema.add("properties",properties);
        JsonArray required=new JsonArray();
        required.add("query");
        schema.add("required",required);
        return List.of(new NativeTool(TOOL_NAME,
            "Search indexed technical PDF manuals and other RAG documents. "+
            "Returns source filename, original PDF page, text excerpt and layout warning. "+
            "Use for documentation; ga_search_semantic searches firmware functions instead.",
            schema,getProviderName()));
    }
    @Override public boolean handlesTool(String name){return TOOL_NAME.equals(name);}
    @Override public void setContext(Program program){}
    @Override public CompletableFuture<ToolResult> executeTool(String name,JsonObject args){
        if(!handlesTool(name))return CompletableFuture.completedFuture(
            ToolResult.error("Unknown documentation tool"));
        if(args==null || !args.has("query") || !args.get("query").isJsonPrimitive())
            return CompletableFuture.completedFuture(ToolResult.error("Missing query"));
        String query=args.get("query").getAsString();
        if(query.isBlank())return CompletableFuture.completedFuture(ToolResult.error("Empty query"));
        return CompletableFuture.supplyAsync(()->{
            try{
                // Lexical document retrieval works without an embeddings provider.
                List<SearchResult> hits=RAGEngine.search(query,8);
                if(hits.isEmpty())return ToolResult.success("No indexed document hits for: "+query);
                StringBuilder answer=new StringBuilder();
                for(SearchResult hit:hits){
                    answer.append("SOURCE: ").append(hit.getFilename())
                        .append(" PDF_PAGE: ").append(hit.getPageNumber())
                        .append(" PATH: ").append(hit.getSourcePath())
                        .append(" LAYOUT_UNCERTAIN: ").append(hit.isUncertainTable())
                        .append("\\nEXCERPT: ").append(hit.getSnippet()).append("\\n\\n");
                }
                answer.append("WARNING: Verify bit diagrams and multi-column tables on original PDF page.");
                return ToolResult.success(answer.toString());
            }catch(Exception ex){return ToolResult.error("Document RAG search failed: "+ex.getMessage());}
        });
    }
}
