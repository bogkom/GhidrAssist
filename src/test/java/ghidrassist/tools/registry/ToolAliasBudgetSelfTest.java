package ghidrassist.tools.registry;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidrassist.tools.api.*;
import java.util.*;
import java.util.concurrent.*;
public class ToolAliasBudgetSelfTest {
 public static void main(String[] args) {
  ToolRegistry registry=new ToolRegistry();
  registry.registerProvider(new ToolProvider(){
   public String getProviderName(){return "alias-fixture";}
   public List<Tool> getTools(){return List.of("get_one","get_alias").stream().map(n->(Tool)new Tool(){
    public String getName(){return n;}public String getExecutionIdentity(){return "same:operation";}
    public String getDescription(){return "alias";}public String getSource(){return "same";}public JsonObject getInputSchema(){return new JsonObject();}
   }).toList();}
   public boolean handlesTool(String n){return n.equals("get_one")||n.equals("get_alias");}
   public void setContext(Program p){}public CompletableFuture<ToolResult> executeTool(String n,JsonObject a){return CompletableFuture.completedFuture(ToolResult.success("ok"));}
  });
  registry.configureInvestigationToolLimit("",new ToolExecutionPolicy(null,Map.of("get_one",1)));
  JsonObject a=new JsonObject();a.addProperty("key",1);JsonObject b=new JsonObject();b.addProperty("key",2);
  if(!registry.execute("get_one",a).join().isSuccess()||!registry.execute("get_alias",b).join().isError())throw new AssertionError("Alias bypassed budget with different arguments");
  registry.configureInvestigationToolLimit("");
  if(!registry.execute("get_one",a).join().isSuccess()||!registry.execute("get_alias",a).join().isError())throw new AssertionError("Static alias bypassed duplicate suppression");
  registry.configureInvestigationToolLimit("",new ToolExecutionPolicy(Set.of("get_one"),Map.of()));
  if(!registry.execute("get_alias",b).join().isError())throw new AssertionError("Alias bypassed explicit allowlist");
  System.out.println("ToolAliasBudgetSelfTest PASS");
 }
}
