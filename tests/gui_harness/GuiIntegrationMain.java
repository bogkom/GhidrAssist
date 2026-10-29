// Adapted/reviewed from docs/gui-regression-reference; synthetic-only fixture.
// No standard Project Manager / CodeBrowser required.
import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassist.*;
import ghidrassist.apiprovider.*;
import ghidrassist.core.TabController;
import ghidrassist.ui.tabs.QueryTab;
import ghidrassist.tools.api.*;
import ghidrassist.tools.registry.ToolRegistry;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.BooleanSupplier;

public class GuiIntegrationMain {
 static class Manager extends DefaultProjectManager { Manager(){super();} }
 static class WindowTool extends PluginTool {
  WindowTool(Project project){super(project,"GhidrAssist isolated GUI regression",false,false,false);}
  void shutdown(){super.dispose();}
 }
 static final Gson JSON=new GsonBuilder().setPrettyPrinting().create();
 static Object field(Object owner,String name)throws Exception {
  Class<?> c=owner.getClass();while(c!=null){try{Field f=c.getDeclaredField(name);f.setAccessible(true);return f.get(owner);}catch(NoSuchFieldException e){c=c.getSuperclass();}}
  throw new NoSuchFieldException(name);
 }
 static void edt(Runnable action)throws Exception {SwingUtilities.invokeAndWait(action);}
 static void waitFor(BooleanSupplier test,int seconds)throws Exception {
  long deadline=System.nanoTime()+seconds*1000000000L;
  while(System.nanoTime()<deadline){if(test.getAsBoolean())return;Thread.sleep(30);}
  throw new AssertionError("GUI integration timeout");
 }
 static boolean onEdt(BooleanSupplier test) {
  boolean[] answer=new boolean[1];try{edt(()->answer[0]=test.getAsBoolean());}catch(Exception e){throw new RuntimeException(e);}return answer[0];
 }
 static class Fixture implements ToolProvider {
  int polls;
  public String getProviderName(){return "gui-fixture";}
  public List<Tool> getTools(){return List.of("get_task_status","get_gui_fact","get_gui_fact_alias").stream().map(name->(Tool)new Tool(){
   public String getName(){return name;} public String getDescription(){return "GUI integration fixture";}
   public String getExecutionIdentity(){return name.startsWith("get_gui_fact")?"gui:fact":"gui:status";}
   public JsonObject getInputSchema(){return JsonParser.parseString("{\"type\":\"object\",\"properties\":{\"key\":{\"type\":\"string\"},\"task_id\":{\"type\":\"string\"}}}").getAsJsonObject();}
   public String getSource(){return "gui-fixture";}
  }).toList();}
  public boolean handlesTool(String name){return getTools().stream().anyMatch(t->t.getName().equals(name));}
  public void setContext(Program p){}
  public CompletableFuture<ToolResult> executeTool(String name,JsonObject args){return CompletableFuture.completedFuture(ToolResult.success(name.equals("get_task_status")?"status="+(++polls==1?"PENDING":"COMPLETED"):"GUI_FACT=42"));}
 }
 public static void main(String[] args) throws Exception {
  Path configPath=Path.of(args[0]),out=Path.of(args[2]);String endpoint=args[1];
  JsonObject config=JsonParser.parseString(Files.readString(configPath)).getAsJsonObject();
  String mode=config.get("mode").getAsString();
  if(!mode.equals("smoke") && !mode.equals("policy"))
   throw new IllegalArgumentException("smoke/policy mode required");
  var app=new GhidraApplicationConfiguration();app.setShowSplashScreen(false);
  app.setApplicationLogFile(out.resolve("application.log").toFile());
  Application.initializeApplication(new GhidraApplicationLayout(Path.of(config.get("ghidra").getAsString()).toFile()),app);
  ghidra.framework.preferences.Preferences.setProperty("GhidrAssist.LuceneIndexPath",config.get("index").getAsString());
  ghidra.framework.preferences.Preferences.setProperty("GhidrAssist.RAGLibraries.v1","[]");
  Manager manager=new Manager();
  Project project=manager.openProject(new ProjectLocator(config.get("project_dir").getAsString(),config.get("project_name").getAsString()),false,false);
  AppInfo.setActiveProject(project);
  Object consumer=new Object();
  Program program=(Program)project.getProjectData().getFile("/"+config.get("program").getAsString()).getDomainObject(consumer,false,false,TaskMonitor.DUMMY);
  WindowTool[] tool=new WindowTool[1]; TabController[] controller=new TabController[1];
  JsonObject result=new JsonObject();result.addProperty("run_id",config.get("run_id").getAsString());
  result.addProperty("mode",mode);
  result.addProperty("application_headless",app.isHeadless());result.addProperty("awt_headless",GraphicsEnvironment.isHeadless());
  JsonObject cases=new JsonObject();result.add("cases",cases);
  try {
   edt(()->{try{
    tool[0]=new WindowTool(project);tool[0].addPlugin("ghidra.app.plugin.core.progmgr.ProgramManagerPlugin");
    tool[0].addPlugin("ghidrassist.GhidrAssistPlugin"); tool[0].getService(ProgramManager.class).openProgram(program);
    tool[0].setVisible(true);tool[0].getToolFrame().setSize(1200,950);
   }catch(Exception e){throw new RuntimeException(e);}});
   GhidrAssistPlugin plugin=(GhidrAssistPlugin)tool[0].getManagedPlugins().stream().filter(p->p instanceof GhidrAssistPlugin).findFirst().orElseThrow();
   Object provider=field(plugin,"provider"),ui=field(provider,"ui");
   QueryTab query=(QueryTab)field(ui,"queryTab");controller[0]=(TabController)field(ui,"controller");
   edt(()->{try{((JTabbedPane)field(ui,"tabbedPane")).setSelectedComponent(query);}catch(Exception e){throw new RuntimeException(e);}});
   // The tool can take more than one EDT cycle to show Query after
   // PluginTool.setVisible(true). Wait for the actual UI, not a fixed sleep.
   waitFor(()->onEdt(()->{
     Program current=tool[0].getService(ProgramManager.class).getCurrentProgram();
     return tool[0].getToolFrame().isShowing() && query.isShowing() &&
         current!=null && current.equals(program);
   }),20);
   edt(()->{try{
     JFrame window=tool[0].getToolFrame();
     Program active=tool[0].getService(ProgramManager.class).getCurrentProgram();
     if(!window.isShowing()||!query.isShowing()||
         active==null||!active.equals(program))
       throw new AssertionError("GUI/program mismatch: window="+
           window.isShowing()+" query="+query.isShowing()+
           " program="+(active!=null));
     result.addProperty("window_showing",true);
     result.addProperty("query_showing",true);
     result.addProperty("ran_on_edt",SwingUtilities.isEventDispatchThread());
     result.addProperty("program_open",true);
     BufferedImage frame=new BufferedImage(window.getWidth(),window.getHeight(),
         BufferedImage.TYPE_INT_RGB);
     Graphics2D paint=frame.createGraphics();window.printAll(paint);paint.dispose();
     if(!ImageIO.write(frame,"png",out.resolve("swing-render.png").toFile()))
       throw new AssertionError("Swing render PNG failed");
     result.addProperty("swing_render",true);
   }catch(Exception e){throw new RuntimeException(e);}});
   Files.writeString(out.resolve("gui-results.json"),JSON.toJson(result));
   Files.writeString(out.resolve("window.ready"),"ready");
   long captureDeadline=System.nanoTime()+30_000_000_000L;
   while(!Files.exists(out.resolve("window.probed"))){
     if(System.nanoTime()>captureDeadline)throw new AssertionError("X11 capture handshake timed out");
     Thread.sleep(75);
   }
   if(mode.equals("policy")){
   edt(()->{if(query.getTaskToolPolicyPanel().snapshot()!=null)throw new AssertionError("Default GUI policy must use legacy behavior");});
   result.addProperty("default_policy_legacy",true);
   JFrame[] narrowHost={null};int[] queryIndex={-1};
   edt(()->{try{
    if(query.getTaskToolPolicyPanel().getParent()!=null)throw new AssertionError("Policy editor still occupies Query");
    result.addProperty("policy_editor_detached",true);
    JTabbedPane tabs=(JTabbedPane)field(ui,"tabbedPane");queryIndex[0]=tabs.indexOfComponent(query);tabs.remove(query);
    narrowHost[0]=new JFrame("Actual Query component - narrow regression");narrowHost[0].add(query);narrowHost[0].setSize(360,850);narrowHost[0].setVisible(true);
   }catch(Exception e){throw new RuntimeException(e);}});
   Thread.sleep(250);
   edt(()->{try{
    narrowHost[0].validate();
    JPanel toolbar=(JPanel)query.getTaskToolPolicyPanel().getConfigureButton().getParent();
    for(Component c:toolbar.getComponents())if(c.isVisible()){
     Rectangle b=c.getBounds();if(b.x<0||b.y<0||b.x+b.width>toolbar.getWidth()||b.y+b.height>toolbar.getHeight())
       throw new AssertionError("Clipped Query option: "+c+" parent="+toolbar.getSize());
    }
    JTextArea status=(JTextArea)field(query,"contextStatusLabel");
    if(!status.getLineWrap()||status.getWidth()>query.getWidth()||status.getHeight()<status.getPreferredSize().height)
      throw new AssertionError("Model status does not wrap within narrow Query");
    result.addProperty("narrow_status_wrapped",true);
    result.addProperty("narrow_query_width",query.getWidth());result.addProperty("narrow_toolbar_unclipped",true);
    Window w=SwingUtilities.getWindowAncestor(query);BufferedImage image=new BufferedImage(w.getWidth(),w.getHeight(),BufferedImage.TYPE_INT_RGB);
    Graphics2D g=image.createGraphics();w.printAll(g);g.dispose();ImageIO.write(image,"png",out.resolve("query-narrow.png").toFile());
    narrowHost[0].remove(query);narrowHost[0].dispose();
    JTabbedPane tabs=(JTabbedPane)field(ui,"tabbedPane");tabs.insertTab("Query",null,query,null,queryIndex[0]);tabs.setSelectedComponent(query);
    tool[0].getToolFrame().validate();
    var panel=query.getTaskToolPolicyPanel();
    ((JComboBox)field(panel,"mode")).setSelectedItem(ghidrassist.ui.common.TaskToolPolicyPanel.Mode.READ_ONLY);
    ((JComboBox)field(panel,"lifetime")).setSelectedItem(ghidrassist.ui.common.TaskToolPolicyPanel.Lifetime.CONVERSATION);
    ((JButton)field(panel,"apply")).doClick();controller[0].handleAgentPlanCancelled();
    if(panel.snapshot()==null||!panel.snapshot().readOnly())throw new AssertionError("Cancelling a plan consumed conversation settings");
    result.addProperty("cancel_plan_retains_settings",true);controller[0].handleNewChatSession();
   }catch(Exception e){throw new RuntimeException(e);}});
   edt(()->{if(query.getTaskToolPolicyPanel().snapshot()!=null)throw new AssertionError("New chat retained policy");result.addProperty("conversation_new_reset",true);});
   edt(()->{try{
    var panel=query.getTaskToolPolicyPanel();
    ((JComboBox)field(panel,"mode")).setSelectedItem(ghidrassist.ui.common.TaskToolPolicyPanel.Mode.READ_ONLY);
    ((JComboBox)field(panel,"lifetime")).setSelectedItem(ghidrassist.ui.common.TaskToolPolicyPanel.Lifetime.CONVERSATION);
    ((JButton)field(panel,"apply")).doClick();
    ghidrassist.services.QueryService service=(ghidrassist.services.QueryService)field(controller[0],"queryService");
    int current=service.getCurrentSessionId();
    if(service.getChatSessions().size()<2)service.createNewChatSession();
    var sessions=service.getChatSessions();int target=-1;
    for(int i=0;i<sessions.size();i++)if(sessions.get(i).getId()!=service.getCurrentSessionId()){target=i;break;}
    if(target<0)throw new AssertionError("No second conversation available");
    controller[0].handleChatSessionSelection(target);
   }catch(Exception e){throw new RuntimeException(e);}});
   edt(()->{if(query.getTaskToolPolicyPanel().snapshot()!=null)throw new AssertionError("Switch chat retained policy");result.addProperty("conversation_switch_reset",true);});
   for(String id:List.of("GUI_ALLOW","GUI_ASYNC","GUI_ALIAS_BUDGET","GUI_STATIC_DUP")) {
    Fixture fixture=new Fixture();
    APIProviderConfig cfg=new APIProviderConfig("GUI Regression",APIProvider.ProviderType.OPENAI_PLATFORM_API,id,4096,endpoint,"local-regression",false,true,20);
    ghidra.framework.preferences.Preferences.setProperty("GhidrAssist.APIProviders",JSON.toJson(List.of(cfg)));
    ghidra.framework.preferences.Preferences.setProperty("GhidrAssist.SelectedAPIProvider",cfg.getName());
    Path gate=out.resolve(id+".registered");Files.deleteIfExists(gate);
    edt(()->{try{((JButton)field(query,"newButton")).doClick();}catch(Exception e){throw new RuntimeException(e);}});
    edt(()->{}); // The real New action queues session creation on EDT.
    edt(()->{try{
     ((JCheckBox)field(query,"useAgenticCheckBox")).setSelected(true);
     ((JTextArea)field(query,"queryTextArea")).setText("Run "+id+". Respect the task policy and report actual tool outcomes.");
     ((JButton)field(query,"submitButton")).doClick();
    }catch(Exception e){throw new RuntimeException(e);}});
    waitFor(()->onEdt(()->{try{return ((JPanel)field(query,"planPanel")).isVisible();}catch(Exception e){throw new RuntimeException(e);}}),30);
    edt(()->{try{
     var panel=query.getTaskToolPolicyPanel();
     var nativeTools=new ghidrassist.tools.native_.NativeToolManager(new ghidrassist.AnalysisDB());nativeTools.setContext(program);
     List<Tool> tools=new ArrayList<>(nativeTools.getTools());tools.addAll(fixture.getTools());panel.setTools(tools);
     panel.showConfiguration(query,()->{});
     ((JComboBox)field(panel,"mode")).setSelectedItem(ghidrassist.ui.common.TaskToolPolicyPanel.Mode.SELECTED);
     JTable rows=(JTable)field(panel,"table");
     for(int row=0;row<rows.getRowCount();row++) {
      String name=String.valueOf(rows.getValueAt(row,0));
      boolean allowed=id.startsWith("GUI_ALIAS")||id.equals("GUI_STATIC_DUP")?name.startsWith("get_gui_fact")
       :id.equals("GUI_ASYNC")?name.equals("get_task_status"):name.equals("ga_get_document_page");
      rows.setValueAt(allowed,row,1); rows.setValueAt((id.equals("GUI_BUDGET")&&name.equals("ga_get_document_page"))||(id.equals("GUI_ALIAS_BUDGET")&&name.equals("get_gui_fact"))?"1":"",row,2);
     }
     // Validate the real Swing editor before submitting the same task policy.
     if(rows.getRowCount()>0){Object previous=rows.getValueAt(0,2);rows.setValueAt("invalid",0,2);
      ((JButton)field(panel,"apply")).doClick();
      if(!((JTextArea)field(panel,"notice")).getText().contains("nonnegative"))throw new AssertionError("GUI accepted an invalid budget");
      if(panel.snapshot()!=null)throw new AssertionError("Invalid budget was committed");rows.setValueAt(previous,0,2);}
     ((JButton)field(panel,"apply")).doClick();
     if(panel.snapshot()==null)throw new AssertionError("Selected policy was not applied");
     Files.writeString(out.resolve(id+"-policy.json"),JSON.toJson(panel.snapshot()));
     Window policyWindow=SwingUtilities.getWindowAncestor(query);policyWindow.validate();
     BufferedImage configured=new BufferedImage(policyWindow.getWidth(),policyWindow.getHeight(),BufferedImage.TYPE_INT_RGB);
     Graphics2D drawing=configured.createGraphics();policyWindow.printAll(drawing);drawing.dispose();ImageIO.write(configured,"png",out.resolve(id+"-policy.png").toFile());
     ((JButton)field(query,"approvePlanButton")).doClick();
    }catch(Exception e){throw new RuntimeException(e);}});
    Object[] orchestrator=new Object[1];
    waitFor(()->{try{orchestrator[0]=field(controller[0],"currentOrchestrator");return orchestrator[0]!=null;}catch(Exception e){throw new RuntimeException(e);}},20);
    ToolRegistry registry=(ToolRegistry)field(orchestrator[0],"toolRegistry");registry.registerProvider(fixture);Files.writeString(gate,"ready");
    waitFor(()->onEdt(()->{try{
        if (((JPanel)field(query,"approvalPanel")).isVisible()) ((JButton)field(query,"approveOnceButton")).doClick();
        return !(boolean)field(controller[0],"isQueryRunning");
    }catch(Exception e){throw new RuntimeException(e);}}),60);
    JsonObject record=new JsonObject();JsonArray entries=new JsonArray();
    for(var entry:registry.getExecutionJournal().snapshot()) {
     JsonObject j=new JsonObject();j.addProperty("tool",entry.toolName());j.addProperty("state",entry.state().toString());j.addProperty("executed",entry.executed());j.addProperty("detail",entry.detail());entries.add(j);
    }
    record.add("journal",entries);
    edt(()->{try{
     record.addProperty("edt",SwingUtilities.isEventDispatchThread());record.addProperty("window_showing",tool[0].getToolFrame().isShowing());
     record.addProperty("query_showing",query.isShowing());
     record.addProperty("provider_in_tool",((docking.ComponentProvider)provider).isInTool());
    }catch(Exception e){throw new RuntimeException(e);}
     try {
      javax.swing.table.DefaultTableModel model=(javax.swing.table.DefaultTableModel)field(query.getTaskToolPolicyPanel(),"events");
      JsonArray rows=new JsonArray();for(int row=0;row<model.getRowCount();row++){JsonArray values=new JsonArray();for(int col=0;col<model.getColumnCount();col++)values.add(String.valueOf(model.getValueAt(row,col)));rows.add(values);}
      record.add("gui_outcomes",rows);record.addProperty("response_html",((JTextPane)field(query,"responseTextPane")).getText());
      Window actualWindow=SwingUtilities.getWindowAncestor(query);
      if(actualWindow==null || !query.isShowing()) throw new AssertionError("Query GUI is not actually visible");
      BufferedImage image=new BufferedImage(actualWindow.getWidth(),actualWindow.getHeight(),BufferedImage.TYPE_INT_RGB);
      Graphics2D graphics=image.createGraphics();actualWindow.printAll(graphics);graphics.dispose();ImageIO.write(image,"png",out.resolve(id+".png").toFile());
     }catch(Exception e){throw new RuntimeException(e);}
    });
    cases.add(id,record);Files.writeString(out.resolve("gui-results.json"),JSON.toJson(result));
   }
   }
  } finally {
   edt(()->{if(controller[0]!=null)controller[0].dispose();if(tool[0]!=null){tool[0].getService(ProgramManager.class).closeAllPrograms(true);tool[0].shutdown();}});
   program.release(consumer);project.close();
  }
  Files.writeString(out.resolve("gui-results.json"),JSON.toJson(result));
  System.exit(0);
 }
}
