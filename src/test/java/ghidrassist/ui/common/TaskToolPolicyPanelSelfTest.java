package ghidrassist.ui.common;

import com.google.gson.JsonObject;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.registry.ToolExecutionPolicy;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import javax.imageio.ImageIO;

/** Real Swing editor checks: inventory/filtering, committed policy, lifetimes and resizing. */
public final class TaskToolPolicyPanelSelfTest {
    private static int checks;
    private static Object field(Object owner, String name) throws Exception {
        Field f=owner.getClass().getDeclaredField(name); f.setAccessible(true); return f.get(owner);
    }
    private static void check(boolean pass,String message) { checks++; if(!pass)throw new AssertionError(message); }
    private static JButton button(Container parent,String text) {
        for(Component c:parent.getComponents()) {
            if(c instanceof JButton b && b.getText().equals(text))return b;
            if(c instanceof Container nested){JButton b=button(nested,text);if(b!=null)return b;}
        }
        return null;
    }
    private static void shot(Window window,Path output)throws Exception {
        BufferedImage image=new BufferedImage(window.getWidth(),window.getHeight(),BufferedImage.TYPE_INT_RGB);
        Graphics2D g=image.createGraphics();window.printAll(g);g.dispose();ImageIO.write(image,"png",output.toFile());
    }
    private static void layout(Component c) {
        if(c instanceof Container p){p.doLayout();for(Component child:p.getComponents())layout(child);}
    }
    private static void bounds(Container c) {
        for(Component child:c.getComponents()) {
            if(!child.isVisible())continue;
            if(child instanceof JButton || child instanceof JComboBox || child instanceof JTextField) {
                Rectangle b=child.getBounds();
                check(b.x>=0 && b.y>=0 && b.x+b.width<=c.getWidth() && b.y+b.height<=c.getHeight(),"Clipped control: "+child.getName()+" "+b+" parent="+c.getSize());
            }
            if(child instanceof Container nested && !(child instanceof JScrollPane) && !(child instanceof JTable))bounds(nested);
        }
    }
    public static void main(String[] args)throws Exception {
        if(GraphicsEnvironment.isHeadless())throw new AssertionError("A real Swing display is required");
        Path output=Path.of(args[0]);Files.createDirectories(output);
        Throwable[] error={null};
        SwingUtilities.invokeAndWait(()->{
            JFrame owner=new JFrame("Task policy UI regression");
            TaskToolPolicyPanel panel=new TaskToolPolicyPanel(()->{});
            try {
                owner.setSize(360,600);owner.add(panel.getConfigureButton(),BorderLayout.NORTH);owner.setVisible(true);
                check(panel.getParent()==null,"Policy editor must not occupy the conversation area");
                check(panel.snapshot()==null,"Default preserves legacy/unrestricted overload");
                List<Tool> inventory=new ArrayList<>();
                for(int i=0;i<320;i++) {
                    final int n=i;
                    inventory.add(new Tool(){
                        public String getName(){return "mcp_server_"+(n%8)+(n%2==0?"_get_function_":"_update_function_")+n+(n==0?"_a_very_long_untruncated_remote_tool_name":"");}
                        public String getDescription(){return n==17?"Unique phrase for description lookup":"Actual provider description number "+n;}
                        public String getSource(){return "mcp:provider-"+(n%8);}
                        public JsonObject getInputSchema(){return new JsonObject();}
                    });
                }
                panel.setTools(inventory);
                @SuppressWarnings("unchecked") JComboBox<TaskToolPolicyPanel.Mode> mode=(JComboBox<TaskToolPolicyPanel.Mode>)field(panel,"mode");
                @SuppressWarnings("unchecked") JComboBox<TaskToolPolicyPanel.Lifetime> lifetime=(JComboBox<TaskToolPolicyPanel.Lifetime>)field(panel,"lifetime");
                JTextField search=(JTextField)field(panel,"search"),total=(JTextField)field(panel,"total");
                JTable table=(JTable)field(panel,"table");JButton apply=(JButton)field(panel,"apply");
                @SuppressWarnings("unchecked") JComboBox<String> provider=(JComboBox<String>)field(panel,"provider");
                panel.showConfiguration(owner,()->{});JDialog dialog=(JDialog)field(panel,"dialog");
                check(dialog.isShowing()&&dialog.isResizable()&&!dialog.isModal(),"Resizable modeless window is required");
                check(table.getRowCount()==320,"Large MCP inventory must be available");
                search.setText("UNIQUE PHRASE");check(table.getRowCount()==1,"Description search must be case insensitive");
                search.setText("mcp_server_0_get_function_0_a_very_long");check(table.getRowCount()==1,"Full name search");
                check(table.getValueAt(0,0).toString().endsWith("_a_very_long_untruncated_remote_tool_name"),"Do not shorten registered names");
                check(table.getColumnModel().getColumn(0).getPreferredWidth()>=table.getFontMetrics(table.getFont()).stringWidth(inventory.get(0).getName())+20,"Full tool names remain reachable by horizontal scrolling");
                search.setText("[");check(table.getRowCount()==0,"Search is literal, not a regular expression");
                search.setText("");provider.setSelectedItem("mcp:provider-3");check(table.getRowCount()==40,"Provider grouping/filter");
                mode.setSelectedItem(TaskToolPolicyPanel.Mode.SELECTED);
                provider.setSelectedIndex(0);button(panel,"Deselect all shown").doClick();
                provider.setSelectedItem("mcp:provider-3");button(panel,"Select all shown").doClick();
                search.setText("UNIQUE PHRASE");check(table.getRowCount()==0,"Combined filters");search.setText("");
                check(((JLabel)field(panel,"count")).getText().contains("Allowed: 40 / 320"),"Filtered selection count must include hidden tools");
                provider.setSelectedIndex(0);button(panel,"Deselect all shown").doClick();
                search.setText("mcp_server_0_get_function_0_a_very_long");table.setValueAt(true,0,1);table.setValueAt("1",0,2);total.setText("1");
                lifetime.setSelectedItem(TaskToolPolicyPanel.Lifetime.CONVERSATION);apply.doClick();
                ToolExecutionPolicy policy=panel.snapshot();String tool=inventory.get(0).getName();
                check(policy!=null&&policy.allows(tool)&&!policy.allows(inventory.get(1).getName()),"Exact selected allowlist");
                check(policy.totalLimit()==1&&policy.limit(tool)==1,"Global and per-tool limits");
                panel.showConfiguration(owner,()->{});
                Tool discovered=new Tool(){
                    public String getName(){return "mcp_new_get_unknown";}
                    public String getDescription(){return "";}
                    public String getSource(){return "mcp:new-provider";}
                    public JsonObject getInputSchema(){return new JsonObject();}
                };
                List<Tool> expanded=new ArrayList<>(inventory);expanded.add(discovered);panel.setTools(expanded);search.setText(discovered.getName());
                check(table.getRowCount()==1&&!Boolean.TRUE.equals(table.getValueAt(0,1)),"Newly discovered tools cannot widen a selected allowlist");
                check(table.getValueAt(0,4).equals(""),"Do not invent descriptions for unknown tools");
                apply.doClick();check(!panel.snapshot().allows(discovered.getName()),"Refresh preserves the committed allowlist");panel.setTools(inventory);search.setText("");
                check(panel.getConfigureButton().getText().contains("Selected: 1")&&panel.getConfigureButton().getText().contains("chat"),"Main toolbar describes active mode/lifetime");
                panel.beginExecution();check(!panel.getConfigureButton().isEnabled()&&!table.isCellEditable(0,2),"Freeze editing during execution");panel.finishExecution();
                check(panel.snapshot()!=null&&panel.snapshot().totalLimit()==1,"Conversation policy survives first task");
                panel.beginExecution();panel.finishExecution();check(panel.snapshot()!=null,"Conversation policy survives repeat task");
                panel.showConfiguration(owner,()->{});total.setText("99");button(panel,"Cancel").doClick();check(panel.snapshot().totalLimit()==1,"Cancel cannot change committed policy");
                panel.showConfiguration(owner,()->{});check(total.getText().equals("1"),"Reopening discards unsaved edits");
                for(String invalid:List.of("-1","1.5","2147483648","invalid")){
                    total.setText(invalid);apply.doClick();check(panel.snapshot().totalLimit()==1&&dialog.isVisible(),"Invalid total must not commit: "+invalid);
                }
                total.setText("1");search.setText(tool);table.setValueAt("-1",0,2);apply.doClick();check(panel.snapshot().limit(tool)==1,"Invalid per-tool limit must not commit");
                table.setValueAt("",0,2);total.setText("0");apply.doClick();check(panel.snapshot().totalLimit()==0&&panel.snapshot().limit(tool)==null,"Zero total and Unlimited per-tool");
                panel.showConfiguration(owner,()->{});mode.setSelectedItem(TaskToolPolicyPanel.Mode.READ_ONLY);total.setText("");apply.doClick();
                check(panel.snapshot().readOnly()&&panel.snapshot().allows(inventory.get(1).getName()),"Read-only is enforced by existing registry classifier, not an invented allowlist");
                panel.showConfiguration(owner,()->{});check(((JLabel)field(panel,"count")).getText().contains("Allowed: 160 / 320"),"Read-only preview matches the registry classification");
                lifetime.setSelectedItem(TaskToolPolicyPanel.Lifetime.NEXT_TASK);apply.doClick();panel.beginExecution();panel.finishExecution();check(panel.snapshot()==null,"Next task policy resets after execution");
                panel.showConfiguration(owner,()->{});mode.setSelectedItem(TaskToolPolicyPanel.Mode.SELECTED);button(panel,"Deselect all shown").doClick();apply.doClick();check(!panel.snapshot().allows(tool),"Empty selection denies all");
                panel.resetForNewTask();check(panel.snapshot()==null,"New/switch conversation clears restrictions");
                panel.showConfiguration(owner,()->{});total.setText("1");apply.doClick();check(panel.snapshot()!=null&&panel.snapshot().allows(tool),"All available tools can have a total budget");
                panel.showConfiguration(owner,()->{});button(panel,"Restore defaults").doClick();check(panel.snapshot()!=null,"Defaults require explicit Apply");apply.doClick();check(panel.snapshot()==null,"Apply defaults restores unrestricted behavior");
                panel.showConfiguration(owner,()->{});
                dialog.setSize(620,460);layout(dialog);bounds(panel);shot(dialog,output.resolve("editor-small.png"));
                dialog.setSize(1250,780);layout(dialog);bounds(panel);shot(dialog,output.resolve("editor-large.png"));
                button(panel,"Help (?)").doClick();JDialog help=(JDialog)field(panel,"helpDialog");check(help.isShowing()&&help.isResizable(),"Help is available in a scalable window");shot(help,output.resolve("help.png"));help.setVisible(false);
                panel.record("rejected",tool,"REQUESTED","{}");panel.record("rejected",tool,"FAILED","Blocked by policy");
                panel.record("failed",tool,"REQUESTED","{}");panel.record("failed",tool,"RUNNING","{}");panel.record("failed",tool,"FAILED","Provider failed");
                panel.showHistory(owner);JDialog history=(JDialog)field(panel,"historyDialog");
                javax.swing.table.DefaultTableModel events=(javax.swing.table.DefaultTableModel)field(panel,"events");
                check(events.getValueAt(0,1).equals("REJECTED")&&events.getValueAt(1,1).equals("FAILED"),"History distinguishes rejection and failed execution");
                check(history.isShowing()&&history!=dialog&&history.isResizable(),"History is separate and optional");shot(history,output.resolve("history.png"));
                Files.writeString(output.resolve("editor-results.json"),"{\"status\":\"PASS\",\"inventory\":320,\"checks\":"+checks+",\"small_window\":\"620x460\",\"large_window\":\"1250x780\"}\n");
            } catch(Throwable t){
                error[0]=t;
                try { JDialog failed=(JDialog)field(panel,"dialog");if(failed!=null&&failed.isShowing())shot(failed,output.resolve("editor-failure.png")); } catch(Exception ignored) {}
            } finally{panel.dispose();owner.dispose();}
        });
        if(error[0]!=null)throw new AssertionError("Task policy UI failed",error[0]);
        System.out.println("TaskToolPolicyPanelSelfTest PASS "+checks+" checks");
        System.exit(0);
    }
}
