// GA-09 synthetic-only full CodeBrowser/Listing regression for pinned PR #56.
// No private ECU firmware, original Ghidra projects, OAuth or external models.
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.framework.project.tool.GhidraToolTemplate;
import org.jdom2.output.XMLOutputter;
import org.jdom2.input.SAXBuilder;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.GoToService;
import ghidra.app.services.CodeViewerService;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.GhidrAssistProvider;
import ghidrassist.ui.GhidrAssistUI;
import ghidrassist.ui.tabs.HardwareAnalysisTab;
import ghidrassist.hardware.HardwareInventoryService;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

public final class CodeBrowserMmioMain {
    static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    static final String PROGRAM_A = "synthetic-mmio.bin";
    static final String PROGRAM_B = "guard-other.bin";
    static class Manager extends DefaultProjectManager { Manager(){super();} }
    static class Tool extends GhidraTool {
        // A full GhidraTool, unlike a generic PluginTool, owns the
        // ToolExtensionsStatusManager and persists <EXTENSIONS> in XML.
        Tool(Project p){super(p,"GhidrAssist isolated CodeBrowser MMIO");}
        Tool(Project p,GhidraToolTemplate t){super(p,t);}
        void shutdown(){super.dispose();}
    }
    static void require(boolean ok,String text) {
        if(!ok)throw new AssertionError(text);
    }
    static Object field(Object owner,String name) throws Exception {
        for(Class<?> c=owner.getClass();c!=null;c=c.getSuperclass())
            try {
                Field f=c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(owner);
            }catch(NoSuchFieldException ignored){}
        throw new NoSuchFieldException(name);
    }
    static void edt(Runnable r)throws Exception {
        if(SwingUtilities.isEventDispatchThread())r.run();
        else SwingUtilities.invokeAndWait(r);
    }
    static boolean evalEdt(BooleanSupplier test)throws Exception {
        boolean[] result={false};
        edt(()->result[0]=test.getAsBoolean());
        return result[0];
    }
    static void until(BooleanSupplier pred,int timeoutSeconds)throws Exception {
        long deadline=System.nanoTime()+timeoutSeconds*1000000000L;
        while(System.nanoTime()<deadline){
            if(pred.getAsBoolean())return;
            Thread.sleep(60);
        }
        throw new AssertionError("Timed out waiting for real GUI condition");
    }
    static <T extends Component> T child(Component component,Class<T> type) {
        if(type.isInstance(component))return type.cast(component);
        if(component instanceof Container container)
            for(Component c:container.getComponents()){
                T found=child(c,type);
                if(found!=null)return found;
            }
        return null;
    }
    static JButton button(Component root,String name) {
        if(root instanceof JButton b && name.equals(b.getText()))return b;
        if(root instanceof Container container)
            for(Component c:container.getComponents()){
                JButton found=button(c,name);
                if(found!=null)return found;
            }
        return null;
    }
    static JDialog mmioDialog() {
        JDialog found=null;
        for(Window window:Window.getWindows()){
            if(window instanceof JDialog d && d.isShowing() &&
                    d.getTitle().startsWith("MMIO access references")){
                if(found!=null)throw new AssertionError("Ambiguous MMIO dialogs");
                found=d;
            }
        }
        return found;
    }
    static void clickTwice(JTable table) {
        Rectangle r=table.getCellRect(table.getSelectedRow(),0,true);
        MouseEvent ev=new MouseEvent(table,MouseEvent.MOUSE_CLICKED,
            System.currentTimeMillis(),0,r.x+5,r.y+5,2,false,MouseEvent.BUTTON1);
        for(MouseListener listener:table.getMouseListeners())listener.mouseClicked(ev);
    }
    static boolean at(CodeViewerService viewer,long address) {
        ProgramLocation loc=viewer.getCurrentLocation();
        return loc!=null && loc.getAddress()!=null &&
            loc.getAddress().getOffset()==address;
    }
    static String hex(Program p,long address) {
        return p.getAddressFactory().getDefaultAddressSpace()
            .getAddress(address).toString();
    }
    public static void main(String[] args)throws Exception {
        Path config=Path.of(args[0]),out=Path.of(args[1]);
        JsonObject conf=GSON.fromJson(Files.readString(config),JsonObject.class);
        var app=new GhidraApplicationConfiguration();
        app.setShowSplashScreen(false);
        app.setApplicationLogFile(out.resolve("application.log").toFile());
        Application.initializeApplication(new GhidraApplicationLayout(
            Path.of(conf.get("ghidra").getAsString()).toFile()),app);
        ghidra.framework.preferences.Preferences.setProperty(
            "GhidrAssist.LuceneIndexPath",conf.get("index").getAsString());
        ghidra.framework.preferences.Preferences.setProperty(
            "GhidrAssist.RAGLibraries.v1","[]");
        Manager manager=new Manager();
        Project project=manager.openProject(new ProjectLocator(
            conf.get("project_dir").getAsString(),"CodeBrowserFixture"),false,false);
        AppInfo.setActiveProject(project);
        Object consumer=new Object();
        Program first=(Program)project.getProjectData().getFile("/"+PROGRAM_A)
            .getDomainObject(consumer,false,false,TaskMonitor.DUMMY);
        Program second=(Program)project.getProjectData().getFile("/"+PROGRAM_B)
            .getDomainObject(consumer,false,false,TaskMonitor.DUMMY);
        Tool[] tool={null};
        JsonObject result=new JsonObject();
        result.addProperty("schema",1);
        result.addProperty("ghidra_version","12.1.4");
        result.addProperty("synthetic_only",true);
        result.addProperty("supervisor_ack",false);
        result.addProperty("application_headless",app.isHeadless());
        result.addProperty("awt_headless",GraphicsEnvironment.isHeadless());
        if(args.length==3 && "restore".equals(args[2])) {
            Tool[] restored={null};
            try {
                require(!app.isHeadless() && !GraphicsEnvironment.isHeadless(),
                    "Restored CodeBrowser must run with a real display");
                var persisted=new SAXBuilder().build(
                    out.resolve("tool-template.xml").toFile()).getRootElement();
                var template=new GhidraToolTemplate(persisted,
                    "synthetic-test-only-template");
                // GhidraTool constructs menus/actions: initialization MUST
                // execute on the Swing EDT, not the Java startup thread.
                edt(()->{
                    restored[0]=new Tool(project,template);
                    restored[0].setVisible(true);
                });
                require(restored[0].getManagedPlugins().stream().anyMatch(
                    p->p instanceof GhidrAssistPlugin),
                    "GhidrAssist missing after actual Java-process restart");
                require(restored[0].getService(CodeViewerService.class)!=null,
                    "CodeBrowser Listing missing from saved tool template");
                Thread.sleep(900);
                for(Window w:Window.getWindows()) {
                    if(w.isShowing() && w instanceof JDialog dlg &&
                            dlg.getTitle().contains("New Plugins Found"))
                        throw new AssertionError(
                            "New extension prompt returned after full process restart");
                }
                JsonObject restarted=new JsonObject();
                restarted.addProperty("schema",1);
                restarted.addProperty("restart_process_verified",true);
                restarted.addProperty("codebrowser_restored",true);
                restarted.addProperty("ghidrassist_restored",true);
                restarted.addProperty("no_repeated_plugin_prompt",true);
                restarted.addProperty("private_data_used",false);
                restarted.addProperty("supervisor_ack",false);
                Files.writeString(out.resolve("restart-results.json"),
                    GSON.toJson(restarted));
            } finally {
                if(restored[0]!=null) {
                    edt(()->restored[0].shutdown());
                }
                first.release(consumer);
                second.release(consumer);
                project.close();
            }
            return;
        }
        try {
            require(!app.isHeadless() && !GraphicsEnvironment.isHeadless(),
                "Real Swing display required");
            Address site=first.getAddressFactory().getDefaultAddressSpace()
                .getAddress(0x20);
            // The fixture, never a private project, is the ONLY write target.
            int tx=first.startTransaction("TEST-ONLY decode synthetic MMIO");
            try {
                require(new DisassembleCommand(site,null,false)
                    .applyTo(first,TaskMonitor.DUMMY),
                    "Failed to disassemble synthetic MOVE.W");
            }finally{first.endTransaction(tx,true);}
            Instruction instruction=first.getListing().getInstructionAt(site);
            require(instruction!=null && instruction.toString()
                .toUpperCase(Locale.ROOT).contains("FFFA00"),
                "Synthetic 68k direct destination was not decoded");
            var scan=new HardwareInventoryService().scan(first,true,TaskMonitor.DUMMY);
            require(scan.sites.stream().anyMatch(s->s.pc.equals(site) &&
                    s.register.equals("SIMCR") && s.literal!=null &&
                    s.literal==0x40ca),
                "Read-only scanner did not recognize synthetic SIMCR word");
            result.addProperty("synthetic_simcr_site",true);
            String before=instruction.toString();
            edt(()->{try{
                tool[0]=new Tool(project);
                tool[0].addPlugins(List.of(
                    "ghidra.app.plugin.core.progmgr.ProgramManagerPlugin",
                    "ghidra.app.plugin.core.gotoquery.GoToServicePlugin",
                    "ghidra.app.plugin.core.clipboard.ClipboardPlugin",
                    "ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin",
                    "ghidrassist.GhidrAssistPlugin"));
                ProgramManager pm=tool[0].getService(ProgramManager.class);
                pm.openProgram(first);
                pm.openProgram(second,ProgramManager.OPEN_VISIBLE);
                pm.setCurrentProgram(first);
                tool[0].setVisible(true);
                tool[0].getToolFrame().setSize(1300,950);
            }catch(Exception e){throw new RuntimeException(e);}});
            require(tool[0].getService(GoToService.class)!=null,
                "Real GoToService absent");
            CodeViewerService viewer=tool[0].getService(CodeViewerService.class);
            require(viewer!=null && viewer.getListingPanel()!=null,
                "Real CodeBrowser Listing service missing");
            GhidrAssistPlugin plugin=(GhidrAssistPlugin)tool[0]
                .getManagedPlugins().stream().filter(
                    p->p instanceof GhidrAssistPlugin).findFirst().orElseThrow();
            GhidrAssistUI ui=((GhidrAssistProvider)field(plugin,"provider")).getUI();
            HardwareAnalysisTab tab=(HardwareAnalysisTab)field(ui,"hardwareAnalysisTab");
            // Actual tab selection through the production GhidrAssist JTabbedPane.
            edt(()->{
                try {
                    ((JTabbedPane)field(ui,"tabbedPane")).setSelectedComponent(tab);
                    ((JComboBox<?>)field(tab,"selection")).setSelectedIndex(1);
                    ((JButton)field(tab,"run")).doClick();
                }catch(Exception ex){throw new RuntimeException(ex);}
            });
            until(()->{
                try{return evalEdt(()->((JButton)fieldUnchecked(tab,"exploreMmio"))
                    .isEnabled());}
                catch(Exception e){throw new RuntimeException(e);}
            },35);
            result.addProperty("hardware_analyze_gui",true);
            edt(()->{try{
                ((JButton)field(tab,"exploreMmio")).doClick();
            }catch(Exception e){throw new RuntimeException(e);}});
            JDialog dialog=mmioDialog();
            require(dialog!=null,"Real MMIO references dialog never appeared");
            JTable table=child(dialog.getContentPane(),JTable.class);
            require(table!=null && table.getRowCount()>0,
                "No real synthetic SIMCR table row");
            JTextField filter=child(dialog.getContentPane(),JTextField.class);
            require(filter!=null,"No real MMIO filter");
            edt(()->filter.setText("SIMCR"));
            require(table.getRowCount()==1,"SIMCR filter did not isolate fixture");
            edt(()->table.setRowSelectionInterval(0,0));
            String column=table.getValueAt(0,0).toString();
            require(column.toLowerCase(Locale.ROOT).contains("20"),
                "MMIO row PC does not reference synthetic instruction");
            JButton go=button(dialog.getContentPane(),"Go To Listing");
            require(go!=null,"Go To Listing action missing");
            edt(()->{
                try {
                    Address different=first.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(0x24);
                    tool[0].getService(GoToService.class).goTo(different,first);
                    go.doClick();
                }catch(Exception e){throw new RuntimeException(e);}
            });
            until(()->{
                try{return evalEdt(()->at(viewer,0x20));}
                catch(Exception e){throw new RuntimeException(e);}
            },15);
            result.addProperty("listing_navigation",true);
            edt(()->{
                ProgramManager managerService=tool[0].getService(ProgramManager.class);
                managerService.setCurrentProgram(second);
            });
            until(()->{
                try{return evalEdt(()->tool[0]
                    .getService(ProgramManager.class).getCurrentProgram()==second);}
                catch(Exception e){throw new RuntimeException(e);}
            },10);
            // Navigation guard must reject both button and double-click.
            edt(()->go.doClick());
            require(!at(viewer,0x20), "Stale Go To Listing changed the second Listing");
            JLabel label=child(dialog.getContentPane(),JLabel.class);
            boolean warned=false;
            for(Component c:((Container)dialog.getContentPane()).getComponents()){
                if(c instanceof Container component)
                    warned |= containsWarning(component);
            }
            require(warned,"No active-program-change warning");
            edt(()->clickTwice(table));
            require(tool[0].getService(ProgramManager.class).getCurrentProgram()==second &&
                !at(viewer,0x20),"Double-click bypassed stale-program guard");
            result.addProperty("stale_go_to_rejected",true);
            result.addProperty("stale_double_click_rejected",true);
            result.addProperty("listing_remained_second_program",true);
            require(first.getListing().getInstructionAt(site).toString().equals(before),
                "Hardware Analyze mutated synthetic Listing");
            result.addProperty("read_only_analyze",true);
            // This is serialized tool *configuration*, not user preference persistence
            // across a real application restart.
            ToolTemplate saved=tool[0].saveToolToToolTemplate();
            require(saved instanceof GhidraToolTemplate &&
                    saved.getToolElement()!=null,
                "Ghidra CodeBrowser configuration is not a persistable tool template");
            String xml=new XMLOutputter().outputString(saved.getToolElement());
            require(xml.contains("<EXTENSIONS>") &&
                    xml.contains("GhidrAssist") &&
                    xml.contains("ghidrassist.GhidrAssistPlugin"),
                "Saved tool XML lacks GhidrAssist extension/plugin records");
            result.addProperty("tool_template_saved",true);
            result.addProperty("extension_metadata_serialized",true);
            // Persist a real GhidraToolTemplate on disk in disposable output.
            // The runner launches a NEW Java process to read it back.
            Files.writeString(out.resolve("tool-template.xml"),
                new XMLOutputter().outputString(
                    ((GhidraToolTemplate)saved).saveToXml()));
            // Restore ONLY the synthetic test tool and confirm installed plugin
            // does not return as an unknown extension in the same run.
            edt(()->{try{
                dialog.dispose();
                tool[0].shutdown();
                tool[0]=new Tool(project,(GhidraToolTemplate)saved);
                tool[0].setVisible(true);
            }catch(Exception ex){throw new RuntimeException(ex);}});
            require(tool[0].getManagedPlugins().stream()
                .anyMatch(p->p instanceof GhidrAssistPlugin),
                "Restored tool template lost GhidrAssistPlugin");
            Thread.sleep(650);
            for(Window w:Window.getWindows()){
                if(w.isShowing() && w instanceof JDialog dlg &&
                        dlg.getTitle().contains("New Plugins Found"))
                    throw new AssertionError("Known extension prompts again after tool restore");
            }
            result.addProperty("tool_template_reloaded",true);
            result.addProperty("no_new_extension_prompt_on_restore",true);
            Files.writeString(out.resolve("gui-results.json"),GSON.toJson(result));
        } finally {
            if(tool[0]!=null)edt(()->tool[0].shutdown());
            first.release(consumer);
            second.release(consumer);
            project.close();
        }
    }
    static Object fieldUnchecked(Object obj,String name){
        try{return field(obj,name);}catch(Exception e){throw new RuntimeException(e);}
    }
    static boolean containsWarning(Component comp){
        if(comp instanceof JLabel label && label.getText()!=null &&
                label.getText().contains("Active program changed; rerun Analyze."))
            return true;
        if(comp instanceof Container container)
            for(Component child:container.getComponents())
                if(containsWarning(child))return true;
        return false;
    }
}
