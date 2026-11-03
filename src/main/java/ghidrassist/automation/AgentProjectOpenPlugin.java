package ghidrassist.automation;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import javax.swing.Timer;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Optional Project Window plugin for explicitly requested agent sessions only.
 * A normal active project opens the program using native ToolServices, not a
 * ghidra: URL (which is read-only for local projects).
 */
@PluginInfo(
    status = PluginStatus.UNSTABLE,
    packageName = "GhidrAssist",
    category = PluginCategoryNames.COMMON,
    shortDescription = "GhidrAssist Automation Project Opener",
    description = "Opt-in synthetic/agent fixture opening in active project"
)
public final class AgentProjectOpenPlugin extends Plugin implements ApplicationLevelOnlyPlugin {
    // Exactly one Project Window opener for this JVM. Never launch from CodeBrowser.
    private static final AtomicBoolean OPEN_REQUEST_CONSUMED=new AtomicBoolean(false);
    private Timer poller;
    private int attempts;
    // Restored project tools can appear after the Project Window is ready.
    private static final int RESTORE_SETTLE_TICKS=40; // 10s at 250ms

    /** Reuse any existing CodeBrowser-like ProgramManager before launching. */
    static boolean reuseExistingProgramTool(DomainFile requested, PluginTool[] running) {
        if(running==null)return false;
        ProgramManager available=null;
        for(PluginTool existing:running) {
            if(existing==null || existing instanceof FrontEndTool)continue;
            ProgramManager pm=existing.getService(ProgramManager.class);
            if(pm==null)continue;
            for(var opened:pm.getAllOpenPrograms()) {
                if(opened!=null && opened.getDomainFile()!=null &&
                        requested.getPathname().equals(opened.getDomainFile().getPathname())) {
                    pm.setCurrentProgram(opened);
                    return true;
                }
            }
            if(available==null)available=pm;
        }
        if(available==null)return false;
        if(available.openProgram(requested)==null)
            Msg.error(AgentProjectOpenPlugin.class,
                "Existing CodeBrowser could not open requested automation program");
        // Never create an additional tool when a program-capable tool exists.
        return true;
    }


    public AgentProjectOpenPlugin(PluginTool tool) {
        super(tool);
        String path = System.getProperty("ghidrassist.automation.openProgram", "");
        String expected = System.getProperty("ghidrassist.automation.project", "");
        if (!(tool instanceof FrontEndTool) || path.isBlank() || expected.isBlank()) {
            poller = null;
            return;
        }
        poller = new Timer(250, event -> {
            if (++attempts > 240) {
                Msg.error(this,"Timed out waiting for writable automation project");
                poller.stop();
                return;
            }
            Project project = tool.getProject();
            if (project == null) return;
            Path actual = Path.of(project.getProjectLocator().getLocation(),
                project.getProjectLocator().getName() + ".gpr").toAbsolutePath().normalize();
            if (!actual.equals(Path.of(expected).toAbsolutePath().normalize())) return;
            String programPath = path.startsWith("/") ? path : "/" + path;
            DomainFile file = project.getProjectData().getFile(programPath);
            if (file == null || file.isReadOnly()) {
                Msg.error(this,"Automation program absent or marked read-only: " + programPath);
                poller.stop();
                return;
            }
            // Wait for the previously saved project workspace to restore.
            if(attempts<RESTORE_SETTLE_TICKS)return;
            poller.stop();
            if (!OPEN_REQUEST_CONSUMED.compareAndSet(false,true)) return;
            if(reuseExistingProgramTool(file,project.getToolServices().getRunningTools()))
                return;
            if (project.getToolServices().launchDefaultTool(List.of(file)) == null)
                Msg.error(this,"Unable to launch CodeBrowser from active writable project");
        });
        poller.setRepeats(true);
        poller.start();
    }

    @Override protected void dispose() {
        if (poller != null) poller.stop();
        super.dispose();
    }
}
