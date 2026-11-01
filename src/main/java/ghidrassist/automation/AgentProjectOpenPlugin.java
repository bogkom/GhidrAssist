package ghidrassist.automation;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import javax.swing.Timer;
import java.nio.file.Path;
import java.util.List;

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
public final class AgentProjectOpenPlugin extends Plugin implements FrontEndable {
    private Timer poller;
    private int attempts;

    public AgentProjectOpenPlugin(PluginTool tool) {
        super(tool);
        String path = System.getProperty("ghidrassist.automation.openProgram", "");
        String expected = System.getProperty("ghidrassist.automation.project", "");
        if (path.isBlank() || expected.isBlank()) {
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
            if (file == null || !file.canSave() || file.isReadOnly()) {
                Msg.error(this,"Automation program absent or not writable: " + programPath);
                poller.stop();
                return;
            }
            poller.stop();
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
