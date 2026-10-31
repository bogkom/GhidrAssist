package ghidrassist;

import javax.swing.Icon;
import ghidrassist.resources.GhidrAssistIcons;
import ghidra.framework.plugintool.util.PluginPackage;

/**
 * Ghidra extension point for the package referenced by @PluginInfo on
 * GhidrAssistPlugin. Without this class, Ghidra's package registry falls back
 * to Miscellaneous and logs "Can't find plugin package ... Creating stub".
 *
 * Public zero-arg constructor and PluginPackage class name are intentional:
 * Ghidra's ClassSearcher discovers extension points by these conventions.
 */
public final class GhidrAssistPluginPackage extends PluginPackage {
    public static final String NAME = "GhidrAssist";

    private static Icon icon() {
        // Reuse the already bundled extension icon. No user files, remote
        // images, OAuth or provider settings are needed for class discovery.
        return GhidrAssistIcons.ROBOT_ICON;
    }

    public GhidrAssistPluginPackage() {
        super(NAME, icon(),
            "GhidrAssist code and hardware-analysis assistants",
            PluginPackage.FEATURE_PRIORITY);
    }
}
