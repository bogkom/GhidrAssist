package ghidrassist;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import java.awt.image.BufferedImage;
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
        // Self-contained neutral icon: no dependency on user settings, RAG,
        // external images, credentials, network or Desktop UI resources.
        return new ImageIcon(new BufferedImage(
            16, 16, BufferedImage.TYPE_INT_ARGB));
    }

    public GhidrAssistPluginPackage() {
        super(NAME, icon(),
            "GhidrAssist code and hardware-analysis assistants",
            PluginPackage.FEATURE_PRIORITY);
    }
}
