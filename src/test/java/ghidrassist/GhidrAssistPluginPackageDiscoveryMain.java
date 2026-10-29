package ghidrassist;

import java.io.File;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.plugintool.util.PluginPackage;

/**
 * Real Ghidra startup contract, not just reflection on a loadable class.
 * The extension is installed in a disposable Ghidra profile by CI.
 */
public final class GhidrAssistPluginPackageDiscoveryMain {
    private GhidrAssistPluginPackageDiscoveryMain() {}

    public static void main(String[] args) throws Exception {
        if(args.length!=1)
            throw new IllegalArgumentException("Expected Ghidra installation directory");
        var config=new HeadlessGhidraApplicationConfiguration();
        Application.initializeApplication(
            new GhidraApplicationLayout(new File(args[0])), config);
        if(!PluginPackage.exists(GhidrAssistPluginPackage.NAME))
            throw new AssertionError("Real ClassSearcher did not register GhidrAssist package");
        PluginPackage installed=PluginPackage.getPluginPackage(
            GhidrAssistPluginPackage.NAME);
        if(!(installed instanceof GhidrAssistPluginPackage))
            throw new AssertionError(
                "Real Ghidra package lookup returned fallback Miscellaneous stub");
        if(!GhidrAssistPluginPackage.NAME.equals(installed.getName()))
            throw new AssertionError("Package name mismatch in Ghidra registry");
        System.out.println("GhidrAssistPluginPackageDiscoveryMain OK");
    }
}
