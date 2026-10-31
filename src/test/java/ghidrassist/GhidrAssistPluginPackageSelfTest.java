package ghidrassist;

import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginPackage;
import java.lang.reflect.Constructor;

/** Offline structural contract, not a CodeBrowser acceptance receipt. */
public final class GhidrAssistPluginPackageSelfTest {
    private GhidrAssistPluginPackageSelfTest() {}

    public static void main(String[] args) throws Exception {
        Class<GhidrAssistPluginPackage> pkgType=GhidrAssistPluginPackage.class;
        if (!PluginPackage.class.isAssignableFrom(pkgType))
            throw new AssertionError("Plugin package must extend Ghidra PluginPackage");
        if (!pkgType.getSimpleName().endsWith("PluginPackage"))
            throw new AssertionError("Plugin package must follow ClassSearcher naming");
        Constructor<GhidrAssistPluginPackage> ctor=pkgType.getConstructor();
        GhidrAssistPluginPackage pkg=ctor.newInstance();
        PluginInfo info=GhidrAssistPlugin.class.getAnnotation(PluginInfo.class);
        if (info==null)
            throw new AssertionError("GhidrAssistPlugin missing runtime @PluginInfo");
        if (!GhidrAssistPluginPackage.NAME.equals(info.packageName()) ||
                !GhidrAssistPluginPackage.NAME.equals(pkg.getName()))
            throw new AssertionError("Ghidra package lookup name mismatch");
        if (pkg.getIcon()==null || pkg.getDescription()==null ||
                pkg.getDescription().isBlank())
            throw new AssertionError("PluginPackage must provide UI metadata");
        System.out.println("GhidrAssistPluginPackageSelfTest OK");
    }
}
