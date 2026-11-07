package ghidrassist;

import java.lang.reflect.Type;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidrassist.apiprovider.APIProviderConfig;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = GhidrAssistPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "GhidrAssist LLM Plugin",
    description = "A plugin that provides code assistance using a language model."
)
public class GhidrAssistPlugin extends ProgramPlugin {
    public enum CodeViewType {
        IS_DECOMPILER,
        IS_DISASSEMBLER,
        UNKNOWN
    }
    private GhidrAssistProvider provider;
    private ghidrassist.automation.AutomationServer automationServer;
    // ProgramPlugin.currentProgram may already have been changed by Ghidra
    // before programActivated() is invoked; track the prior event separately.
    private Program lastEvidenceProgram;

    public GhidrAssistProvider getAutomationProvider() { return provider; }
    private String lastActiveProvider;

    public GhidrAssistPlugin(PluginTool tool) {
        super(tool);
        String pluginName = getName();
        provider = new GhidrAssistProvider(this, pluginName);
        try { automationServer = ghidrassist.automation.AutomationServer.start(this); }
        catch (java.io.IOException error) { ghidra.util.Msg.error(this, "Automation startup failed", error); }
    }

    @Override
    protected void dispose() {
        ghidrassist.agent.react.AgenticEvidenceRegistry.shared()
            .invalidate(lastEvidenceProgram);
        if (automationServer != null) { automationServer.close(); automationServer = null; }
        if (provider != null) {
            tool.removeComponentProvider(provider);
            provider = null;
        }
        super.dispose();
    }

    @Override
    protected void programActivated(Program program) {
        // GA-12/15: even returning to a previously opened Program must
        // not expose findings gathered while CodeBrowser displayed another.
        // A running ReAct job may still finish asynchronously; its cache
        // cannot be reattached without an entirely new investigation.
        // Ghidra's ProgramPlugin event machinery can update its inherited
        // currentProgram BEFORE dispatching this callback. Only our own
        // last-activation field identifies the previously displayed source.
        Program previous=lastEvidenceProgram;
        lastEvidenceProgram=program;
        if(previous!=null && previous!=program) {
            ghidrassist.agent.react.AgenticEvidenceRegistry.shared()
                .invalidate(previous);
        }
        super.programActivated(program);
        if (provider != null) {
            javax.swing.SwingUtilities.invokeLater(() -> {
                if (provider != null) provider.getUI().refreshRAGDocuments();
            });
        }
    }

    @Override
    public void locationChanged(ProgramLocation loc) {
        if (provider != null) {
            provider.getUI().updateLocation(loc);
        }
    }

    public Program getCurrentProgram() {
        return currentProgram;
    }

    public Address getCurrentAddress() {
        if (currentLocation != null) {
            return currentLocation.getAddress();
        }
        return null;
    }

    public Function getCurrentFunction() {
        Program program = getCurrentProgram();
        Address address = getCurrentAddress();

        if (program != null && address != null) {
            FunctionManager functionManager = program.getFunctionManager();
            return functionManager.getFunctionContaining(address);
        }
        return null;
    }

    public String getLastActiveProvider() {
        return lastActiveProvider;
    }
    
    public CodeViewType checkLastActiveCodeView() {
        if (currentLocation instanceof DecompilerLocation) {
            return CodeViewType.IS_DECOMPILER;
        } else if (currentLocation != null) {
            return CodeViewType.IS_DISASSEMBLER;
        } else {
            return CodeViewType.UNKNOWN;
        }
    }

    public static APIProviderConfig getCurrentProviderConfig() {
        // Load the list of API providers from preferences
        String providersJson = Preferences.getProperty("GhidrAssist.APIProviders", "[]");
        Gson gson = new Gson();
        Type listType = new TypeToken<List<APIProviderConfig>>() {}.getType();
        List<APIProviderConfig> apiProviders = gson.fromJson(providersJson, listType);
        if (apiProviders == null) {
            return null;
        }

        // Load the selected provider name
        String selectedProviderName = Preferences.getProperty("GhidrAssist.SelectedAPIProvider", "");
        
        for (APIProviderConfig provider : apiProviders) {
            if (provider == null) {
                continue;
            }
            provider.normalizeLegacyDefaults();
            if (provider.getName().equals(selectedProviderName)) {
                return provider;
            }
        }

        return null;
    }

	public GhidrAssistPlugin getInstance() {
		return this;
	}
}
