// Real Ghidra 12.1.4 PUBLIC, isolated synthetic program only.
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassist.hardware.HardwareAnalysisRevision;
import ghidrassist.hardware.HardwareFlowStageCache;
import ghidrassist.hardware.HardwareGhidraInputFingerprint;
import ghidrassist.hardware.HardwareDurableStageStore;
import java.nio.file.Files;
import java.nio.file.Path;

public final class Ga12DurableRealGhidraMain {
    private static final class Manager extends DefaultProjectManager {
        Manager(){super();}
    }
    private static void require(boolean yes,String message){
        if(!yes)throw new AssertionError(message);
    }
    public static void main(String[] args)throws Exception {
        require(args.length==5,"Arguments: ghidra,project,proof,cache,phase");
        String phase=args[4];
        require(phase.equals("write")||phase.equals("read")||phase.equals("edit"),
            "Unknown durable checkpoint phase");
        Path ghidra=Path.of(args[0]).toRealPath();
        Path projectDir=Path.of(args[1]).toRealPath();
        Path proofs=Path.of(args[2]).toRealPath();
        Path cache=Path.of(args[3]).toRealPath();
        System.setProperty("ghidrassist.ga12.durable.dir",cache.toString());
        var cfg=new HeadlessGhidraApplicationConfiguration();
        cfg.setApplicationLogFile(proofs.resolve("ghidra-"+phase+".log").toFile());
        Application.initializeApplication(new GhidraApplicationLayout(ghidra.toFile()),cfg);
        Manager manager=new Manager();
        Project project=manager.openProject(new ProjectLocator(
            projectDir.toString(),"Ga11Vectors"),false,false);
        AppInfo.setActiveProject(project);
        Object consumer=new Object();
        Program full=null;
        try{
            full=(Program)project.getProjectData()
                .getFile("/vectors-full.bin")
                .getDomainObject(consumer,false,false,TaskMonitor.DUMMY);
            require(full!=null && full.getMemory().getSize()==4096,
                "Real synthetic binary not opened");
            long before=full.getModificationNumber();
            var original=HardwareGhidraInputFingerprint.capture(
                full,TaskMonitor.DUMMY,true);
            require(original.isPresent(),
                "Missing complete Ghidra program/input/JAR fingerprint");
            if(phase.equals("edit")){
                int tx=full.startTransaction("GA12 SYNTHETIC EDIT TO INVALIDATE CACHE");
                try{
                    var address=full.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(0x700);
                    byte previous=full.getMemory().getByte(address);
                    full.getMemory().setByte(address,(byte)(previous^0x35));
                }finally{full.endTransaction(tx,true);}
                require(full.getModificationNumber()!=before,
                    "Editing real Ghidra program did not update revision");
                var modified=HardwareGhidraInputFingerprint.capture(
                    full,TaskMonitor.DUMMY,true);
                require(modified.isPresent() &&
                    !modified.get().inputSha256().equals(original.get().inputSha256()),
                    "Changed Listing/memory retained stale input fingerprint");
            }
            HardwareAnalysisRevision revision=HardwareAnalysisRevision.capture(
                full,full.getModificationNumber(),full.getLanguageID().toString(),
                full.getExecutableSHA256(),true);
            var result=HardwareFlowStageCache.loadOrAnalyze(
                full,revision,TaskMonitor.DUMMY);
            boolean expected=phase.equals("read");
            require(result.reused()==expected,
                "Restart cache reuse mismatch for phase "+phase+
                ": reused="+result.reused());
            require(result.report().cfgReviewComplete && !result.report().limited,
                "Incomplete CFG must not be persisted as full evidence");
            require(result.report().markdown.contains("CFG/P-code"),
                "Missing real Ghidra computed/restored CFG report");
            Path checkpoint=HardwareDurableStageStore.checkpointPath(
                cache,original.get());
            require(Files.isRegularFile(checkpoint),
                "Durable checkpoint was not written in isolated directory");
            if(!phase.equals("edit"))
                require(full.getModificationNumber()==before,
                    "Read-only CFG checkpoint modified Program");
            String proof="{\"phase\":\""+phase+"\",\"reused\":"+
                result.reused()+",\"synthetic_only\":true,"+
                "\"program_modification_unchanged\":"+
                (full.getModificationNumber()==before)+
                ",\"ghidra_real\":true,\"checkpoint_exists\":true}";
            Files.writeString(proofs.resolve("ga12-"+phase+".json"),proof+"\n");
            System.out.println("GA12 REAL GHIDRA "+phase+" PASS");
        }finally{
            if(full!=null)full.release(consumer);
            project.close();
        }
    }
}
