// Isolated Ghidra 12.1.4 PUBLIC: completed function restart, never ECU firmware.
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import ghidrassist.hardware.HardwareAnalysisRevision;
import ghidrassist.hardware.HardwareFlowStageCache;
import ghidrassist.hardware.HardwareGhidraInputFingerprint;
import ghidrassist.hardware.HardwareDurableStageStore;
import ghidrassist.hardware.GhidraHardwareFlowService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public final class Ga12DurableFunctionsRealGhidraMain {
    static class Manager extends DefaultProjectManager { Manager(){super();} }
    private static void require(boolean yes,String message){
        if(!yes)throw new AssertionError(message);
    }
    private static Address address(Program p,long at){
        return p.getAddressFactory().getDefaultAddressSpace().getAddress(at);
    }
    private static void define(Program p,long entry,String name)throws Exception{
        Address at=address(p,entry);
        require(new DisassembleCommand(at,null,false)
            .applyTo(p,TaskMonitor.DUMMY),"Real CPU32 disassembler failed at "+at);
        Function created=p.getFunctionManager().createFunction(
            name,at,new AddressSet(at,at.add(7)),SourceType.ANALYSIS);
        require(created!=null && created.getEntryPoint().equals(at),
            "Synthetic 8-byte function not defined");
    }
    private static int count(String text,String tag){
        var matcher=Pattern.compile(Pattern.quote(tag)+"(\\d+)").matcher(text);
        require(matcher.find(),"Missing function stage counter "+tag);
        return Integer.parseInt(matcher.group(1));
    }
    public static void main(String[] args)throws Exception {
        require(args.length==5,"args: ghidra, project, reports, private-dir, phase");
        String phase=args[4];
        require(phase.equals("write")||phase.equals("read")||phase.equals("edit"),
            "Invalid stage");
        Path ghidra=Path.of(args[0]).toRealPath();
        Path projectDir=Path.of(args[1]).toRealPath();
        Path out=Path.of(args[2]).toRealPath();
        Path directory=Path.of(args[3]).toRealPath();
        System.setProperty("ghidrassist.ga12.durable.dir",directory.toString());
        var cfg=new HeadlessGhidraApplicationConfiguration();
        cfg.setApplicationLogFile(out.resolve("ghidra-functions-"+phase+".log").toFile());
        Application.initializeApplication(new GhidraApplicationLayout(ghidra.toFile()),cfg);
        Manager manager=new Manager();
        Project project=manager.openProject(new ProjectLocator(
            projectDir.toString(),"Ga11Vectors"),false,false);
        AppInfo.setActiveProject(project);
        Object consumer=new Object();
        Program full=null;
        try {
            full=(Program)project.getProjectData().getFile("/vectors-full.bin")
                .getDomainObject(consumer,false,false,TaskMonitor.DUMMY);
            require(full!=null && full.getMemory().getSize()==4096,
                "Cannot open isolated real CPU32 Ghidra Program");
            if(phase.equals("write")){
                int tx=full.startTransaction("GA12 synthetic-only function fixture");
                boolean commit=false;
                try{
                    full.getMemory().setBytes(address(full,0x600L),
                        HexFormat.of().parseHex("207c00fffa004e75"));
                    full.getMemory().setBytes(address(full,0x650L),
                        HexFormat.of().parseHex("207c00fffa104e75"));
                    define(full,0x600L,"GA12_SYNTHETIC_FUNCTION_A");
                    define(full,0x650L,"GA12_SYNTHETIC_FUNCTION_B");
                    commit=true;
                }finally{full.endTransaction(tx,commit);}
                full.save("GA12 isolated function fixture",TaskMonitor.DUMMY);
            }
            require(full.getFunctionManager().getFunctionAt(
                address(full,0x600L))!=null &&
                full.getFunctionManager().getFunctionAt(
                    address(full,0x650L))!=null,
                "Two persisted real Ghidra function entries required");
            var original=HardwareGhidraInputFingerprint.capture(
                full,TaskMonitor.DUMMY,true);
            require(original.isPresent(),"Cannot fingerprint complete synthetic Listing");
            long revisionNumber=full.getModificationNumber();
            if(phase.equals("edit")){
                int tx=full.startTransaction("GA12 isolated changed synthetic input");
                try {
                    byte old=full.getMemory().getByte(address(full,0x700));
                    full.getMemory().setByte(address(full,0x700),(byte)(old^0x5a));
                }finally{full.endTransaction(tx,true);}
                require(full.getModificationNumber()!=revisionNumber,
                    "Synthetic edit did not change Program revision");
                var modified=HardwareGhidraInputFingerprint.capture(
                    full,TaskMonitor.DUMMY,true);
                require(modified.isPresent() &&
                    !modified.get().inputSha256().equals(original.get().inputSha256()),
                    "Input changes must invalidate full Ghidra fingerprint");
            }
            long before=full.getModificationNumber();
            HardwareAnalysisRevision revision=HardwareAnalysisRevision.capture(
                full,before,full.getLanguageID().toString(),
                full.getExecutableSHA256(),true);
            boolean wasCancelled=false,wasReused=false;
            int restored=0,saved=0;
            if(phase.equals("write")){
                Program observed=full;
                AtomicInteger checks=new AtomicInteger();
                TaskMonitor interrupt=(TaskMonitor)java.lang.reflect.Proxy
                    .newProxyInstance(TaskMonitor.class.getClassLoader(),
                        new Class[]{TaskMonitor.class},(proxy,method,a)-> {
                            if(method.getName().equals("checkCancelled")) {
                                checks.incrementAndGet();
                                if(GhidraHardwareFlowService
                                        .checkpointedFunctionStages(observed)>0)
                                    throw new CancelledException();
                                return null;
                            }
                            return method.invoke(TaskMonitor.DUMMY,a);
                        });
                try{HardwareFlowStageCache.loadOrAnalyze(
                    full,revision,interrupt);}
                catch(CancelledException expected){wasCancelled=true;}
                require(wasCancelled && checks.get()>0 &&
                    GhidraHardwareFlowService.checkpointedFunctionStages(full)>0,
                    "Scan did not cancel after first complete function");
                Path finishedStage=HardwareDurableStageStore.checkpointPath(
                    directory,original.get());
                require(!Files.exists(finishedStage),
                    "Interrupted full report incorrectly written to disk");
                try(var files=Files.list(directory)){
                    require(files.anyMatch(Files::isRegularFile),
                        "Completed function not saved before interruption");
                }
                saved=1;
            }else{
                var completed=HardwareFlowStageCache.loadOrAnalyze(
                    full,revision,TaskMonitor.DUMMY);
                wasReused=completed.reused();
                require(!wasReused,"Unexpected finished-report disk cache reuse");
                restored=count(completed.report().markdown,
                    "- Completed per-function fixed points restored from disk: ");
                saved=count(completed.report().markdown,
                    "; newly saved: ");
                if(phase.equals("read")) {
                    require(restored>=1,"Previously saved function not restored across JVM");
                }else {
                    require(restored==0,"Edited Program reused stale completed function");
                }
                require(completed.report().markdown.contains(
                    "CFG/P-code initialization evidence"),
                    "No real computed CFG report after restore");
            }
            require(full.getModificationNumber()==before,
                "Read-only staged analysis edited Ghidra database");
            String proof="{\"phase\":\""+phase+"\",\"synthetic_only\":true,"+
                "\"real_ghidra\":true,\"interrupted\":"+wasCancelled+
                ",\"whole_stage_reused\":"+wasReused+
                ",\"function_restored\":"+restored+
                ",\"function_saved\":"+saved+
                ",\"program_unchanged\":true}";
            Files.writeString(out.resolve("ga12-function-"+phase+".json"),
                proof+"\n");
            System.out.println("GA12 FUNCTION RESTART "+phase+" PASS "+proof);
        }finally{
            if(full!=null)full.release(consumer);
            project.close();
        }
    }
}
