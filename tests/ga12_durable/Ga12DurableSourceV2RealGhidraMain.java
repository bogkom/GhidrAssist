// Independent Java 25 JVMs, real 12.1.4 PUBLIC Ghidra, private-free CPU32 only.
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
import ghidrassist.hardware.HardwareDurableCfgReport;
import ghidrassist.hardware.HardwareDurableStageStore;
import ghidrassist.hardware.HardwareFlowStageCache;
import ghidrassist.hardware.HardwareGhidraInputFingerprint;
import ghidrassist.hardware.HardwareResetIndirectVbrCorrelation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class Ga12DurableSourceV2RealGhidraMain {
    private static final class Manager extends DefaultProjectManager {
        Manager(){super();}
    }
    private static void require(boolean yes,String label) {
        if(!yes)throw new AssertionError("GA12 V2 REAL GHIDRA FAIL: "+label);
    }
    private static void sourceMatches(
            HardwareResetIndirectVbrCorrelation.SourceInventory source) {
        require(source!=null,"typed V2 source inventory retained");
        var first=source.page(0,1),second=source.page(1,1);
        require(first.colocatedPairs()==2 && first.rows().size()==1 &&
            first.nextOffset()==1 && first.hasMore() &&
            first.omittedIndirect()==1 && second.rows().size()==1 &&
            second.nextOffset()==2 && !second.hasMore() &&
            second.omittedIndirect()==1,
            "two page exact totals, bounded misses and stable cursor");
        require(first.rows().get(0).function()==0x130L &&
            first.rows().get(0).indirectPc()==0x138L &&
            first.rows().get(0).indirectTarget()==0x180L &&
            first.rows().get(0).vbrPc()==0x144L &&
            first.rows().get(0).mayMm() &&
            first.rows().get(0).resetRelation()==
                HardwareResetIndirectVbrCorrelation.ResetRelation
                    .IN_OBSERVED_RESET_CALL_SUBSET,
            "native RESET first source pair provenance");
        require(second.rows().get(0).function()==0x200L &&
            second.rows().get(0).indirectPc()==0x206L &&
            second.rows().get(0).vbrPc()==0x208L &&
            second.rows().get(0).resetRelation()==
                HardwareResetIndirectVbrCorrelation.ResetRelation
                    .OUTSIDE_OBSERVED_RESET_CALL_SUBSET,
            "native disconnected MOVEC pair provenance");
        require(source.page(2,1).rows().isEmpty(),
            "no fabricated pair at final cursor");
    }
    /** Convert only this synthetic fixture's typed V2 to a historic V1 payload.
     * The outer full-input-keyed store remains intact and authoritative.
     */
    private static void installLegacyV1(Path cache,
            HardwareDurableStageStore.Key key)throws Exception {
        byte[] current=HardwareDurableStageStore.load(cache,key).orElseThrow();
        var report=HardwareDurableCfgReport.decode(current).orElseThrow();
        require(report.sourceInventory()!=null,
            "migration probe requires original typed V2");
        var noSources=new HardwareDurableCfgReport.Snapshot(
            report.markdown(),report.csv(),report.functions(),
            report.indirect(),report.vbr(),report.unresolved(),
            report.visited(),report.limited(),report.resetRecognized(),
            report.resetIncomplete(),report.cfgReviewComplete(),
            report.cfgOmitted(),report.pointersOmitted(),
            report.sites(),report.roles(),report.resetFunctions());
        byte[] v2null=HardwareDurableCfgReport.encode(noSources);
        require(v2null[v2null.length-1]==0,"V2 absent-inventory flag");
        byte[] v1=Arrays.copyOf(v2null,v2null.length-1);
        int lastSchema=4+HardwareDurableCfgReport.SCHEMA.length()-1;
        require(v1[lastSchema]=='2',"known fixed ASCII schema byte");
        v1[lastSchema]='1';
        var older=HardwareDurableCfgReport.decode(v1).orElseThrow();
        require(older.sourceInventory()==null &&
            HardwareDurableCfgReport.eligibleForCompletedRestore(older),
            "historic V1 only CFG; not invented source evidence");
        HardwareDurableStageStore.save(cache,key,v1);
        require(Arrays.equals(HardwareDurableStageStore.load(cache,key)
                .orElseThrow(),v1),
            "V1 saved under exact original full fingerprint");
    }
    public static void main(String[] args)throws Exception {
        require(args.length==5,"ghidra,project,proof,cache,phase");
        String phase=args[4];
        require(phase.equals("source-write")||phase.equals("source-read")||
            phase.equals("source-edit")||phase.equals("source-v1")||
            phase.equals("source-profile"),
            "unexpected isolated V2 phase");
        Path ghidra=Path.of(args[0]).toRealPath();
        Path projectDir=Path.of(args[1]).toRealPath();
        Path proofs=Path.of(args[2]).toRealPath();
        Path cache=Path.of(args[3]).toRealPath();
        System.setProperty("ghidrassist.ga12.durable.dir",cache.toString());
        var config=new HeadlessGhidraApplicationConfiguration();
        config.setApplicationLogFile(proofs.resolve("ghidra-"+phase+".log").toFile());
        Application.initializeApplication(new GhidraApplicationLayout(
            ghidra.toFile()),config);
        Manager manager=new Manager();
        Project project=manager.openProject(new ProjectLocator(
            projectDir.toString(),"Ga12SourceV2"),false,false);
        AppInfo.setActiveProject(project);
        Object consumer=new Object();
        Program program=null;
        try {
            program=(Program)project.getProjectData()
                .getFile("/synthetic-reset-indirect-vbr.bin")
                .getDomainObject(consumer,false,false,TaskMonitor.DUMMY);
            require(program!=null &&
                program.getMemory().getSize()==0x600 &&
                "68000:BE:32:CPU32".equals(
                    program.getLanguageID().toString()),
                "real persistent CPU32 synthetic source Program");
            for(long address:new long[]{0x100,0x130,0x180,0x200,0x240})
                require(program.getFunctionManager().getFunctionAt(
                    program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(address))!=null,
                    "actual Ghidra source Function "+Long.toHexString(address));
            long beforeRevision=program.getModificationNumber();
            boolean selected=!phase.equals("source-profile");
            var original=HardwareGhidraInputFingerprint.capture(
                program,TaskMonitor.DUMMY,true).orElseThrow();
            if(phase.equals("source-edit")) {
                int tx=program.startTransaction(
                    "GA12 SYNTHETIC V2 BYTE CHANGE; NO USER PROGRAM");
                try {
                    var address=program.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(0x500);
                    byte prior=program.getMemory().getByte(address);
                    program.getMemory().setByte(address,(byte)(prior^0x33));
                }finally{program.endTransaction(tx,true);}
                var changed=HardwareGhidraInputFingerprint.capture(
                    program,TaskMonitor.DUMMY,true).orElseThrow();
                require(!changed.inputSha256().equals(original.inputSha256()),
                    "actual changed Program has distinct complete input fingerprint");
            }
            if(phase.equals("source-v1"))
                installLegacyV1(cache,original);
            var revision=HardwareAnalysisRevision.capture(program,
                program.getModificationNumber(),program.getLanguageID().toString(),
                program.getExecutableSHA256(),selected);
            var obtained=HardwareFlowStageCache.loadOrAnalyze(
                program,revision,TaskMonitor.DUMMY);
            boolean expectedReuse=phase.equals("source-read")||
                phase.equals("source-v1");
            require(obtained.reused()==expectedReuse,
                "cross-JVM reuse mismatch for "+phase);
            var report=obtained.report();
            require(report.cfgReviewComplete && !report.limited,
                "incomplete CFG cannot publish completed durable report");
            require(report.markdown.contains("CFG/P-code"),
                "real Ghidra CFG report missing");
            if(phase.equals("source-v1")) {
                require(report.sourceInventory==null,
                    "V1 restored CFG must not fabricate JSR/MOVEC source inventory");
            } else if(phase.equals("source-profile")) {
                require(report.sourceInventory==null &&
                    report.markdown.contains(
                        "Not evaluated: explicit MC68332 profile required"),
                    "generic CPU32 cannot inherit device-specific V2 sources");
            } else sourceMatches(report.sourceInventory);
            Path checkpoint=HardwareDurableStageStore.checkpointPath(
                cache,original);
            require(Files.isRegularFile(checkpoint),
                "exact original Program checkpoint must exist");
            if(!phase.equals("source-edit"))
                require(program.getModificationNumber()==beforeRevision,
                    "read-only source checkpoint modified Ghidra Program");
            String imported=program.getExecutableSHA256();
            String proof="{\"phase\":\""+phase+"\",\"ghidra_real\":true,"+
                "\"reused\":"+obtained.reused()+
                ",\"source_inventory_retained\":"+(report.sourceInventory!=null)+
                ",\"source_pairs\":"+(report.sourceInventory==null?0:
                    report.sourceInventory.page(0,32).colocatedPairs())+
                ",\"omitted_indirect\":"+(report.sourceInventory==null?0:
                    report.sourceInventory.omittedIndirect())+
                ",\"full_input_sha256\":\""+original.inputSha256()+"\""+
                ",\"import_sha256\":\""+imported+"\""+
                ",\"revision_unchanged\":"+
                    (program.getModificationNumber()==beforeRevision)+
                ",\"checkpoint_exists\":true}";
            Files.writeString(proofs.resolve("ga12-"+phase+".json"),proof+"\n");
            System.out.println("GA12 V2 REAL GHIDRA "+phase+
                " PASS: sourcePairs="+(report.sourceInventory==null?0:2)+
                " reused="+obtained.reused());
        }finally{
            if(program!=null)program.release(consumer);
            project.close();
        }
    }
}
