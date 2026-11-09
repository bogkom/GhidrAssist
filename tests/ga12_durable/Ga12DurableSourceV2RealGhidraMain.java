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
import ghidrassist.agent.react.AgenticReviewProgramBinding;
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
        var first=source.page(0,1);
        var second=source.page(1,1);
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
    /**
     * Intentionally reseal a corrupted V2 witness under the exact valid
     * synthetic disk key. SHA and full-input identity still match: decoder
     * semantic validation must refuse this as a cache hit.
     */
    private static void installMalformedSource(Path cache,
            HardwareDurableStageStore.Key key)throws Exception {
        byte[] stage=HardwareDurableStageStore.load(cache,key).orElseThrow();
        require(HardwareDurableCfgReport.decode(stage).orElseThrow()
            .sourceInventory()!=null,"corruption test requires V2 inventory");
        byte[] witness=new byte[]{
            0,0,0,0,0,0,1,0x30,
            0,0,0,0,0,0,1,0x38,
            0,0,0,0,0,0,1,(byte)0x80};
        int at=-1;
        outer:for(int i=0;i<=stage.length-witness.length;i++){
            for(int j=0;j<witness.length;j++)
                if(stage[i+j]!=witness[j])continue outer;
            at=i;break;
        }
        require(at>=0,"exact serialized computed JSR witness");
        stage[at+15]=(byte)0x39;
        require(HardwareDurableCfgReport.decode(stage).isEmpty(),
            "odd JSR must fail closed before disk write");
        HardwareDurableStageStore.save(cache,key,stage);
        require(Arrays.equals(HardwareDurableStageStore.load(cache,key)
                .orElseThrow(),stage),
            "valid outer SHA/store digest of semantically malformed V2");
    }
    /**
     * Two independently cross-checked RESET sets are in the V2 format.
     * A checkpoint with an otherwise valid disk fingerprint and digest
     * must NOT replace the live report with inconsistent source provenance.
     */
    private static void installResetSetMismatch(Path cache,
            HardwareDurableStageStore.Key key)throws Exception {
        byte[] stage=HardwareDurableStageStore.load(cache,key).orElseThrow();
        var snapshot=HardwareDurableCfgReport.decode(stage).orElseThrow();
        require(snapshot.sourceInventory()!=null &&
            !snapshot.sourceInventory().resetVisited().isEmpty(),
            "V2 mismatch fixture has RESET sources");
        // Last address of the sorted binary source RESET set, not the CFG
        // list. XOR bit 1 preserves CPU32 alignment and length bounds.
        stage[stage.length-1]^=0x02;
        require(HardwareDurableCfgReport.decode(stage).isEmpty(),
            "different V2 RESET source subset fails semantic validation");
        HardwareDurableStageStore.save(cache,key,stage);
        require(Arrays.equals(HardwareDurableStageStore.load(cache,key)
                .orElseThrow(),stage),"valid rewrapped mismatched RESET checkpoint");
    }

    /**
     * Incomplete CFG metadata cannot be promoted by retaining otherwise
     * valid JSR/MOVEC source rows or an exact-input disk checksum.
     */
    private static void installIncompleteCfg(Path cache,
            HardwareDurableStageStore.Key key)throws Exception {
        var stage=HardwareDurableStageStore.load(cache,key).orElseThrow();
        var original=HardwareDurableCfgReport.decode(stage).orElseThrow();
        require(HardwareDurableCfgReport.eligibleForCompletedRestore(original) &&
            original.sourceInventory()!=null,
            "incomplete fixture needs an eligible full CFG and V2 sources");
        var incomplete=new HardwareDurableCfgReport.Snapshot(
            original.markdown(),original.csv(),original.functions(),
            original.indirect(),original.vbr(),original.unresolved(),
            original.visited(),true,
            original.resetRecognized(),original.resetIncomplete(),
            false,original.cfgOmitted()+1,original.pointersOmitted(),
            original.sites(),original.roles(),original.resetFunctions(),
            original.sourceInventory());
        require(!HardwareDurableCfgReport.eligibleForCompletedRestore(incomplete)
            && !HardwareDurableCfgReport.eligibleForCompleteSourceInventory(incomplete),
            "incomplete source/CFG checkpoint has no complete-restore privilege");
        var bytes=HardwareDurableCfgReport.encode(incomplete);
        require(HardwareDurableCfgReport.decode(bytes).isPresent(),
            "incomplete typed V2 is format-valid, NOT completed");
        HardwareDurableStageStore.save(cache,key,bytes);
        require(Arrays.equals(HardwareDurableStageStore.load(cache,key)
                .orElseThrow(),bytes),
            "validly checksummed but incomplete V2 must remain untrusted");
    }
    private static final String REVIEW_OBJECTIVE=
        "Independently inspect saved synthetic CPU32 source observations";
    private static void createSyntheticReviewSource(Path file,Program program)
            throws Exception {
        // Synthetic retained data, NOT an LLM run or an approved plan.
        var gson=new com.google.gson.GsonBuilder().disableHtmlEscaping().create();
        var payload=new com.google.gson.JsonObject();
        payload.addProperty("accepted_count",1);
        payload.addProperty("complete",true);
        payload.addProperty("evicted_count",0);
        payload.addProperty("findings_revision",1);
        payload.addProperty("import_sha256",program.getExecutableSHA256());
        payload.addProperty("kind","ghidrassist-agentic-retained-evidence");
        payload.addProperty("program_revision",program.getModificationNumber());
        payload.addProperty("retained_count",1);
        var rows=new com.google.gson.JsonArray();
        var row=new com.google.gson.JsonObject();
        row.addProperty("evidence","synthetic source only 0x00000138");
        row.addProperty("fact","Static computed JSR candidate is not execution");
        row.addProperty("relevance",1);
        row.addProperty("timestamp",1);
        row.addProperty("toolUsed","synthetic-listing");
        rows.add(row);
        payload.add("rows",rows);
        payload.addProperty("run","GA12-NO-LLM-SYNTHETIC-RUN");
        payload.addProperty("schema",1);
        payload.addProperty("source_incomplete",false);
        payload.addProperty("state","SUCCESS");
        var envelope=new com.google.gson.JsonObject();
        envelope.add("payload",payload);
        envelope.addProperty("payload_sha256",
            HardwareDurableStageStore.hash(gson.toJson(payload)));
        Files.writeString(file,gson.toJson(envelope),
            java.nio.file.StandardOpenOption.CREATE_NEW);
    }
    public static void main(String[] args)throws Exception {
        require(args.length==5,"ghidra,project,proof,cache,phase");
        String phase=args[4];
        require(phase.equals("source-write")||phase.equals("source-read")||
            phase.equals("source-edit")||phase.equals("source-v1")||
            phase.equals("source-corrupt")||phase.equals("source-profile")||
            phase.equals("source-mismatch")||phase.equals("source-incomplete")||
            phase.equals("source-name"),
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
            Path reviewSource=proofs.resolve("ga12-synthetic-agentic-review-source.json");
            Path reviewBinding=proofs.resolve("ga12-review-program-binding.json");
            if(phase.equals("source-write")) {
                createSyntheticReviewSource(reviewSource,program);
                AgenticReviewProgramBinding.save(reviewSource,reviewBinding,
                    program,REVIEW_OBJECTIVE,true,TaskMonitor.DUMMY);
                require(Files.isRegularFile(reviewBinding) &&
                    Files.getPosixFilePermissions(reviewBinding).contains(
                        java.nio.file.attribute.PosixFilePermission.OWNER_READ),
                    "create private no-overwrite Review full-input binding");
            }
            if(phase.equals("source-name")) {
                int renameTx=program.startTransaction(
                    "GA12 SYNTHETIC FUNCTION RENAME; NO USER PROGRAM");
                try {
                    var function=program.getFunctionManager().getFunctionAt(
                        program.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(0x130));
                    function.setName("GA12_RENAMED_SOURCE_130",
                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                }finally{program.endTransaction(renameTx,true);}
            }
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
            var actual=HardwareGhidraInputFingerprint.capture(
                program,TaskMonitor.DUMMY,selected).orElseThrow();
            boolean bindingRefused=false;
            try {
                var historical=AgenticReviewProgramBinding.load(
                    reviewSource,reviewBinding,program,selected,TaskMonitor.DUMMY);
                require(historical.toReviewQuery().contains(REVIEW_OBJECTIVE) &&
                    historical.toReviewQuery().contains(
                        "Untrusted historical observations"),
                    "new Review contains only untrusted historical data");
            }catch(IllegalArgumentException denied){
                bindingRefused=true;
            }
            boolean expectBindingRefusal=phase.equals("source-edit")||
                phase.equals("source-name")||phase.equals("source-profile");
            require(bindingRefused==expectBindingRefusal,
                "Full Program Review binding mismatch for "+phase);

            if(phase.equals("source-edit"))
                require(!actual.inputSha256().equals(original.inputSha256()),
                    "edited bytes must change exact effective fingerprint");
            if(phase.equals("source-name"))
                require(!actual.inputSha256().equals(original.inputSha256()),
                    "renamed function must modify full Program fingerprint");
            if(phase.equals("source-profile"))
                require(!actual.mc68332() && original.mc68332() &&
                    !actual.equals(original),
                    "generic CPU32 has a different full checkpoint key profile");
            if(phase.equals("source-mismatch"))
                installResetSetMismatch(cache,original);
            if(phase.equals("source-incomplete"))
                installIncompleteCfg(cache,original);
            if(phase.equals("source-v1"))
                installLegacyV1(cache,original);
            if(phase.equals("source-corrupt"))
                installMalformedSource(cache,original);
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
            require(!HardwareDurableCfgReport.eligibleForCompleteSourceInventory(
                new HardwareDurableCfgReport.Snapshot(
                    report.markdown,report.configurationEvidenceCsv,
                    report.functions,report.indirect,report.vbr,
                    report.unresolved,report.visited,report.limited,
                    report.resetCandidateRecognized,report.resetGraphIncomplete,
                    report.cfgReviewComplete,report.cfgSitesOmitted,
                    report.pointerSitesOmitted,
                    java.util.List.of(),java.util.List.of(),
                    new java.util.ArrayList<>(report.resetCandidateFunctions),
                    report.sourceInventory)),
                "Unknown/omitted synthetic JSR witnesses must remain incomplete");
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
                ",\"effective_input_sha256\":\""+actual.inputSha256()+"\""+
                ",\"selected_mc68332\":"+selected+
                ",\"review_binding_refused\":"+bindingRefused+
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
