package ghidrassist.hardware;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static ghidrassist.hardware.HardwareDataflow.Kind.*;

/**
 * GA-12 actual two-JVM Ghidra CodeBrowser test.
 *
 * Real Program bytes and Listing bind a synthetic translated CFG input; the
 * 96-node worklist intentionally forces multiple fixed-point slices. This is
 * NOT a claim that 96 instructions exist at these synthetic CFG node addresses,
 * and no Ghidra Listing, hardware or project is modified by this test.
 */
public final class Ga12InterruptedCfgRestartFixture {
    private Ga12InterruptedCfgRestartFixture(){}
    private static final Gson JSON=new Gson();
    private static final long ENTRY=0x100L;
    private static final int BUDGET=512;
    private static final Set<Long> TARGETS=Set.of(0xfffa00L);
    private static final String ANALYZER_TAG="GA12-SYNTHETIC-CFG-RESTART-V1";

    private static void require(boolean valid,String problem) {
        if(!valid)throw new IllegalStateException(problem);
    }
    private static List<HardwareDataflow.Step> graph() {
        List<HardwareDataflow.Step> steps=new ArrayList<>();
        for(int i=0;i<96;i++) {
            long address=ENTRY+2L*i;
            List<Long> next=i==95?List.of():List.of(address+2);
            if(i==0)
                steps.add(new HardwareDataflow.Step(address,SET_POINTER,
                    "A0",0xfffa00L,0,null,0,next,"synthetic MOVEA"));
            else if(i==95)
                steps.add(new HardwareDataflow.Step(address,STORE_INDIRECT,
                    "A0",0,0,0x40ca,16,next,"synthetic MOVE.W"));
            else
                steps.add(new HardwareDataflow.Step(address,OTHER,
                    null,0,0,null,0,next,"synthetic NOP"));
        }
        return List.copyOf(steps);
    }
    private static String hex(Program program) {
        return program.getExecutableSHA256();
    }
    private static HardwareDurableStageStore.Key identity(Program program)
            throws ghidra.program.model.mem.MemoryAccessException {
        require(program!=null && program.getDomainFile()!=null,
            "Actual Ghidra Program with project identity required");
        String imported=hex(program);
        require(imported!=null && imported.matches("(?i)[a-f0-9]{64}"),
            "Actual Ghidra import SHA unavailable");
        byte[] programBytes=new byte[256];
        int count=program.getMemory().getBytes(
            program.getAddressFactory().getDefaultAddressSpace().getAddress(0),
            programBytes);
        require(count==programBytes.length,
            "Whole disposable synthetic input must be readable");
        var instruction=program.getListing().getInstructionAt(
            program.getAddressFactory().getDefaultAddressSpace().getAddress(0x20));
        require(instruction!=null,"Real synthetic Listing instruction missing");
        String listing=instruction.toString();
        String language=program.getLanguage().getLanguageID().toString();
        String projectId=HardwareDurableStageStore.hash(
            "GA12-REAL-GHIDRA-PROJECT|" +
            program.getDomainFile().getPathname() + "|" + imported);
        String byteHash=HardwareDurableStageStore.hash(programBytes);
        String inputHash=HardwareDurableStageStore.hash(
            "GA12-REAL-GHIDRA-FULL-256-BYTE-INPUT|" + byteHash +
            "|" + language + "|" + listing);
        String engine=HardwareDurableStageStore.hash(ANALYZER_TAG);
        return new HardwareDurableStageStore.Key(
            projectId,imported.toLowerCase(java.util.Locale.ROOT),
            inputHash,engine,language,true);
    }
    private static HardwareDurableStageStore.Key changed(
            HardwareDurableStageStore.Key key,String which) {
        return switch(which) {
            case "analysis-input" -> new HardwareDurableStageStore.Key(
                key.programIdSha256(),key.importedSha256(),
                HardwareDurableStageStore.hash("different actual Ghidra Listing"),
                key.analyzerSha256(),key.language(),key.mc68332());
            case "analyzer" -> new HardwareDurableStageStore.Key(
                key.programIdSha256(),key.importedSha256(),key.inputSha256(),
                HardwareDurableStageStore.hash("upgraded GA12 analyzer implementation"),
                key.language(),key.mc68332());
            case "profile" -> new HardwareDurableStageStore.Key(
                key.programIdSha256(),key.importedSha256(),key.inputSha256(),
                key.analyzerSha256(),key.language(),false);
            case "language" -> new HardwareDurableStageStore.Key(
                key.programIdSha256(),key.importedSha256(),key.inputSha256(),
                key.analyzerSha256(),"other language profile",key.mc68332());
            default -> throw new IllegalArgumentException(which);
        };
    }
    private static Path store(Path output) {
        return output.resolve("ga12-interrupted-cfg-cache");
    }
    private static Path receipt(Path output,String suffix) {
        return output.resolve("ga12-interrupted-cfg-"+suffix+".json");
    }

    /** First genuine Ghidra process deliberately stops just after a saved slice. */
    public static void interruptInFirstJvm(Program program,Path output)
            throws Exception {
        Path directory=store(output);
        Files.createDirectories(directory);
        var key=identity(program);
        var steps=graph();
        require(HardwareDurableFunctionStages.loadProgress(directory,key,
            ENTRY,BUDGET,steps,TARGETS).isEmpty(),"Unexpected saved worklist on first JVM");
        require(HardwareDurableFunctionStages.load(directory,key,
            ENTRY,BUDGET,steps,TARGETS).isEmpty(),"Unexpected completed source");
        AtomicInteger checks=new AtomicInteger();
        boolean cancelled=false;
        try {
            HardwarePartialStageRunner.analyze(ENTRY,steps,TARGETS,
                BUDGET,directory,key,TaskMonitor.DUMMY,
                ()->checks.incrementAndGet()<=2);
        } catch(CancelledException expected) {
            cancelled=true;
        }
        require(cancelled,"First JVM did not interrupt incomplete fixed point");
        var partial=HardwareDurableFunctionStages.loadProgress(directory,
            key,ENTRY,BUDGET,steps,TARGETS).orElseThrow(
                ()->new IllegalStateException("No intermediate worklist on disk"));
        require(partial.iterations()>0 && !partial.pending().isEmpty(),
            "Unfinished worklist missing on first JVM");
        require(HardwareDurableFunctionStages.load(directory,key,
            ENTRY,BUDGET,steps,TARGETS).isEmpty(),
            "Partial CFG illegally published as completed evidence");
        JsonObject report=new JsonObject();
        report.addProperty("schema",1);
        report.addProperty("real_ghidra_program",true);
        report.addProperty("real_first_jvm",true);
        report.addProperty("deliberately_cancelled",cancelled);
        report.addProperty("partial_worklist_saved",true);
        report.addProperty("partial_not_review_evidence",true);
        report.addProperty("intermediate_iterations",partial.iterations());
        report.addProperty("import_sha256",key.importedSha256());
        report.addProperty("full_input_sha256",key.inputSha256());
        report.addProperty("engine_sha256",key.analyzerSha256());
        Files.writeString(receipt(output,"before-restart"),JSON.toJson(report));
    }

    /** Second genuine Ghidra process restores and completes the exact worklist. */
    public static void resumeInSecondJvm(Program program,Path output)
            throws Exception {
        Path directory=store(output);
        var first=JSON.fromJson(Files.readString(
            receipt(output,"before-restart")),JsonObject.class);
        var key=identity(program);
        var steps=graph();
        require(key.importedSha256().equals(first.get("import_sha256").getAsString())
                && key.inputSha256().equals(first.get("full_input_sha256").getAsString())
                && key.analyzerSha256().equals(first.get("engine_sha256").getAsString()),
            "Ghidra input identity drifted across real JVM restart");
        var pending=HardwareDurableFunctionStages.loadProgress(directory,
            key,ENTRY,BUDGET,steps,TARGETS).orElseThrow(
                ()->new IllegalStateException("Second JVM did not restore worklist"));
        require(pending.iterations()==first.get("intermediate_iterations").getAsInt(),
            "Restored worklist iteration counter differs from first JVM");
        for(String dimension:List.of("analysis-input","analyzer","profile","language")) {
            var different=changed(key,dimension);
            require(HardwareDurableFunctionStages.loadProgress(directory,
                different,ENTRY,BUDGET,steps,TARGETS).isEmpty(),
                "Stale intermediate CFG accepted after changed "+dimension);
        }
        var edited=new ArrayList<>(steps);
        edited.set(0,new HardwareDataflow.Step(ENTRY,SET_POINTER,"A0",
            0xfffa02L,0,null,0,List.of(ENTRY+2),"modified synthetic CFG"));
        require(HardwareDurableFunctionStages.loadProgress(directory,key,
            ENTRY,BUDGET,edited,TARGETS).isEmpty(),
            "Mutated translated CFG reused an incompatible worklist");
        require(HardwareDurableFunctionStages.loadProgress(directory,key,
            ENTRY,BUDGET+1,steps,TARGETS).isEmpty(),
            "Changed fixed-point budget reused a worklist");

        var resumed=HardwarePartialStageRunner.analyze(ENTRY,steps,TARGETS,
            BUDGET,directory,key,TaskMonitor.DUMMY,()->true);
        require(resumed.restoredPartial() && !resumed.result().truncated,
            "Second Ghidra JVM did not resume and finish partial CFG");
        var cold=HardwareDataflow.analyze(ENTRY,steps,TARGETS,BUDGET);
        require(!cold.truncated && Arrays.equals(
            HardwareFunctionResultCodec.encode(resumed.result()),
            HardwareFunctionResultCodec.encode(cold)),
            "Resumed fixed point differs from a full cold analysis");
        require(resumed.result().snapshots.size()==1 &&
                resumed.result().snapshots.get(0).effectiveAddress==0xfffa00L,
            "Real-restart CFG lost indirect synthetic MMIO write");
        require(HardwareDurableFunctionStages.save(directory,key,ENTRY,
            BUDGET,steps,TARGETS,resumed.result()),
            "Completed fixed point could not be durably committed");
        require(HardwareDurableFunctionStages.loadProgress(directory,
            key,ENTRY,BUDGET,steps,TARGETS).isEmpty(),
            "Completed checkpoint still masquerades as pending worklist");
        require(HardwareDurableFunctionStages.load(directory,key,
            ENTRY,BUDGET,steps,TARGETS).isPresent(),
            "Completed stage unavailable after independent restart");
        for(String dimension:List.of("analysis-input","analyzer","profile","language")) {
            require(HardwareDurableFunctionStages.load(directory,
                changed(key,dimension),ENTRY,BUDGET,steps,TARGETS).isEmpty(),
                "Completed stale stage reusable under changed "+dimension);
        }
        JsonObject report=new JsonObject();
        report.addProperty("schema",1);
        report.addProperty("real_ghidra_program_reopened",true);
        report.addProperty("real_second_jvm",true);
        report.addProperty("source_identity_matches",true);
        report.addProperty("partial_restored",resumed.restoredPartial());
        report.addProperty("cold_result_exact_match",true);
        report.addProperty("indirect_mmio_static_evidence_retained",true);
        report.addProperty("completed_stage_persisted",true);
        report.addProperty("changed_input_refused",true);
        report.addProperty("changed_analyzer_refused",true);
        report.addProperty("changed_profile_refused",true);
        report.addProperty("changed_language_refused",true);
        report.addProperty("changed_cfg_refused",true);
        report.addProperty("changed_budget_refused",true);
        report.addProperty("no_production_apply",true);
        report.addProperty("import_sha256",key.importedSha256());
        report.addProperty("full_input_sha256",key.inputSha256());
        Files.writeString(receipt(output,"after-restart"),JSON.toJson(report));
    }
}
