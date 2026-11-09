package ghidrassist.hardware;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.MessageDigest;
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

    /**
     * Ghidra 12.1.4 CPU32 genuinely emits both synthetic absolute writes
     * as COPY to RAM varnodes, rather than an indirect PcodeOp.STORE.
     * Exercise the exact production memory-effect resolver on the source
     * instruction in EACH independent CodeBrowser JVM.
     */
    private static void verifyRealPcodeMemoryWrites(Program program) {
        var space=program.getAddressFactory().getDefaultAddressSpace();
        for(long[] site:new long[][]{
                {0x20L,0xfffa00L}, {0x30L,0xfffa04L}}) {
            var insn=program.getListing().getInstructionAt(
                space.getAddress(site[0]));
            require(insn!=null,"Real Ghidra Listing memory write missing");
            var ops=insn.getPcode();
            require(ops!=null && ops.length>0,
                "Real Ghidra P-code translation missing");
            int direct=0,indirect=0;
            for(var op:ops) {
                if(op.getOpcode()==ghidra.program.model.pcode.PcodeOp.STORE)
                    indirect++;
                var out=op.getOutput();
                if(out!=null && out.getAddress()!=null &&
                        out.getAddress().isMemoryAddress())
                    direct++;
            }
            require(direct==1 && indirect==0,
                "Expected one real CPU32 COPY-to-RAM memory effect at "+
                Long.toHexString(site[0])+"; direct="+direct+
                " indirect="+indirect+
                " pcode="+java.util.Arrays.toString(ops));
            Long actual=GhidraHardwareFlowService.pcodeStore(insn);
            require(actual!=null && actual==site[1],
                "Real Ghidra direct RAM P-code address mismatch at "+
                Long.toHexString(site[0])+"; target="+actual);
        }
    }

    /**
     * Two genuine CPU32 Listing functions, translated by production code,
     * with source P-code effects, CFG edges and register propagation.
     * This is independent of the deliberately translated 96-node worklist.
     */
    private record RealFlow(long entry,List<HardwareDataflow.Step> steps,
                            HardwareDataflow.Result result) {}
    private static RealFlow realFlow(Program program,long entry,
                                    long[] instructionOffsets,
                                    int expectedWrites) throws Exception {
        var space=program.getAddressFactory().getDefaultAddressSpace();
        var function=program.getFunctionManager().getFunctionAt(
            space.getAddress(entry));
        require(function!=null,"Missing real Ghidra CPU32 function at "+
            Long.toHexString(entry));
        List<HardwareDataflow.Step> steps=new ArrayList<>();
        for(long at:instructionOffsets) {
            var insn=program.getListing().getInstructionAt(space.getAddress(at));
            require(insn!=null && function.getBody().contains(insn.getAddress()),
                "Missing real Ghidra function instruction "+Long.toHexString(at));
            int memoryWrites=GhidraHardwareFlowService.pcodeMemoryWrites(insn);
            if(at!=entry && at!=instructionOffsets[instructionOffsets.length-1]
                    && !"NOP".equalsIgnoreCase(insn.getMnemonicString()))
                require(memoryWrites==1,
                    "Real CPU32 memory effect count mismatch at "+
                    Long.toHexString(at)+": "+memoryWrites);
            steps.add(GhidraHardwareFlowService.translate(insn,function));
        }
        require(steps.size()==instructionOffsets.length,
            "Incomplete translated Ghidra function");
        var result=HardwareDataflow.analyze(entry,steps,TARGETS,128);
        require(!result.truncated && result.snapshots.size()==expectedWrites,
            "Real CPU32 CFG failed to converge with expected STORE sites");
        return new RealFlow(entry,List.copyOf(steps),result);
    }
    private static String verifyRealRegisterAndAliasFlow(Program program,
            Path output,HardwareDurableStageStore.Key key,
            boolean resumedJvm) throws Exception {
        RealFlow indirect=realFlow(program,0x40L,
            new long[]{0x40L,0x46L,0x4aL},1);
        var proven=indirect.result().snapshots.get(0);
        require(proven.indirect && proven.effectiveAddress!=null &&
                proven.effectiveAddress==0xfffa00L &&
                proven.writtenWord!=null && proven.writtenWord==0x40ca,
            "Real CPU32 source A0 constant did not reach indirect SIMCR");
        RealFlow alias=realFlow(program,0x60L,
            new long[]{0x60L,0x66L,0x6aL,0x6eL,0x72L},3);
        var observations=alias.result().snapshots;
        require(observations.get(0).effectiveAddress!=null &&
                observations.get(0).effectiveAddress==0xfffa00L &&
                observations.get(1).effectiveAddress==null &&
                observations.get(2).effectiveAddress!=null &&
                observations.get(2).effectiveAddress==0xfffa00L &&
                observations.get(2).priorUnknownStore,
            "Unknown A1 alias was promoted or failed to poison provenance");
        // A1's unknown write must invalidate tracked peripheral values
        // before the subsequent A0 write, despite the known A0 pointer.
        require(Integer.valueOf(0x4848).equals(
                observations.get(2).knownPeripheralWords.get(0xfffa00L)),
            "Post-alias source must reflect only the last exact SIMCR store");
        // A whole SIMCR word is invalidated by an overlapping byte;
        // only a later complete 16-bit write can restore exact evidence.
        RealFlow overlap=realFlow(program,0x80L,
            new long[]{0x80L,0x86L,0x8aL,0x8eL,0x92L},3);
        var o=overlap.result().snapshots;
        require(Integer.valueOf(0x40ca).equals(
                o.get(0).knownPeripheralWords.get(0xfffa00L)) &&
                o.get(0).writeBits==16,
            "First real full SIMCR word is not proven");
        require(o.get(1).effectiveAddress!=null &&
                o.get(1).effectiveAddress==0xfffa00L &&
                o.get(1).writeBits==8 &&
                !o.get(1).knownPeripheralWords.containsKey(0xfffa00L) &&
                o.get(1).writtenWord==null,
            "Real overlapping byte retained or invented a full SIMCR word");
        require(Integer.valueOf(0x4848).equals(
                o.get(2).knownPeripheralWords.get(0xfffa00L)) &&
                o.get(2).writeBits==16,
            "Real following complete word did not reestablish SIMCR evidence");
        Path dir=output.resolve("ga12-real-pcode-function-stages");
        Files.createDirectories(dir);
        StringBuilder hashes=new StringBuilder();
        for(RealFlow flow:List.of(indirect,alias,overlap)) {
            byte[] serialized=HardwareFunctionResultCodec.encode(flow.result());
            String digest=HardwareDurableStageStore.hash(serialized);
            hashes.append(Long.toHexString(flow.entry())).append(':')
                .append(digest).append(';');
            if(!resumedJvm) {
                require(HardwareDurableFunctionStages.save(dir,key,
                    flow.entry(),128,flow.steps(),TARGETS,flow.result()),
                    "Could not persist real translated Ghidra function CFG");
            }else {
                var loaded=HardwareDurableFunctionStages.load(dir,key,
                    flow.entry(),128,flow.steps(),TARGETS).orElseThrow(
                    ()->new IllegalStateException(
                        "Second JVM rejected real translated CFG stage"));
                require(Arrays.equals(serialized,
                    HardwareFunctionResultCodec.encode(loaded)),
                    "Real P-code translated completed stage drifted after JVM");
                require(HardwareDurableFunctionStages.load(dir,
                    changed(key,"analysis-input"),flow.entry(),128,
                    flow.steps(),TARGETS).isEmpty(),
                    "Edited source accepted real P-code checkpoint");
                require(HardwareDurableFunctionStages.load(dir,
                    changed(key,"profile"),flow.entry(),128,
                    flow.steps(),TARGETS).isEmpty(),
                    "Generic CPU32 reused MC68332 P-code checkpoint");
            }
        }
        return HardwareDurableStageStore.hash(hashes.toString());
    }

    /** Real decoded 22-instruction CPU32 source, not fabricated CFG Steps. */
    private static RealFlow longTranslatedSource(Program program)
            throws Exception {
        long[] pcs=new long[20];
        pcs[0]=0xa0L;
        for(int i=1;i<=17;i++)pcs[i]=0xa4L+2L*i;
        pcs[18]=0xc8L;pcs[19]=0xccL;
        return realFlow(program,0xa0L,pcs,1);
    }

    private static Path realPendingDirectory(Path output) {
        return output.resolve("ga12-real-translated-pending-stages");
    }

    /** First JVM stops after exactly one coherent fixed-point slice. */
    private static int interruptRealTranslatedSource(Program program,
            Path output,HardwareDurableStageStore.Key key) throws Exception {
        RealFlow source=longTranslatedSource(program);
        var slice=HardwareDataflow.analyzeSlice(source.entry(),
            source.steps(),TARGETS,128,null,
            HardwarePartialStageRunner.ITERATIONS_PER_SLICE);
        require(slice.complete()==null && slice.progress()!=null &&
                slice.progress().iterations()==
                    HardwarePartialStageRunner.ITERATIONS_PER_SLICE &&
                !slice.progress().pending().isEmpty(),
            "Real translated CPU32 worklist did not stop mid-function");
        Path dir=realPendingDirectory(output);
        Files.createDirectories(dir);
        require(HardwareDurableFunctionStages.saveProgress(dir,key,
                source.entry(),128,source.steps(),TARGETS,slice.progress()),
            "Real translated partial source was not saved to disk");
        require(HardwareDurableFunctionStages.load(dir,key,
                source.entry(),128,source.steps(),TARGETS).isEmpty(),
            "Incomplete real translated source became Review evidence");
        return slice.progress().iterations();
    }

    /** Second JVM must resume typed actual Listing/P-code CFG, not cold run. */
    private static void resumeRealTranslatedSource(Program program,
            Path output,HardwareDurableStageStore.Key key,int iterations)
            throws Exception {
        RealFlow source=longTranslatedSource(program);
        Path dir=realPendingDirectory(output);
        var pending=HardwareDurableFunctionStages.loadProgress(dir,key,
            source.entry(),128,source.steps(),TARGETS).orElseThrow(
                ()->new IllegalStateException(
                    "Missing genuine translated Ghidra partial stage"));
        require(pending.iterations()==iterations &&
                HardwareDurableFunctionStages.load(dir,key,
                    source.entry(),128,source.steps(),TARGETS).isEmpty(),
            "Unfinished source checkpoint was published as complete");
        require(HardwareDurableFunctionStages.loadProgress(dir,
                changed(key,"analysis-input"),source.entry(),128,
                source.steps(),TARGETS).isEmpty(),
            "Edited Ghidra source was allowed to resume real worklist");
        require(HardwareDurableFunctionStages.loadProgress(dir,
                changed(key,"profile"),source.entry(),128,
                source.steps(),TARGETS).isEmpty(),
            "Changed MCU profile was allowed to resume worklist");
        require(HardwareDurableFunctionStages.loadProgress(dir,key,
                source.entry(),129,source.steps(),TARGETS).isEmpty(),
            "Changed solver budget was allowed to resume real worklist");
        var resumed=HardwarePartialStageRunner.analyze(source.entry(),
            source.steps(),TARGETS,128,dir,key,TaskMonitor.DUMMY,()->true);
        require(resumed.restoredPartial() && !resumed.result().truncated &&
                Arrays.equals(HardwareFunctionResultCodec.encode(
                    source.result()),
                    HardwareFunctionResultCodec.encode(resumed.result())),
            "Real translated CPU32 partial CFG differs from cold fixed point");
        require(resumed.result().snapshots.size()==1 &&
                resumed.result().snapshots.get(0).effectiveAddress==0xfffa00L &&
                Integer.valueOf(0x4848).equals(
                    resumed.result().snapshots.get(0).writtenWord),
            "Real 22-instruction CPU32 resume lost final SIMCR source");
        require(HardwareDurableFunctionStages.save(dir,key,source.entry(),
                128,source.steps(),TARGETS,resumed.result()) &&
                HardwareDurableFunctionStages.loadProgress(dir,key,
                    source.entry(),128,source.steps(),TARGETS).isEmpty(),
            "Real translated fixed point was not committed atomically");
    }

    /** First genuine Ghidra process deliberately stops just after a saved slice. */
    public static void interruptInFirstJvm(Program program,Path output)
            throws Exception {
        Path directory=store(output);
        Files.createDirectories(directory);
        // A genuine cross-process identity requires the Ghidra Listing
        // baseline to be committed to the ISOLATED synthetic project.
        // Otherwise the next JVM would legitimately see only imported
        // undefined bytes and must reject the stale worklist.
        require(program.getListing().getInstructionAt(
            program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(0x20))!=null,
            "First synthetic CodeBrowser has no Listing baseline to persist");
        if(program.isChanged())
            program.save("GA-12 isolated synthetic Listing identity before CFG interruption",
                TaskMonitor.DUMMY);
        verifyRealPcodeMemoryWrites(program);
        var key=identity(program);
        String realFlowDigest=verifyRealRegisterAndAliasFlow(
            program,output,key,false);
        int realPendingIterations=interruptRealTranslatedSource(
            program,output,key);
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
        report.addProperty("real_pcode_memory_effects_verified",true);
        report.addProperty("real_translated_flow_sha256",realFlowDigest);
        report.addProperty("real_indirect_mmio_proven",true);
        report.addProperty("real_byte_overlap_invalidated",true);
        report.addProperty("real_translated_partial_iterations",
            realPendingIterations);
        report.addProperty("real_translated_partial_not_review",true);
        report.addProperty("real_unknown_alias_poisoned",true);
        report.addProperty("deliberately_cancelled",cancelled);
        report.addProperty("partial_worklist_saved",true);
        report.addProperty("partial_not_review_evidence",true);
        report.addProperty("intermediate_iterations",partial.iterations());
        report.addProperty("import_sha256",key.importedSha256());
        report.addProperty("full_input_sha256",key.inputSha256());
        report.addProperty("engine_sha256",key.analyzerSha256());
        Files.writeString(receipt(output,"before-restart"),JSON.toJson(report));
    }

    /**
     * Exercise damaged on-disk partial stages in disposable cache copies.
     * A corrupt worklist must never become complete evidence or prevent a
     * fresh bounded analysis; the original checkpoint remains untouched.
     */
    private static int damagedWorklistFallback(Path directory,Path output,
            HardwareDurableStageStore.Key key,
            List<HardwareDataflow.Step> steps) throws Exception {
        List<Path> files;
        try(var stream=Files.list(directory)) {
            files=stream.filter(p->p.getFileName().toString().endsWith(".chk"))
                .toList();
        }
        require(files.size()==1,"Expected exactly one isolated partial CFG slot");
        byte[] original=Files.readAllBytes(files.get(0));
        require(original.length>64,"Saved partial checkpoint unexpectedly short");
        byte[] cold=HardwareFunctionResultCodec.encode(
            HardwareDataflow.analyze(ENTRY,steps,TARGETS,BUDGET));
        int checked=0;
        for(String fault:List.of("digest","truncated","oversized")) {
            Path copy=Files.createDirectories(output.resolve(
                "ga12-damaged-stage-"+fault));
            byte[] damaged;
            if("digest".equals(fault)) {
                damaged=original.clone();
                damaged[damaged.length-1]^=0x01;
            } else if("truncated".equals(fault)) {
                damaged=Arrays.copyOf(original,original.length-17);
            } else {
                damaged=new byte[HardwareDurableStageStore.MAX_PAYLOAD_BYTES+4097];
            }
            Files.write(copy.resolve(files.get(0).getFileName()),damaged);
            require(HardwareDurableFunctionStages.loadProgress(copy,
                    key,ENTRY,BUDGET,steps,TARGETS).isEmpty(),
                "Damaged partial worklist was accepted: "+fault);
            require(HardwareDurableFunctionStages.load(copy,
                    key,ENTRY,BUDGET,steps,TARGETS).isEmpty(),
                "Damaged partial worklist was promoted to completed evidence: "+fault);
            var result=HardwarePartialStageRunner.analyze(
                ENTRY,steps,TARGETS,BUDGET,copy,key,TaskMonitor.DUMMY,()->true);
            require(!result.restoredPartial() && !result.result().truncated &&
                    Arrays.equals(cold,
                        HardwareFunctionResultCodec.encode(result.result())),
                "Damaged stage failed closed-start cold-equivalence: "+fault);
            checked++;
        }
        return checked;
    }

    /** Construct malformed typed worklists without relying on model output. */
    private static byte[] invalidTypedProgress(String fault) throws Exception {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        try(DataOutputStream out=new DataOutputStream(bytes)) {
            out.writeUTF("wrong-schema".equals(fault)
                ?"GA12-UNKNOWN-PROGRESS":"GA12-CFG-PROGRESS-1");
            out.writeLong("wrong-entry".equals(fault)?ENTRY+2:ENTRY);
            out.writeInt("wrong-budget".equals(fault)?BUDGET+1:BUDGET);
            out.writeInt("past-budget".equals(fault)?BUDGET:1);
            out.writeInt("alien-node".equals(fault)?2:1);
            out.writeLong("wrong-entry".equals(fault)?ENTRY+2:ENTRY);
            out.writeInt("bad-register".equals(fault)?1:0);
            if("bad-register".equals(fault)) {
                out.writeUTF("R0");
                out.writeLong(0xfffa00L);
            }
            out.writeInt("bad-mmio".equals(fault)?1:0);
            if("bad-mmio".equals(fault)) {
                out.writeLong(0x1000000L);
                out.writeInt(1);
            }
            out.writeBoolean(false);
            out.writeByte(0);
            out.writeByte(0);
            out.writeBoolean(false);
            out.writeBoolean(false);
            if("alien-node".equals(fault)) {
                // Valid additional state cell, but not a real translated
                // CFG instruction. It must be rejected at the cache boundary.
                out.writeLong(0xdeadbeefL);
                out.writeInt(0);
                out.writeInt(0);
                out.writeBoolean(false);
                out.writeByte(0);
                out.writeByte(0);
                out.writeBoolean(false);
                out.writeBoolean(false);
            }
            out.writeInt("duplicate-pending".equals(fault)?2:1);
            out.writeLong("unknown-pending".equals(fault) ||
                "wrong-entry".equals(fault)?ENTRY+2:ENTRY);
            if("duplicate-pending".equals(fault))out.writeLong(ENTRY);
        }
        return bytes.toByteArray();
    }

    /**
     * Replace only the typed payload of a disposable first-JVM stage and
     * recompute the outer SHA-256. This exercises schema/semantic validation
     * rather than just checksum failure. It is NOT attacker authentication.
     */
    private static byte[] validDigestEnvelope(byte[] original,byte[] payload)
            throws Exception {
        ByteArrayInputStream raw=new ByteArrayInputStream(original);
        DataInputStream input=new DataInputStream(raw);
        require(input.readInt()==0x47413132,"Expected GA12 durable envelope");
        for(int i=0;i<6;i++)input.readUTF();
        input.readBoolean();
        int declared=input.readInt();
        require(declared>0 && declared==raw.available()-32,
            "Original checkpoint envelope inconsistent");
        int prefixSize=original.length-raw.available()-4;
        ByteArrayOutputStream buffer=new ByteArrayOutputStream();
        try(DataOutputStream out=new DataOutputStream(buffer)) {
            out.write(original,0,prefixSize);
            out.writeInt(payload.length);
            out.write(payload);
        }
        byte[] body=buffer.toByteArray();
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(body);
        ByteArrayOutputStream result=new ByteArrayOutputStream();
        result.write(body);
        result.write(digest);
        return result.toByteArray();
    }

    private static int malformedTypedFallback(Path directory,Path output,
            HardwareDurableStageStore.Key key,
            List<HardwareDataflow.Step> steps) throws Exception {
        List<Path> originalFiles;
        try(var stream=Files.list(directory)) {
            originalFiles=stream.filter(p->p.getFileName().toString()
                .endsWith(".chk")).toList();
        }
        require(originalFiles.size()==1,"Missing real saved worklist");
        byte[] original=Files.readAllBytes(originalFiles.get(0));
        byte[] cold=HardwareFunctionResultCodec.encode(
            HardwareDataflow.analyze(ENTRY,steps,TARGETS,BUDGET));
        int tested=0;
        for(String fault:List.of("wrong-schema","past-budget",
                "bad-register","bad-mmio","unknown-pending",
                "duplicate-pending","wrong-entry","wrong-budget",
                "alien-node")) {
            Path copy=Files.createDirectories(output.resolve(
                "ga12-typed-invalid-"+fault));
            byte[] payload=invalidTypedProgress(fault);
            // Entry/budget are individually well-formed typed progress
            // records: they must be refused by the caller-bound disk cache.
            boolean contextMismatch="wrong-entry".equals(fault) ||
                "wrong-budget".equals(fault) || "alien-node".equals(fault);
            require(HardwareFunctionProgressCodec.decode(payload).isPresent()
                    ==contextMismatch,
                "Unexpected standalone progress decode: "+fault);
            Files.write(copy.resolve(originalFiles.get(0).getFileName()),
                validDigestEnvelope(original,payload));
            require(HardwareDurableFunctionStages.loadProgress(copy,key,
                    ENTRY,BUDGET,steps,TARGETS).isEmpty(),
                "Valid-digest malformed progress accepted: "+fault);
            require(HardwareDurableFunctionStages.load(copy,key,
                    ENTRY,BUDGET,steps,TARGETS).isEmpty(),
                "Malformed progress misread as finished source: "+fault);
            var recomputed=HardwarePartialStageRunner.analyze(
                ENTRY,steps,TARGETS,BUDGET,copy,key,TaskMonitor.DUMMY,()->true);
            require(!recomputed.restoredPartial() &&
                    !recomputed.result().truncated &&
                    Arrays.equals(cold,HardwareFunctionResultCodec.encode(
                        recomputed.result())),
                "Invalid typed progress did not cold-recover: "+fault);
            tested++;
        }
        return tested;
    }

    /** Second genuine Ghidra process restores and completes the exact worklist. */
    public static void resumeInSecondJvm(Program program,Path output)
            throws Exception {
        Path directory=store(output);
        var first=JSON.fromJson(Files.readString(
            receipt(output,"before-restart")),JsonObject.class);
        verifyRealPcodeMemoryWrites(program);
        require(first.get("real_pcode_memory_effects_verified").getAsBoolean(),
            "First JVM lacked real P-code evidence");
        var key=identity(program);
        String realFlowDigest=verifyRealRegisterAndAliasFlow(
            program,output,key,true);
        require(realFlowDigest.equals(
            first.get("real_translated_flow_sha256").getAsString()),
            "Real CPU32 A0 flow and unknown alias changed across JVMs");
        resumeRealTranslatedSource(program,output,key,
            first.get("real_translated_partial_iterations").getAsInt());
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

        int malformedFallbacks=malformedTypedFallback(
            directory,output,key,steps);
        require(malformedFallbacks==9,"Missing malformed/context-invalid CFG cases");
        int corruptFallbacks=damagedWorklistFallback(
            directory,output,key,steps);
        require(corruptFallbacks==3,"Missing damaged worklist cases");

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
        report.addProperty("real_translated_flow_sha256",realFlowDigest);
        report.addProperty("real_indirect_checkpoint_restored",true);
        report.addProperty("real_alias_checkpoint_restored",true);
        report.addProperty("real_byte_overlap_checkpoint_restored",true);
        report.addProperty("real_translated_partial_restored",true);
        report.addProperty("real_translated_cold_byte_equal",true);
        report.addProperty("real_pcode_memory_effects_verified",true);
        report.addProperty("source_identity_matches",true);
        report.addProperty("partial_restored",resumed.restoredPartial());
        report.addProperty("cold_result_exact_match",true);
        report.addProperty("indirect_mmio_static_evidence_retained",true);
        report.addProperty("completed_stage_persisted",true);
        report.addProperty("damaged_partial_fallbacks",corruptFallbacks);
        report.addProperty("damaged_partial_never_complete",true);
        report.addProperty("malformed_typed_fallbacks",malformedFallbacks);
        report.addProperty("malformed_valid_digest_refused",true);
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
