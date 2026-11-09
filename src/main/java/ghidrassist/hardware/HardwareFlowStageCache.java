package ghidrassist.hardware;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * Exact-program, revision-scoped completed CFG stage cache.
 * Weak keys prevent keeping closed Ghidra projects alive. Values contain
 * only report data and primitive revision metadata (no Program references).
 */
public final class HardwareFlowStageCache {
    private HardwareFlowStageCache(){}
    public record Result(GhidraHardwareFlowService.Report report,boolean reused) {}
    private static final Map<Program,HardwareStageCheckpoint<GhidraHardwareFlowService.Report>>
        COMPLETED=new WeakHashMap<>();
    private static final int MAX_REPORT_CHARS=1_000_000;
    private static final HardwareStageEpochs<Program> EPOCHS=new HardwareStageEpochs<>();
    private static final String DISK_PROPERTY="ghidrassist.ga12.durable.dir";
    // Explicit clear must not revive a completed disk report during this
    // process. Restart still requires strict full-input fingerprint.
    private static final Map<Program,Boolean> SKIP_DISK=new WeakHashMap<>();

    private static Path diskDirectory(){
        String configured=System.getProperty(DISK_PROPERTY);
        if(configured==null || configured.isBlank())return null;
        try{return Path.of(configured).toAbsolutePath().normalize();}
        catch(RuntimeException invalid){return null;}
    }
    private static HardwareDurableCfgReport.Snapshot snapshot(
            GhidraHardwareFlowService.Report r){
        List<HardwareDurableCfgReport.Site> sites=new ArrayList<>();
        for(HardwareCfgWriteAudit.Site s:r.rawCfgMmioSites)
            sites.add(new HardwareDurableCfgReport.Site(
                s.function(),s.pc(),s.register(),s.address(),s.indirect(),
                s.widthBits(),s.literal(),s.priorSimcrMin(),s.priorSimcrMax(),
                s.unknownCall(),s.unknownStore(),s.functionIncomplete()));
        List<HardwareDurableCfgReport.Role> roles=new ArrayList<>();
        for(HardwarePointerRoleReview.Proposal p:r.pointerRoles)
            roles.add(new HardwareDurableCfgReport.Role(
                p.function(),p.functionName(),p.pointer(),p.module(),p.mm(),
                p.sites(),p.registers(),p.status().name(),p.hint()));
        return new HardwareDurableCfgReport.Snapshot(
            r.markdown,r.configurationEvidenceCsv,r.functions,r.indirect,
            r.vbr,r.unresolved,r.visited,r.limited,r.resetCandidateRecognized,
            r.resetGraphIncomplete,r.cfgReviewComplete,
            r.cfgSitesOmitted,r.pointerSitesOmitted,
            sites,roles,new ArrayList<>(r.resetCandidateFunctions),
            r.sourceInventory);
    }
    private static GhidraHardwareFlowService.Report report(
            HardwareDurableCfgReport.Snapshot s){
        List<HardwareCfgWriteAudit.Site> sites=new ArrayList<>();
        for(HardwareDurableCfgReport.Site site:s.sites())
            sites.add(new HardwareCfgWriteAudit.Site(
                site.function(),site.pc(),site.register(),site.address(),
                site.indirect(),site.widthBits(),site.word(),
                site.mmMin(),site.mmMax(),site.unknownCall(),
                site.unknownStore(),site.incomplete()));
        List<HardwarePointerRoleReview.Proposal> roles=new ArrayList<>();
        for(HardwareDurableCfgReport.Role role:s.roles())
            roles.add(new HardwarePointerRoleReview.Proposal(
                role.function(),role.functionName(),role.pointer(),role.module(),
                role.mm(),role.sites(),role.registers(),
                HardwarePointerRoleReview.Status.valueOf(role.status()),
                role.hint()));
        return new GhidraHardwareFlowService.Report(
            s.markdown(),s.functions(),s.indirect(),s.vbr(),s.unresolved(),
            s.visited(),s.limited(),roles,new HashSet<>(s.resetFunctions()),
            s.resetRecognized(),s.resetIncomplete(),s.csv(),sites,
            s.cfgReviewComplete(),s.cfgOmitted(),s.pointersOmitted(),
            s.sourceInventory());
    }

    private static boolean sameRevision(Program program,
            HardwareAnalysisRevision revision) {
        return revision!=null && revision.matches(program,
            program.getModificationNumber(),program.getLanguageID().toString(),
            program.getExecutableSHA256(),revision.mc68332Selected());
    }

    public static Result loadOrAnalyze(Program program,HardwareAnalysisRevision started,
            TaskMonitor monitor) throws CancelledException {
        if(program==null || started==null || monitor==null)
            throw new IllegalArgumentException("Missing Ghidra analysis context");
        monitor.checkCancelled();
        if(!sameRevision(program,started))throw new CancelledException();
        final long computationEpoch;
        final boolean skipDisk;
        synchronized(COMPLETED){
            computationEpoch=EPOCHS.begin(program);
            skipDisk=Boolean.TRUE.equals(SKIP_DISK.get(program));
            HardwareStageCheckpoint<GhidraHardwareFlowService.Report> previous=
                COMPLETED.get(program);
            if(previous!=null && previous.validFor(started.modificationNumber(),
                    started.language(),started.sourceSha256(),
                    started.mc68332Selected())){
                monitor.checkCancelled();
                if(!sameRevision(program,started) ||
                        !EPOCHS.current(program,computationEpoch))
                    throw new CancelledException();
                return new Result(previous.evidence(),true);
            }
            COMPLETED.remove(program);
        }
        // Persistent use is explicit opt-in only, and never keyed by the
        // original executable SHA alone. Missing/unreadable input is a miss.
        Path directory=diskDirectory();
        HardwareDurableStageStore.Key durableKey=null;
        if(directory!=null && !skipDisk){
            durableKey=HardwareGhidraInputFingerprint.capture(
                program,monitor,started.mc68332Selected()).orElse(null);
            if(durableKey!=null){
                var loaded=HardwareDurableStageStore.load(directory,durableKey)
                    .flatMap(HardwareDurableCfgReport::decode);
                if(loaded.isPresent() &&
                        HardwareDurableCfgReport.eligibleForCompletedRestore(
                            loaded.get())){
                    try {
                        GhidraHardwareFlowService.Report restored=report(loaded.get());
                        monitor.checkCancelled();
                        synchronized(COMPLETED){
                            if(!sameRevision(program,started) ||
                                    !EPOCHS.current(program,computationEpoch))
                                throw new CancelledException();
                            COMPLETED.put(program,HardwareStageCheckpoint.complete(
                                started.modificationNumber(),started.language(),
                                started.sourceSha256(),started.mc68332Selected(),
                                restored));
                        }
                        return new Result(restored,true);
                    }catch(IllegalArgumentException invalid){
                        // Untrusted/corrupt payload: analyze from scratch.
                    }
                }
            }
        }
        // No lock held during the expensive Ghidra CFG walk.
        GhidraHardwareFlowService.Report calculated=
            new GhidraHardwareFlowService().analyze(
                program,monitor,started.mc68332Selected(),
                directory,durableKey);
        monitor.checkCancelled();
        if(!sameRevision(program,started))throw new CancelledException();
        synchronized(COMPLETED){
            if(!EPOCHS.current(program,computationEpoch))
                throw new CancelledException();
        }
        if(calculated.markdown.length()<=MAX_REPORT_CHARS){
            HardwareStageCheckpoint<GhidraHardwareFlowService.Report> checkpoint=
                HardwareStageCheckpoint.complete(started.modificationNumber(),
                    started.language(),started.sourceSha256(),
                    started.mc68332Selected(),calculated);
            synchronized(COMPLETED) {
                monitor.checkCancelled();
                if(!sameRevision(program,started) ||
                        !EPOCHS.current(program,computationEpoch))
                    throw new CancelledException();
                COMPLETED.put(program,checkpoint);
                SKIP_DISK.remove(program);
            }
            // Store only complete evidence: never turn a limited/unfinished
            // CFG capture into an apparently complete restart checkpoint.
            if(directory!=null &&
                    HardwareDurableCfgReport.eligibleForCompletedRestore(
                        snapshot(calculated))){
                try{
                    var beforeWrite=HardwareGhidraInputFingerprint.capture(
                        program,monitor,started.mc68332Selected()).orElse(null);
                    // Explicit clear from a concurrent UI turn still wins.
                    synchronized(COMPLETED){
                        if(!sameRevision(program,started) ||
                                !EPOCHS.current(program,computationEpoch))
                            throw new CancelledException();
                    }
                    if(beforeWrite!=null){
                        byte[] bytes=HardwareDurableCfgReport.encode(
                            snapshot(calculated));
                        HardwareDurableStageStore.save(directory,beforeWrite,bytes);
                    }
                }catch(IOException|IllegalArgumentException skip){
                    // Durable cache is best-effort; no analysis or UI failure.
                }
            }
        }
        monitor.checkCancelled();
        synchronized(COMPLETED){
            if(!sameRevision(program,started) ||
                    !EPOCHS.current(program,computationEpoch))
                throw new CancelledException();
        }
        return new Result(calculated,false);
    }

    /** Read-only generation used by Automation source-page cursors.
     * A clear invalidates the generation even if the Program revision is unchanged.
     */
    public static long sourcePageEpoch(Program program) {
        if(program==null)throw new IllegalArgumentException("Missing Program");
        synchronized(COMPLETED){return EPOCHS.begin(program);}
    }
    public static boolean sourcePageEpochCurrent(Program program,long generation) {
        if(program==null)return false;
        synchronized(COMPLETED){return EPOCHS.current(program,generation);}
    }

    public static void clear(Program program){
        if(program==null)return;
        synchronized(COMPLETED){
            EPOCHS.invalidate(program);
            COMPLETED.remove(program);
            SKIP_DISK.put(program,true);
            GhidraHardwareFlowService.invalidateFunctionStages(program);
        }
    }
}
