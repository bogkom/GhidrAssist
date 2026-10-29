package ghidrassist.hardware;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

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
        HardwareStageCheckpoint<GhidraHardwareFlowService.Report> previous;
        synchronized(COMPLETED){
            previous=COMPLETED.get(program);
            if(previous!=null && previous.validFor(started.modificationNumber(),
                    started.language(),started.sourceSha256(),
                    started.mc68332Selected()))
                return new Result(previous.evidence(),true);
            COMPLETED.remove(program);
        }
        // No lock held during the expensive Ghidra CFG walk.
        GhidraHardwareFlowService.Report calculated=
            new GhidraHardwareFlowService().analyze(program,monitor);
        monitor.checkCancelled();
        if(!sameRevision(program,started))throw new CancelledException();
        if(calculated.markdown.length()<=MAX_REPORT_CHARS){
            HardwareStageCheckpoint<GhidraHardwareFlowService.Report> checkpoint=
                HardwareStageCheckpoint.complete(started.modificationNumber(),
                    started.language(),started.sourceSha256(),
                    started.mc68332Selected(),calculated);
            synchronized(COMPLETED) {
                if(!sameRevision(program,started))throw new CancelledException();
                COMPLETED.put(program,checkpoint);
            }
        }
        return new Result(calculated,false);
    }

    public static void clear(Program program){
        if(program==null)return;
        synchronized(COMPLETED){COMPLETED.remove(program);}
    }
}
