package ghidrassist.hardware;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Path;
import java.util.Collection;
import java.util.function.BooleanSupplier;

/**
 * GA-12: resumable FIXED-POINT iterations in an individual function.
 * Only after every worklist successor has converged can a Result be used
 * as source evidence. Partial iterations can never reach Review/Apply.
 */
public final class HardwarePartialStageRunner {
    private HardwarePartialStageRunner(){}
    public static final int ITERATIONS_PER_SLICE=16;
    public static final int MAX_WRITES_PER_FUNCTION=16;
    public record Outcome(HardwareDataflow.Result result,
                          boolean restoredPartial,int storedPartial) {}

    public static Outcome analyze(long entry,
            Collection<HardwareDataflow.Step> steps,Collection<Long> targets,
            int budget,Path directory,HardwareDurableStageStore.Key input,
            TaskMonitor monitor,BooleanSupplier stillCurrent)
            throws CancelledException{
        if(steps==null || targets==null || monitor==null ||
                stillCurrent==null || budget<1)
            throw new IllegalArgumentException("Missing trusted CFG inputs");
        if(directory==null || input==null)
            return new Outcome(HardwareDataflow.analyze(
                entry,steps,targets,budget),false,0);
        var progress=HardwareDurableFunctionStages.loadProgress(
            directory,input,entry,budget,steps,targets).orElse(null);
        boolean restored=progress!=null;
        int stored=0;
        while(true){
            monitor.checkCancelled();
            if(!stillCurrent.getAsBoolean())throw new CancelledException();
            var slice=HardwareDataflow.analyzeSlice(
                entry,steps,targets,budget,progress,ITERATIONS_PER_SLICE);
            monitor.checkCancelled();
            if(!stillCurrent.getAsBoolean())throw new CancelledException();
            if(slice.complete()!=null)
                return new Outcome(slice.complete(),restored,stored);
            if(slice.progress()==null){
                // Oversized worklists stay safe and are recomputed from
                // scratch with the original nonpersistent CFG algorithm.
                return new Outcome(HardwareDataflow.analyze(
                    entry,steps,targets,budget),restored,stored);
            }
            progress=slice.progress();
            if(stored<MAX_WRITES_PER_FUNCTION &&
                    HardwareDurableFunctionStages.saveProgress(
                        directory,input,entry,budget,steps,targets,progress))
                stored++;
            // The UI monitor can cancel after a saved coherent slice.
            monitor.checkCancelled();
        }
    }
}
