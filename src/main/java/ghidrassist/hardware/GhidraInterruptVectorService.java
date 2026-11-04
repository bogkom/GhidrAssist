package ghidrassist.hardware;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Read-only image-zero vector candidate scan for 68000 big-endian programs.
 * Real VBR and ISR execution remain UNKNOWN even if a pointer resolves.
 */
public final class GhidraInterruptVectorService {
    private GhidraInterruptVectorService() {}

    public static String analyze(Program program, TaskMonitor monitor)
            throws CancelledException {
        return analyze(program,monitor,false,true,Set.of(),List.of());
    }

    /** Join already-computed bounded RESET candidate evidence, never runtime IRQ. */
    public static String analyze(Program program,TaskMonitor monitor,
            boolean resetRootRecognized,boolean resetGraphIncomplete,
            Set<Long> resetVisited,
            List<HardwareCallEffects.FunctionNode> callGraph)
            throws CancelledException {
        if(resetVisited==null || callGraph==null)
            throw new IllegalArgumentException("Missing reset-call evidence");
        String language=program.getLanguageID().toString().toUpperCase(Locale.ROOT);
        if(!language.startsWith("68000:BE:"))
            return "## Exception/interrupt vectors\n\nNot evaluated: no "+
                "68000 big-endian vector layout assumption for this language.\n\n";

        if(monitor==null)monitor=TaskMonitor.DUMMY;
        List<HardwareInterruptVectors.Observation> observations=new ArrayList<>();
        List<HardwareVectorResetCorrelation.Target> resolved=new ArrayList<>();
        for(int vector=2;vector<256;vector++){
            monitor.checkCancelled();
            Long raw=null;
            boolean mapped=false;
            String function=null;
            boolean exactFunctionEntry=false;
            long offset=4L*vector;
            try{
                Address slot=program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(offset);
                // Image bytes, not the current VBR or the MCU's ROM-remap status.
                if(program.getMemory().contains(slot)){
                    byte[] bytes=new byte[4];
                    if(program.getMemory().getBytes(slot,bytes)==bytes.length){
                        long word=0;
                        for(byte b:bytes)word=(word<<8)|(b&0xffL);
                        raw=word;
                        if(word!=0 && word!=0xffffffffL && (word&1)==0){
                            try{
                                Address dest=program.getAddressFactory()
                                    .getDefaultAddressSpace().getAddress(word);
                                mapped=program.getMemory().contains(dest);
                                if(mapped){
                                    Function f=program.getFunctionManager()
                                        .getFunctionContaining(dest);
                                    if(f!=null){
                                        function=f.getName()+" @ "+f.getEntryPoint();
                                        exactFunctionEntry=f.getEntryPoint().equals(dest);
                                        resolved.add(new HardwareVectorResetCorrelation.Target(
                                            vector,word,f.getEntryPoint().getOffset(),
                                            exactFunctionEntry));
                                    }
                                }
                            }catch(RuntimeException invalidTarget){
                                mapped=false; // Out of address space: UNKNOWN
                            }
                        }
                    }
                }
            }catch(MemoryAccessException | RuntimeException ignored){
                // Unreadable/truncated/bad vector must never be treated as zero.
            }
            observations.add(new HardwareInterruptVectors.Observation(
                vector,raw,mapped,function,exactFunctionEntry));
        }
        return HardwareInterruptVectors.inspect(0,observations,32).markdown()
            + HardwareVectorResetCorrelation.inspect(
                resetRootRecognized,resetGraphIncomplete,resetVisited,
                resolved,callGraph,32).markdown();
    }
    /**
     * Scan a strictly bounded list of local MOVEC-to-VBR source-image
     * candidates. The source CALL/RESET relation comes from the already
     * computed bounded call graph; it is NOT a dynamic VBR selector.
     *
     * This method must only be called after explicit MC68332 profile choice.
     * Never create memory, disassemble or mutate a Program in this scan.
     */
    public static String analyzeRelocatedSourceTables(Program program,
            TaskMonitor monitor,List<HardwareVbrRelocationEvidence.Site> sites,
            int sourceSitesOmitted,boolean resetRootRecognized,
            boolean resetGraphIncomplete,Set<Long> resetVisited,
            List<HardwareCallEffects.FunctionNode> callGraph)
            throws CancelledException {
        if(program==null || sites==null || sourceSitesOmitted<0 ||
                resetVisited==null || callGraph==null)
            throw new IllegalArgumentException("Invalid relocated VBR evidence");
        if(monitor==null)monitor=TaskMonitor.DUMMY;
        var plan=HardwareVbrRelocationEvidence.plan(
            sites,resetRootRecognized,resetGraphIncomplete,resetVisited,3,24);
        StringBuilder report=new StringBuilder(plan.markdown());
        if(sourceSitesOmitted>0)
            report.append("- **INCOMPLETE INPUT:** ")
                .append(sourceSitesOmitted)
                .append(" additional decoded MOVEC sites omitted by the ")
                .append("256-site source cap; never infer missing writes.\n\n");
        String language=program.getLanguageID().toString().toUpperCase(Locale.ROOT);
        if(!language.startsWith("68000:BE:"))
            return report.append("- Not evaluated: unsupported 68000 ")
                .append("big-endian vector layout.\n\n").toString();
        for(Long base:plan.tableBases()){
            monitor.checkCancelled();
            List<HardwareInterruptVectors.Observation> observations=
                new ArrayList<>();
            List<HardwareVectorResetCorrelation.Target> targets=
                new ArrayList<>();
            for(int vector=2;vector<256;vector++){
                monitor.checkCancelled();
                Long pointer=null;
                boolean mapped=false,exactEntry=false;
                String function=null;
                long location=base+4L*vector;
                try {
                    Address slot=program.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(location);
                    if(program.getMemory().contains(slot)){
                        byte[] word=new byte[4];
                        if(program.getMemory().getBytes(slot,word)==word.length){
                            long value=0;
                            for(byte part:word)
                                value=(value<<8)|(part&0xffL);
                            pointer=value;
                            if(value!=0 && value!=0xffffffffL &&
                                    value<=HardwareVbrRelocationEvidence.MAX_24BIT &&
                                    (value&1)==0){
                                try{
                                    Address dest=program.getAddressFactory()
                                        .getDefaultAddressSpace().getAddress(value);
                                    mapped=program.getMemory().contains(dest);
                                    if(mapped){
                                        Function found=program.getFunctionManager()
                                            .getFunctionContaining(dest);
                                        if(found!=null){
                                            function=found.getName()+" @ "+
                                                found.getEntryPoint();
                                            exactEntry=found.getEntryPoint()
                                                .equals(dest);
                                            targets.add(new
                                                HardwareVectorResetCorrelation.Target(
                                                    vector,value,
                                                    found.getEntryPoint().getOffset(),
                                                    exactEntry));
                                        }
                                    }
                                }catch(RuntimeException badTarget){
                                    mapped=false;
                                }
                            }
                        }
                    }
                }catch(MemoryAccessException | RuntimeException badSlot){
                    // UNKNOWN bytes, never a fabricated zero or a handler.
                }
                observations.add(new HardwareInterruptVectors.Observation(
                    vector,pointer,mapped,function,exactEntry));
            }
            report.append("### Relocated **source-image** table candidate at ")
                .append(String.format(Locale.ROOT,"0x%08X",base))
                .append(" (not necessarily selected by the MCU)\n\n")
                .append(HardwareInterruptVectors.inspect(
                    base,observations,12).markdown())
                .append(HardwareVectorResetCorrelation.inspectRelocated(
                    base,resetRootRecognized,resetGraphIncomplete,resetVisited,
                    targets,callGraph,12).markdown());
        }
        return report.toString();
    }

}
