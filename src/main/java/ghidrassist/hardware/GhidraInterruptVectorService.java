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

/**
 * Read-only image-zero vector candidate scan for 68000 big-endian programs.
 * Real VBR and ISR execution remain UNKNOWN even if a pointer resolves.
 */
public final class GhidraInterruptVectorService {
    private GhidraInterruptVectorService() {}

    public static String analyze(Program program, TaskMonitor monitor)
            throws CancelledException {
        String language=program.getLanguageID().toString().toUpperCase(Locale.ROOT);
        if(!language.startsWith("68000:BE:"))
            return "## Exception/interrupt vectors\n\nNot evaluated: no "+
                "68000 big-endian vector layout assumption for this language.\n\n";

        if(monitor==null)monitor=TaskMonitor.DUMMY;
        List<HardwareInterruptVectors.Observation> observations=new ArrayList<>();
        for(int vector=2;vector<256;vector++){
            monitor.checkCancelled();
            Long raw=null;
            boolean mapped=false;
            String function=null;
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
                                    if(f!=null)
                                        function=f.getName()+" @ "+f.getEntryPoint();
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
                vector,raw,mapped,function));
        }
        return HardwareInterruptVectors.inspect(0,observations,32).markdown();
    }
}
