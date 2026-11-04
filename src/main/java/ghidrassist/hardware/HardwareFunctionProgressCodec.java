package ghidrassist.hardware;

import java.io.*;
import java.util.*;

/**
 * Typed, bounded, versioned intermediate CFG worklist codec.
 * Decoding never publishes Analysis/Review/RAG. Outer durable-store digest
 * detects accidental corruption; it is not an attacker authentication.
 */
public final class HardwareFunctionProgressCodec {
    private HardwareFunctionProgressCodec(){}
    public static final String SCHEMA="GA12-CFG-PROGRESS-1";
    private static final int CAP=HardwareDurableStageStore.MAX_PAYLOAD_BYTES;

    public static byte[] encode(HardwareDataflow.Progress progress)throws IOException{
        if(progress==null)throw new IOException("No partial progress");
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        try(DataOutputStream out=new DataOutputStream(bytes)){
            out.writeUTF(SCHEMA);
            out.writeLong(progress.entry());
            out.writeInt(progress.maxIterations());
            out.writeInt(progress.iterations());
            out.writeInt(progress.atEntry().size());
            for(var node:new TreeMap<>(progress.atEntry()).entrySet()){
                out.writeLong(node.getKey());
                var state=node.getValue();
                out.writeInt(state.pointers().size());
                for(var reg:new TreeMap<>(state.pointers()).entrySet()){
                    out.writeUTF(reg.getKey());
                    out.writeLong(reg.getValue());
                }
                out.writeInt(state.peripherals().size());
                for(var mmio:new TreeMap<>(state.peripherals()).entrySet()){
                    out.writeLong(mmio.getKey());out.writeInt(mmio.getValue());
                }
                out.writeBoolean(state.vbr()!=null);
                if(state.vbr()!=null)out.writeLong(state.vbr());
                out.writeByte(state.mmMin());out.writeByte(state.mmMax());
                out.writeBoolean(state.unknownCall());
                out.writeBoolean(state.unknownStore());
            }
            out.writeInt(progress.pending().size());
            for(Long pc:progress.pending())out.writeLong(pc);
        }
        if(bytes.size()>CAP)throw new IOException("Worklist checkpoint too large");
        return bytes.toByteArray();
    }

    public static Optional<HardwareDataflow.Progress> decode(byte[] data){
        if(data==null || data.length<32 || data.length>CAP)
            return Optional.empty();
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(data))){
            if(!SCHEMA.equals(in.readUTF()))return Optional.empty();
            long entry=in.readLong();
            int budget=in.readInt(),iterations=in.readInt();
            int nodes=count(in,HardwareDataflow.MAX_PROGRESS_NODES);
            Map<Long,HardwareDataflow.EntryState> states=new LinkedHashMap<>();
            int cells=0;
            for(int i=0;i<nodes;i++){
                long pc=in.readLong();
                int nreg=count(in,16);
                Map<String,Long> registers=new LinkedHashMap<>();
                cells+=nreg;
                if(cells>HardwareDataflow.MAX_PROGRESS_CELLS)return Optional.empty();
                for(int j=0;j<nreg;j++){
                    String name=in.readUTF();long value=in.readLong();
                    if(registers.putIfAbsent(name,value)!=null)return Optional.empty();
                }
                int nmmio=count(in,256);
                cells+=nmmio;
                if(cells>HardwareDataflow.MAX_PROGRESS_CELLS)return Optional.empty();
                Map<Long,Integer> peripheral=new LinkedHashMap<>();
                for(int j=0;j<nmmio;j++)
                    if(peripheral.putIfAbsent(in.readLong(),in.readInt())!=null)
                        return Optional.empty();
                Long vbr=in.readBoolean()?in.readLong():null;
                int min=in.readUnsignedByte(),max=in.readUnsignedByte();
                boolean unknownCall=in.readBoolean(),unknownStore=in.readBoolean();
                var state=new HardwareDataflow.EntryState(
                    registers,peripheral,vbr,min,max,unknownCall,unknownStore);
                if(states.putIfAbsent(pc,state)!=null)return Optional.empty();
            }
            int pending=count(in,HardwareDataflow.MAX_PROGRESS_NODES);
            List<Long> queue=new ArrayList<>();
            for(int i=0;i<pending;i++)queue.add(in.readLong());
            if(in.available()!=0)return Optional.empty();
            return Optional.of(new HardwareDataflow.Progress(
                entry,budget,iterations,states,queue));
        }catch(IOException|IllegalArgumentException|NullPointerException bad){
            return Optional.empty();
        }
    }
    private static int count(DataInputStream in,int cap)throws IOException{
        int n=in.readInt();
        if(n<0 || n>cap)throw new IOException("Out-of-range progress count");
        return n;
    }
}
