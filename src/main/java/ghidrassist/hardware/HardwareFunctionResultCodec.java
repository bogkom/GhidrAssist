package ghidrassist.hardware;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Pure Java fixed-schema codec for a FINISHED intraprocedural fixed point.
 * No ObjectInputStream, class names, partial iterations or unbounded arrays.
 */
public final class HardwareFunctionResultCodec {
    private HardwareFunctionResultCodec(){}
    private static final String SCHEMA="GA12-FUNCTION-FIXPOINT-1";
    private static final int MAX_BYTES=HardwareDurableStageStore.MAX_PAYLOAD_BYTES;
    private static final int MAX_PERIPHERAL_CELLS=HardwareFunctionStageCache.MAX_MMIO_WORD_CELLS;
    private static final int MAX_REGISTER_CELLS=HardwareFunctionStageCache.MAX_REGISTER_CELLS;

    private static void text(DataOutputStream o,String text)throws IOException{
        if(text==null){o.writeInt(-1);return;}
        byte[] b=text.getBytes(StandardCharsets.UTF_8);
        if(b.length>128)throw new IOException("Unbounded register/enum text");
        o.writeInt(b.length);o.write(b);
    }
    private static String text(DataInputStream in)throws IOException{
        int n=in.readInt();
        if(n==-1)return null;
        if(n<0 || n>128 || n>in.available())
            throw new IOException("Invalid fixed-point text length");
        return new String(in.readNBytes(n),StandardCharsets.UTF_8);
    }
    private static void longOpt(DataOutputStream o,Long n)throws IOException{
        o.writeBoolean(n!=null);
        if(n!=null)o.writeLong(n);
    }
    private static Long longOpt(DataInputStream in)throws IOException{
        return in.readBoolean()?in.readLong():null;
    }
    private static void intOpt(DataOutputStream o,Integer n)throws IOException{
        o.writeBoolean(n!=null);
        if(n!=null)o.writeInt(n);
    }
    private static Integer intOpt(DataInputStream in)throws IOException{
        return in.readBoolean()?in.readInt():null;
    }
    private static int count(DataInputStream in,int cap)throws IOException{
        int n=in.readInt();
        if(n<0 || n>cap)throw new IOException("Invalid fixed-point count");
        return n;
    }
    public static byte[] encode(HardwareDataflow.Result r)throws IOException{
        if(r==null || r.truncated ||
                r.snapshots.size()>HardwareFunctionStageCache.MAX_SNAPSHOTS_PER_FUNCTION ||
                r.knownPointersAtEntry.size()>HardwareFunctionStageCache.MAX_STEPS_PER_FUNCTION ||
                r.reachedNodes<0 || r.reachedNodes>HardwareFunctionStageCache.MAX_STEPS_PER_FUNCTION ||
                r.iterations<0 || r.iterations>30000)
            throw new IOException("Incomplete or oversized function");
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        try(DataOutputStream o=new DataOutputStream(bytes)){
            text(o,SCHEMA);
            o.writeInt(r.reachedNodes);
            o.writeInt(r.iterations);
            o.writeInt(r.snapshots.size());
            long mmioCount=0;
            for(HardwareDataflow.Snapshot s:r.snapshots){
                o.writeLong(s.instruction);text(o,s.kind.name());
                longOpt(o,s.effectiveAddress);intOpt(o,s.writtenWord);
                o.writeInt(s.writeBits);text(o,s.pointerRegister);
                longOpt(o,s.vbr);o.writeBoolean(s.indirect);
                o.writeInt(s.priorMmCandidateMin);
                o.writeInt(s.priorMmCandidateMax);
                o.writeBoolean(s.priorUnknownCall);
                o.writeBoolean(s.priorUnknownStore);
                o.writeInt(s.knownPeripheralWords.size());
                mmioCount+=s.knownPeripheralWords.size();
                if(mmioCount>MAX_PERIPHERAL_CELLS)
                    throw new IOException("Excessive peripheral evidence");
                for(var e:new TreeMap<>(s.knownPeripheralWords).entrySet()){
                    o.writeLong(e.getKey());o.writeInt(e.getValue());
                }
            }
            o.writeInt(r.knownPointersAtEntry.size());
            long registerCount=0;
            for(var e:new TreeMap<>(r.knownPointersAtEntry).entrySet()){
                o.writeLong(e.getKey());
                o.writeInt(e.getValue().size());
                registerCount+=e.getValue().size();
                if(registerCount>MAX_REGISTER_CELLS)
                    throw new IOException("Excessive register evidence");
                for(var register:new TreeMap<>(e.getValue()).entrySet()){
                    text(o,register.getKey());o.writeLong(register.getValue());
                }
            }
        }
        if(bytes.size()>MAX_BYTES)throw new IOException("Function snapshot too large");
        return bytes.toByteArray();
    }
    /** Any corruption, incomplete record or incompatible schema => cache miss. */
    public static Optional<HardwareDataflow.Result> decode(byte[] data){
        if(data==null || data.length<24 || data.length>MAX_BYTES)
            return Optional.empty();
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(data))){
            if(!SCHEMA.equals(text(in)))return Optional.empty();
            int reached=in.readInt(),iterations=in.readInt();
            int count=count(in,HardwareFunctionStageCache.MAX_SNAPSHOTS_PER_FUNCTION);
            List<HardwareDataflow.Snapshot> snapshots=new ArrayList<>();
            long cells=0;
            for(int i=0;i<count;i++){
                long pc=in.readLong();
                String name=text(in);
                HardwareDataflow.Kind kind=HardwareDataflow.Kind.valueOf(name);
                Long addr=longOpt(in);Integer value=intOpt(in);
                int bits=in.readInt();String register=text(in);Long vbr=longOpt(in);
                boolean indirect=in.readBoolean();
                int min=in.readInt(),max=in.readInt();
                boolean unknownCall=in.readBoolean(),unknownStore=in.readBoolean();
                int countPeriph=count(in,MAX_PERIPHERAL_CELLS);
                cells+=countPeriph;
                if(cells>MAX_PERIPHERAL_CELLS)return Optional.empty();
                Map<Long,Integer> peripheral=new LinkedHashMap<>();
                for(int j=0;j<countPeriph;j++)
                    if(peripheral.put(in.readLong(),in.readInt())!=null)
                        return Optional.empty();
                if(indirect!=(kind==HardwareDataflow.Kind.STORE_INDIRECT))
                    return Optional.empty();
                snapshots.add(HardwareDataflow.Snapshot.restore(
                    pc,kind,addr,value,bits,register,vbr,peripheral,indirect,
                    min,max,unknownCall,unknownStore));
            }
            int pointerCount=count(in,HardwareFunctionStageCache.MAX_STEPS_PER_FUNCTION);
            Map<Long,Map<String,Long>> pointers=new LinkedHashMap<>();
            long regs=0;
            for(int i=0;i<pointerCount;i++){
                long at=in.readLong();
                int n=count(in,16);regs+=n;
                if(regs>MAX_REGISTER_CELLS)return Optional.empty();
                Map<String,Long> registerMap=new LinkedHashMap<>();
                for(int j=0;j<n;j++)
                    if(registerMap.put(text(in),in.readLong())!=null)
                        return Optional.empty();
                if(pointers.put(at,registerMap)!=null)return Optional.empty();
            }
            if(in.available()!=0)return Optional.empty();
            return Optional.of(HardwareDataflow.Result.restore(
                snapshots,reached,iterations,pointers));
        }catch(IOException|IllegalArgumentException|NullPointerException bad){
            return Optional.empty();
        }
    }
}
