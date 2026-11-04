package ghidrassist.hardware;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Typed, bounded serialization for every completed CFG Report component.
 * No Java ObjectInputStream, polymorphic gadgets or Ghidra DB mutations.
 */
public final class HardwareDurableCfgReport {
    private HardwareDurableCfgReport(){}
    public static final String SCHEMA="GA12-CFG-REPORT-1";
    public record Site(long function,long pc,String register,long address,
            boolean indirect,int widthBits,Integer word,int mmMin,int mmMax,
            boolean unknownCall,boolean unknownStore,boolean incomplete) {}
    public record Role(long function,String functionName,String pointer,
            String module,int mm,int sites,int registers,String status,
            String hint) {}
    public record Snapshot(String markdown,String csv,int functions,
            int indirect,int vbr,int unresolved,int visited,boolean limited,
            boolean resetRecognized,boolean resetIncomplete,
            boolean cfgReviewComplete,long cfgOmitted,long pointersOmitted,
            List<Site> sites,List<Role> roles,List<Long> resetFunctions) {
        public Snapshot {
            if(markdown==null || csv==null || sites==null || roles==null ||
                    resetFunctions==null || functions<0 || indirect<0 ||
                    vbr<0 || unresolved<0 || visited<0 || cfgOmitted<0 ||
                    pointersOmitted<0 || sites.size()>12000 ||
                    roles.size()>8000 || resetFunctions.size()>50000)
                throw new IllegalArgumentException("Invalid CFG snapshot");
            sites=List.copyOf(sites);roles=List.copyOf(roles);
            resetFunctions=List.copyOf(resetFunctions);
        }
    }
    private static void writeText(DataOutputStream out,String text)throws IOException{
        if(text==null)throw new IOException("Null checkpoint string");
        byte[] bytes=text.getBytes(StandardCharsets.UTF_8);
        if(bytes.length>2_000_000)throw new IOException("Oversized checkpoint string");
        out.writeInt(bytes.length);out.write(bytes);
    }
    private static String readText(DataInputStream in)throws IOException{
        int count=in.readInt();
        if(count<0 || count>2_000_000 || count>in.available())
            throw new IOException("Bad checkpoint string length");
        byte[] bytes=in.readNBytes(count);
        return new String(bytes,StandardCharsets.UTF_8);
    }
    public static byte[] encode(Snapshot s)throws IOException{
        if(s==null)throw new IOException("Null CFG snapshot");
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        try(DataOutputStream out=new DataOutputStream(bytes)){
            writeText(out,SCHEMA);
            writeText(out,s.markdown());writeText(out,s.csv());
            out.writeInt(s.functions());out.writeInt(s.indirect());
            out.writeInt(s.vbr());out.writeInt(s.unresolved());
            out.writeInt(s.visited());out.writeBoolean(s.limited());
            out.writeBoolean(s.resetRecognized());
            out.writeBoolean(s.resetIncomplete());
            out.writeBoolean(s.cfgReviewComplete());
            out.writeLong(s.cfgOmitted());out.writeLong(s.pointersOmitted());
            out.writeInt(s.sites().size());
            for(Site v:s.sites()){
                out.writeLong(v.function());out.writeLong(v.pc());
                writeText(out,v.register());out.writeLong(v.address());
                out.writeBoolean(v.indirect());out.writeInt(v.widthBits());
                out.writeBoolean(v.word()!=null);
                if(v.word()!=null)out.writeInt(v.word());
                out.writeInt(v.mmMin());out.writeInt(v.mmMax());
                out.writeBoolean(v.unknownCall());out.writeBoolean(v.unknownStore());
                out.writeBoolean(v.incomplete());
            }
            out.writeInt(s.roles().size());
            for(Role v:s.roles()){
                out.writeLong(v.function());writeText(out,v.functionName());
                writeText(out,v.pointer());writeText(out,v.module());
                out.writeInt(v.mm());out.writeInt(v.sites());out.writeInt(v.registers());
                writeText(out,v.status());writeText(out,v.hint());
            }
            out.writeInt(s.resetFunctions().size());
            for(long entry:s.resetFunctions())out.writeLong(entry);
        }
        if(bytes.size()>HardwareDurableStageStore.MAX_PAYLOAD_BYTES)
            throw new IOException("Report too large for durable cache");
        return bytes.toByteArray();
    }
    private static int count(DataInputStream in,int cap)throws IOException{
        int n=in.readInt();
        if(n<0 || n>cap)throw new IOException("Invalid checkpoint record count");
        return n;
    }
    public static Optional<Snapshot> decode(byte[] data){
        if(data==null || data.length==0 ||
                data.length>HardwareDurableStageStore.MAX_PAYLOAD_BYTES)
            return Optional.empty();
        try(DataInputStream in=new DataInputStream(new ByteArrayInputStream(data))){
            if(!SCHEMA.equals(readText(in)))return Optional.empty();
            String markdown=readText(in),csv=readText(in);
            int functions=in.readInt(),indirect=in.readInt(),vbr=in.readInt(),
                unresolved=in.readInt(),visited=in.readInt();
            boolean limited=in.readBoolean(),resetRecognized=in.readBoolean(),
                resetIncomplete=in.readBoolean(),review=in.readBoolean();
            long cfgOmitted=in.readLong(),pointerOmitted=in.readLong();
            int siteCount=count(in,12000);
            List<Site> sites=new ArrayList<>();
            for(int i=0;i<siteCount;i++){
                long fn=in.readLong(),pc=in.readLong();
                String register=readText(in);long address=in.readLong();
                boolean viaPointer=in.readBoolean();int width=in.readInt();
                Integer word=in.readBoolean()?in.readInt():null;
                int min=in.readInt(),max=in.readInt();
                boolean call=in.readBoolean(),store=in.readBoolean(),
                    incomplete=in.readBoolean();
                sites.add(new Site(fn,pc,register,address,viaPointer,width,
                    word,min,max,call,store,incomplete));
            }
            int roleCount=count(in,8000);
            List<Role> roles=new ArrayList<>();
            for(int i=0;i<roleCount;i++){
                roles.add(new Role(in.readLong(),readText(in),readText(in),
                    readText(in),in.readInt(),in.readInt(),in.readInt(),
                    readText(in),readText(in)));
            }
            int resetCount=count(in,50000);
            List<Long> resets=new ArrayList<>();
            for(int i=0;i<resetCount;i++)resets.add(in.readLong());
            if(in.available()!=0)return Optional.empty();
            return Optional.of(new Snapshot(markdown,csv,functions,indirect,
                vbr,unresolved,visited,limited,resetRecognized,
                resetIncomplete,review,cfgOmitted,pointerOmitted,
                sites,roles,resets));
        }catch(IOException|RuntimeException malformed){
            return Optional.empty();
        }
    }
}
