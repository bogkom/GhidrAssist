package ghidrassist.hardware;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.util.*;

/**
 * Typed, bounded serialization for every completed CFG Report component.
 * No Java ObjectInputStream, polymorphic gadgets or Ghidra DB mutations.
 */
public final class HardwareDurableCfgReport {
    private HardwareDurableCfgReport(){}
    /** V2 includes optional bounded live JSR/MOVEC source provenance. */
    public static final String SCHEMA="GA12-CFG-REPORT-2";
    public static final String LEGACY_SCHEMA="GA12-CFG-REPORT-1";
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
            List<Site> sites,List<Role> roles,List<Long> resetFunctions,
            HardwareResetIndirectVbrCorrelation.SourceInventory sourceInventory) {
        /** V1 callers and historic snapshots have no typed source inventory. */
        public Snapshot(String markdown,String csv,int functions,
                int indirect,int vbr,int unresolved,int visited,boolean limited,
                boolean resetRecognized,boolean resetIncomplete,
                boolean cfgReviewComplete,long cfgOmitted,long pointersOmitted,
                List<Site> sites,List<Role> roles,List<Long> resetFunctions) {
            this(markdown,csv,functions,indirect,vbr,unresolved,visited,limited,
                resetRecognized,resetIncomplete,cfgReviewComplete,cfgOmitted,
                pointersOmitted,sites,roles,resetFunctions,null);
        }
        public Snapshot {
            if(markdown==null || csv==null || sites==null || roles==null ||
                    resetFunctions==null || functions<0 || indirect<0 ||
                    vbr<0 || unresolved<0 || visited<0 || cfgOmitted<0 ||
                    pointersOmitted<0 || sites.size()>12000 ||
                    roles.size()>8000 || resetFunctions.size()>50000)
                throw new IllegalArgumentException("Invalid CFG snapshot");
            // A typed source inventory cannot contradict the CFG summary's
            // RESET provenance. This gate applies before save AND after V2
            // decode, even when the outer disk checksum is valid.
            if(sourceInventory!=null){
                // A missing RESET root has no observed function subset.
                // Never persist it as an apparently complete positive set.
                if(resetRecognized==resetFunctions.isEmpty() ||
                        !resetRecognized && !resetIncomplete)
                    throw new IllegalArgumentException(
                        "Unrooted or contradictory V2 RESET source set");
                // The independent CFG and typed source sections carry the
                // SAME bounded RESET reachability set. A V2 report may have
                // unknown/omitted JSR witnesses, but it cannot fabricate a
                // different RESET set while claiming the CFG was restored.
                Set<Long> fromCfg=new HashSet<>(resetFunctions);
                if(sourceInventory.resetRecognized()!=resetRecognized ||
                        sourceInventory.resetIncomplete()!=resetIncomplete ||
                        fromCfg.size()!=resetFunctions.size() ||
                        !sourceInventory.resetVisited().equals(fromCfg))
                    throw new IllegalArgumentException(
                        "Contradictory V2 RESET source provenance/counters");
            }
            sites=List.copyOf(sites);roles=List.copyOf(roles);
            resetFunctions=List.copyOf(resetFunctions);
        }
    }
    /**
     * GA-12: A full-input-keyed disk envelope and valid binary schema do
     * NOT independently attest JSR/MOVEC/RESET source claims after restart.
     * Original V2 source rows are retained on disk for format compatibility
     * and forensic inspection, but MUST NOT become an active source cursor,
     * Review evidence or proof of source completeness in a restored report.
     *
     * Live source pages require a fresh Ghidra Listing/CFG scan against the
     * current Program. This method deliberately does NOT reinterpret stored
     * Markdown, derive any CALL path, or promote partial source records.
     * Only the aggregate completed CFG report remains reusable.
     */
    public static Snapshot restoredForReadOnlyDisplay(Snapshot saved) {
        if(!eligibleForCompletedRestore(saved))
            throw new IllegalArgumentException("Incomplete GA-12 disk source");
        final String warning=
            "## GA-12 RESTORED AGGREGATE — SOURCE INVENTORY UNVERIFIED\n\n"+
            "This report was restored from a full-input-keyed disk checkpoint. "+
            "Any JSR/MOVEC/RESET or MMIO source claims shown below are cached "+
            "text, NOT independently replayed live Ghidra source evidence. "+
            "The typed source inventory and pagination are unavailable until "+
            "Analyze is recomputed from the current Listing (clear the "+
            "completed checkpoint first). Missing or bounded source paths "+
            "remain UNKNOWN; this does not prove execution, active MM/VBR, "+
            "ISR dispatch or physical mapping.\n\n";
        // Preserve the same 1 MiB report bound as the completed-stage
        // cache. An oversized warning+body is a cold-analysis miss.
        if(saved.markdown().length()>1_000_000-warning.length())
            throw new IllegalArgumentException("Restored source report too large");
        return new Snapshot(warning+saved.markdown(),saved.csv(),
            saved.functions(),saved.indirect(),saved.vbr(),
            saved.unresolved(),saved.visited(),saved.limited(),
            saved.resetRecognized(),saved.resetIncomplete(),
            saved.cfgReviewComplete(),saved.cfgOmitted(),
            saved.pointersOmitted(),saved.sites(),saved.roles(),
            saved.resetFunctions(),null);
    }

    /**
     * Complete CFG restoration and a complete observed JSR/MOVEC inventory
     * are different claims. Never elevate a historical V1 CFG-only snapshot
     * or a V2 with omitted/uncertain source witnesses to complete sources.
     * This classifier checks only stored STRUCTURE. It is NOT source
     * revalidation after restart; the active restored snapshot must be
     * sanitized by restoredForReadOnlyDisplay() and will then fail this
     * test until a fresh independent Ghidra scan replaces it.
     * This read-only classifier does not authorize Review/Apply or execution.
     */
    public static boolean eligibleForCompleteSourceInventory(Snapshot snapshot){
        if(!eligibleForCompletedRestore(snapshot) ||
                snapshot.sourceInventory()==null)return false;
        var sources=snapshot.sourceInventory();
        if(!sources.resetRecognized() || sources.resetIncomplete() ||
                sources.omittedIndirect()!=0 || sources.omittedVbr()!=0)
            return false;
        for(var jsr:sources.indirect())
            if(jsr.uncertain())return false;
        for(var movec:sources.vbr())
            if(movec.uncertain())return false;
        return true;
    }

    /**
     * GA-12: a valid checksum and matching Program fingerprint alone do not
     * prove that a historical payload contains a completed CFG evidence set.
     * An interrupted or display-budget-omitted snapshot is not a resumable
     * "complete" analysis, even if a separate writer emitted it.
     *
     * This pure gate is checked both before durable save and AFTER decoding,
     * preserving the ability to decode/inspect incomplete historical data.
     */
    public static boolean eligibleForCompletedRestore(Snapshot snapshot) {
        return snapshot!=null && snapshot.cfgReviewComplete() &&
            !snapshot.limited() &&
            snapshot.cfgOmitted()==0 && snapshot.pointersOmitted()==0 &&
            snapshot.markdown()!=null &&
            snapshot.markdown().length()<=1_000_000;
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
        // No silent U+FFFD substitution of corrupted provenance.
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        }catch(CharacterCodingException malformed){
            throw new IOException("Invalid checkpoint UTF-8",malformed);
        }
    }
    private static boolean readBoolean(DataInputStream in)throws IOException{
        // Ghidra evidence cannot treat any nonzero byte as canonical TRUE.
        int value=in.readUnsignedByte();
        if(value!=0 && value!=1)
            throw new IOException("Noncanonical checkpoint boolean");
        return value==1;
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
            writeInventory(out,s.sourceInventory());
        }
        if(bytes.size()>HardwareDurableStageStore.MAX_PAYLOAD_BYTES)
            throw new IOException("Report too large for durable cache");
        return bytes.toByteArray();
    }
    /** Version 2 retains the bounded observed source inventory only. */
    private static void writeInventory(DataOutputStream out,
            HardwareResetIndirectVbrCorrelation.SourceInventory sources)
            throws IOException {
        out.writeBoolean(sources!=null);
        if(sources==null)return;
        out.writeBoolean(sources.resetRecognized());
        out.writeBoolean(sources.resetIncomplete());
        out.writeInt(sources.omittedIndirect());
        out.writeInt(sources.omittedVbr());
        out.writeInt(sources.indirect().size());
        for(var row:sources.indirect()) {
            out.writeLong(row.caller());out.writeLong(row.pc());
            out.writeLong(row.target());out.writeBoolean(row.mayMm());
            out.writeBoolean(row.uncertain());
        }
        out.writeInt(sources.vbr().size());
        for(var row:sources.vbr()) {
            out.writeLong(row.function());out.writeLong(row.pc());
            out.writeBoolean(row.tableBase()!=null);
            if(row.tableBase()!=null)out.writeLong(row.tableBase());
            out.writeBoolean(row.uncertain());
        }
        out.writeInt(sources.resetVisited().size());
        for(long address:new TreeSet<>(sources.resetVisited()))
            out.writeLong(address);
    }

    private static HardwareResetIndirectVbrCorrelation.SourceInventory
            readInventory(DataInputStream in)throws IOException {
        if(!readBoolean(in))return null;
        boolean root=readBoolean(in),incomplete=readBoolean(in);
        int omittedIndirect=in.readInt(),omittedVbr=in.readInt();
        int jsrs=count(in,HardwareResetIndirectVbrCorrelation.MAX_INDIRECT_SOURCES);
        List<HardwareResetIndirectVbrCorrelation.Indirect> indirect=new ArrayList<>();
        for(int i=0;i<jsrs;i++) {
            indirect.add(new HardwareResetIndirectVbrCorrelation.Indirect(
                in.readLong(),in.readLong(),in.readLong(),
                readBoolean(in),readBoolean(in)));
        }
        int movecs=count(in,HardwareResetIndirectVbrCorrelation.MAX_VBR_SOURCES);
        List<HardwareResetIndirectVbrCorrelation.Vbr> vbr=new ArrayList<>();
        for(int i=0;i<movecs;i++) {
            long entry=in.readLong(),pc=in.readLong();
            Long base=readBoolean(in)?in.readLong():null;
            vbr.add(new HardwareResetIndirectVbrCorrelation.Vbr(
                entry,pc,base,readBoolean(in)));
        }
        int resetCount=count(in,50000);
        Set<Long> reset=new HashSet<>();
        for(int i=0;i<resetCount;i++) {
            if(!reset.add(in.readLong()))throw new IOException("Duplicate RESET entry");
        }
        return new HardwareResetIndirectVbrCorrelation.SourceInventory(
            indirect,vbr,reset,root,incomplete,omittedIndirect,omittedVbr);
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
            String schema=readText(in);
            boolean v2=SCHEMA.equals(schema);
            if(!v2 && !LEGACY_SCHEMA.equals(schema))return Optional.empty();
            String markdown=readText(in),csv=readText(in);
            int functions=in.readInt(),indirect=in.readInt(),vbr=in.readInt(),
                unresolved=in.readInt(),visited=in.readInt();
            boolean limited=readBoolean(in),resetRecognized=readBoolean(in),
                resetIncomplete=readBoolean(in),review=readBoolean(in);
            long cfgOmitted=in.readLong(),pointerOmitted=in.readLong();
            int siteCount=count(in,12000);
            List<Site> sites=new ArrayList<>();
            for(int i=0;i<siteCount;i++){
                long fn=in.readLong(),pc=in.readLong();
                String register=readText(in);long address=in.readLong();
                boolean viaPointer=readBoolean(in);int width=in.readInt();
                Integer word=readBoolean(in)?in.readInt():null;
                int min=in.readInt(),max=in.readInt();
                boolean call=readBoolean(in),store=readBoolean(in),
                    incomplete=readBoolean(in);
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
            var sourceInventory=v2?readInventory(in):null;
            if(in.available()!=0)return Optional.empty();
            return Optional.of(new Snapshot(markdown,csv,functions,indirect,
                vbr,unresolved,visited,limited,resetRecognized,
                resetIncomplete,review,cfgOmitted,pointerOmitted,
                sites,roles,resets,sourceInventory));
        }catch(IOException|RuntimeException malformed){
            return Optional.empty();
        }
    }
}
