package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Raw big-endian Motorola 68k/CPU32 byte-pattern inventory.
 *
 * Only three unambiguous absolute-address forms are decoded:
 * MOVE.W #imm,(absolute long), MOVE.L #imm,(absolute long), CLR.W (absolute long).
 * The opcode may occur in data or inside a different instruction. Therefore
 * every result is a raw pattern, NOT a disassembled instruction or an executed
 * hardware write. Ghidra program Listing and control-flow proof come later.
 */
public final class FirmwarePatternScanner {
    private FirmwarePatternScanner() {}

    public enum Kind { MOVE_WORD, MOVE_LONG, CLR_WORD }

    public static final class Hit {
        public final int offset, absoluteAddress, widthBits;
        public final long value;
        public final Kind kind;
        private Hit(int offset,int absoluteAddress,int widthBits,long value,Kind kind){
            this.offset=offset;
            this.absoluteAddress=absoluteAddress;
            this.widthBits=widthBits;
            this.value=value;
            this.kind=kind;
        }
        public String toString(){
            return String.format(Locale.ROOT,"%06X %s #%X -> %06X (RAW CANDIDATE)",
                offset,kind,value,absoluteAddress);
        }
    }
    public static final class Report {
        public final int size;
        public final int halfwordCandidateCount;
        public final List<Hit> hits;
        private Report(int size,int halfwordCandidateCount,List<Hit> hits){
            this.size=size;
            this.halfwordCandidateCount=halfwordCandidateCount;
            this.hits=Collections.unmodifiableList(new ArrayList<>(hits));
        }
        public long count(Kind kind){
            return hits.stream().filter(h->h.kind==kind).count();
        }
    }
    private static int unsignedWord(byte[] bytes,int at){
        return ((bytes[at]&0xff)<<8)|(bytes[at+1]&0xff);
    }
    private static long unsignedLong(byte[] bytes,int at){
        return ((long)unsignedWord(bytes,at)<<16)|unsignedWord(bytes,at+2);
    }
    public static Report scan(byte[] bytes,int fromAddress,int toAddress) {
        if(bytes==null)throw new IllegalArgumentException("Firmware required");
        if(fromAddress<0||toAddress<fromAddress||toAddress>0xffffff)
            throw new IllegalArgumentException("Invalid 24-bit target address range");
        List<Hit> hits=new ArrayList<>();
        int rawHalfwords=0;
        for(int at=0;at+6<=bytes.length;at+=2){
            int op=unsignedWord(bytes,at);
            if(op==0x33fc && at+8<=bytes.length){   // MOVE.W immediate -> absolute long
                rawHalfwords++;
                long address=unsignedLong(bytes,at+4);
                if(address>=fromAddress&&address<=toAddress)
                    hits.add(new Hit(at,(int)address,16,unsignedWord(bytes,at+2),Kind.MOVE_WORD));
            }else if(op==0x23fc && at+10<=bytes.length){ // MOVE.L immediate -> absolute long
                long address=unsignedLong(bytes,at+6);
                if(address>=fromAddress&&address<=toAddress)
                    hits.add(new Hit(at,(int)address,32,unsignedLong(bytes,at+2),Kind.MOVE_LONG));
            }else if(op==0x4279 && at+6<=bytes.length){ // CLR.W absolute long
                long address=unsignedLong(bytes,at+2);
                if(address>=fromAddress&&address<=toAddress)
                    hits.add(new Hit(at,(int)address,16,0,Kind.CLR_WORD));
            }
        }
        return new Report(bytes.length,rawHalfwords,hits);
    }
    public static List<Integer> findMovecToVbr(byte[] bytes){
        if(bytes==null)throw new IllegalArgumentException("Firmware required");
        List<Integer> at=new ArrayList<>();
        for(int i=0;i+4<=bytes.length;i+=2) {
            // opcode 4E7B = register -> control register; extension lower 12
            // bits == 0x801 selects VBR. Upper nibble carries the source reg.
            if(unsignedWord(bytes,i)==0x4e7b &&
                    (unsignedWord(bytes,i+2)&0x0fff)==0x0801)
                at.add(i);
        }
        return Collections.unmodifiableList(at);
    }
}
