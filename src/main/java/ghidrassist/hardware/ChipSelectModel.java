package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Pure, deterministic MC68332 chip-select encoding model. Does not access
 * Ghidra or make claims about the physical board, running instructions or
 * active memory maps. Treat all raw words as conditional configuration inputs.
 */
public final class ChipSelectModel {
    private ChipSelectModel() {}
    private static final long MASK24 = 0xffffffL;
    private static final long[] SIZES = {
        2048, 8192, 16384, 65536, 131072, 262144, 524288, 1048576
    };
    public enum PinMode { DISCRETE, ALTERNATE, CS_8_BIT, CS_16_BIT, UNKNOWN }
    public enum Match { NOT_ASSERTED, ADDRESS_ONLY, CONDITIONAL_MATCH, POSSIBLE_SAME_CYCLE }
    public enum Overlap {
        NONE, DIFFERENT_READ_WRITE, DIFFERENT_SPACE, COMPLEMENTARY_BYTE_LANES, UNRESOLVED
    }

    public static final class Decoder {
        public final String profile;
        public final String source;
        public Decoder(String profile, String source) {
            if (!"MC68332".equals(profile))
                throw new IllegalArgumentException("Only explicitly selected MC68332 semantics are implemented");
            this.profile=profile;
            this.source=source;
        }
        public Window window(int chipSelect, Integer csbar, Integer csor, Integer cspar) {
            if (chipSelect < -1 || chipSelect > 10)
                throw new IllegalArgumentException("CSBOOT is -1; chip-selects are CS0..CS10");
            if (csbar==null) return null;
            long size=SIZES[csbar & 7];
            long address=(((long)csbar & 0xfff8L)<<8)&MASK24;
            long start=address & ~(size-1);
            PinMode pin=pinMode(chipSelect,cspar);
            return new Window(chipSelect,csbar,csor,cspar,start,size,pin,source);
        }
    }
    public static PinMode pinMode(int chipSelect,Integer cspar) {
        if(cspar==null) return PinMode.UNKNOWN;
        if(chipSelect < -1 || chipSelect > 10) throw new IllegalArgumentException("Chip-select outside range");
        // CSBOOT uses CSPAR0 bits 1:0, CS0..5 bits 3:2..13:12,
        // CS6..10 use CSPAR1 bits 1:0..9:8.
        int shift=chipSelect<0?0:chipSelect<=5?(chipSelect+1)*2:(chipSelect-6)*2;
        return switch((cspar>>>shift)&3) {
            case 0 -> PinMode.DISCRETE;
            case 1 -> PinMode.ALTERNATE;
            case 2 -> PinMode.CS_8_BIT;
            case 3 -> PinMode.CS_16_BIT;
            default -> PinMode.UNKNOWN;
        };
    }
    public static final class Window {
        public final int chipSelect;
        public final int csbar;
        public final Integer csor;
        public final Integer cspar;
        public final long first;
        public final long size;
        public final long last;
        public final PinMode pinMode;
        public final String source;
        public final int byteField;
        public final int readWrite;
        public final int space;
        public final int dsack;
        public final int mode;

        private Window(int chipSelect,int csbar,Integer csor,Integer cspar,
                long first,long size,PinMode pinMode,String source) {
            this.chipSelect=chipSelect;
            this.csbar=csbar&0xffff;
            this.csor=csor==null?null:csor&0xffff;
            this.cspar=cspar==null?null:cspar&0xffff;
            this.first=first;
            this.size=size;
            this.last=first+size-1;
            this.pinMode=pinMode;
            this.source=source;
            byteField=csor==null?-1:(csor>>>13)&3;
            readWrite=csor==null?-1:(csor>>>11)&3;
            space=csor==null?-1:(csor>>>4)&3;
            dsack=csor==null?-1:(csor>>>6)&15;
            mode=csor==null?-1:(csor>>>15)&1;
        }
        public String label(){return chipSelect<0?"CSBOOT":"CS"+chipSelect;}
        public boolean includes(long address){
            return address>=first && address<=last;
        }
        public boolean pinOutput(){
            return pinMode==PinMode.CS_8_BIT||pinMode==PinMode.CS_16_BIT;
        }
        /**
         * A possible asserted select requires configured output, BYTE != 0,
         * R/W != 0. This alone NEVER proves external selection in hardware.
         */
        public boolean eligibleForAssertion(){
            return pinOutput() && csor!=null && byteField!=0 && readWrite!=0;
        }
        public Match hypotheticalAccess(long address, boolean write, boolean supervisor, boolean cpuSpace) {
            if (!includes(address)) return Match.NOT_ASSERTED;
            if (!eligibleForAssertion()) return Match.ADDRESS_ONLY;
            if(write && (readWrite&2)==0) return Match.ADDRESS_ONLY;
            if(!write && (readWrite&1)==0) return Match.ADDRESS_ONLY;
            if(space==0 && !cpuSpace)return Match.ADDRESS_ONLY;
            if(space==1 && (supervisor||cpuSpace))return Match.ADDRESS_ONLY;
            if(space==2 && (!supervisor||cpuSpace))return Match.ADDRESS_ONLY;
            if(space==3 && cpuSpace)return Match.ADDRESS_ONLY;
            return Match.CONDITIONAL_MATCH;
        }
        public String toSummary(){
            return label()+" CSBAR="+hex(csbar,4)+" range="+hex(first,6)+".."+hex(last,6)+
                " size="+(size/1024)+"KiB, pin="+pinMode+
                ", CSOR="+(csor==null?"UNKNOWN":hex(csor,4))+
                ", BYTE="+byteField+", R/W="+readWrite+", SPACE="+space+
                "; "+(eligibleForAssertion()?"eligible (conditional)":"inactive or unknown");
        }
    }
    public static Overlap overlap(Window a, Window b) {
        if(a==null||b==null||a.first>b.last||b.first>a.last)return Overlap.NONE;
        if(!a.eligibleForAssertion()||!b.eligibleForAssertion())
            return Overlap.UNRESOLVED;
        if((a.readWrite&b.readWrite)==0)return Overlap.DIFFERENT_READ_WRITE;
        if((a.space==1&&b.space==2)||(a.space==2&&b.space==1)||
                (a.space==0&&b.space!=0)||(b.space==0&&a.space!=0))
            return Overlap.DIFFERENT_SPACE;
        if(a.pinMode==PinMode.CS_16_BIT && b.pinMode==PinMode.CS_16_BIT &&
                ((a.byteField==1&&b.byteField==2)||(a.byteField==2&&b.byteField==1)))
            return Overlap.COMPLEMENTARY_BYTE_LANES;
        return Overlap.UNRESOLVED;
    }
    public static List<String> overlaps(List<Window> windows){
        if(windows==null)return List.of();
        List<String> output=new ArrayList<>();
        for(int i=0;i<windows.size();i++)
            for(int j=i+1;j<windows.size();j++){
                Window a=windows.get(i),b=windows.get(j);
                Overlap relationship=overlap(a,b);
                if(relationship!=Overlap.NONE)
                    output.add(a.label()+"/"+b.label()+" "+
                        hex(Math.max(a.first,b.first),6)+".."+
                        hex(Math.min(a.last,b.last),6)+" : "+relationship);
            }
        return Collections.unmodifiableList(output);
    }
    public static String hex(long value,int width){
        return String.format(Locale.ROOT,"0x%0"+width+"X",value);
    }
}
