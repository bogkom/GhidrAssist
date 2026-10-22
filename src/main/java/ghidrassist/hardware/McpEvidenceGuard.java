package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Read-only, bounded, deterministic evidence from real MCP disassembly output. */
public final class McpEvidenceGuard {
    private McpEvidenceGuard() {}
    private static final Pattern IMMEDIATE_WRITE = Pattern.compile(
        "(?im)^\\s*(?:ram:)?([0-9a-f]{6,8}):\\s*move\\.(b|w|l)\\s+" +
        "#(-?0x[0-9a-f]+)\\s*,\\s*\\(\\s*0x([0-9a-f]{6,8})\\s*\\)\\.l");
    private record Write(long pc, long address, long value, int width) {}

    public static String enrich(String toolName, String content) {
        if (content == null || toolName == null ||
            !toolName.toLowerCase(Locale.ROOT).endsWith("get_disassembly")) return content;
        String raw=content.replace("\\n", "\n");
        Matcher m=IMMEDIATE_WRITE.matcher(raw);
        List<Write> writes=new ArrayList<>();
        while(m.find() && writes.size()<80) {
            int width=switch(m.group(2).toLowerCase(Locale.ROOT)) {
                case "b" -> 8; case "w" -> 16; default -> 32;
            };
            long addr=Long.parseUnsignedLong(m.group(4),16);
            if (!inSimWindow(addr)) continue;
            long num=Long.parseUnsignedLong(m.group(3).replace("-","").substring(2),16);
            if (m.group(3).startsWith("-")) num=-num;
            long value=num & (width==32?0xffffffffL:(1L<<width)-1);
            writes.add(new Write(Long.parseUnsignedLong(m.group(1),16),addr,value,width));
        }
        if(writes.isEmpty())return content;
        StringBuilder out=new StringBuilder(
            "<<<DETERMINISTIC_MCP_DISASSEMBLY_EVIDENCE>>>\n" +
            "Verified literal writes from THIS tool response; NOT proof of runtime execution or CPU model.\n");
        Map<Long,Integer> words=new LinkedHashMap<>();
        for(Write w:writes) {
            out.append(String.format(Locale.ROOT,
                "- instruction 0x%08X: move.%s immediate to 0x%08X = 0x%0"+
                (w.width()/4)+"X",w.pc(),w.width()==8?"b":w.width()==16?"w":"l",
                w.address(),w.value()));
            String name=nameHypothesis(w.address());
            if(name!=null)out.append(" [MC68332 register-map HYPOTHESIS: ").append(name).append("]");
            out.append("\n");
            if(w.width()==16)words.put(w.address(),(int)w.value());
        }
        for(long base:new long[]{0x00fffa00L,0x007ffa00L}){
            Integer a=words.get(base+0x4e),b=words.get(base+0x52);
            if(a!=null && b!=null){
                int xor=xor16(a,b);
                out.append(String.format(Locale.ROOT,
                    "- verified XOR16: 0x%04X (%s) XOR 0x%04X (%s) = 0x%04X (%s); bit indices LSB=0: %s\n",
                    a,binary16(a),b,binary16(b),xor,binary16(xor),setBits(xor)));
            }
        }
        out.append("Consistency check: Do not claim that there are no DIRECT WRITES to listed " +
            "addresses. A register-name mapping or runtime path is a separate, conditional claim.\n" +
            "<<<END_DETERMINISTIC_MCP_DISASSEMBLY_EVIDENCE>>>\n\n");
        return out+content;
    }

    private static boolean inSimWindow(long address){
        return (address&0xffffff00L)==0x00fffa00L ||
            (address&0xffffff00L)==0x007ffa00L;
    }
    private static String nameHypothesis(long address){
        return switch((int)(address&0xff)){
            case 0x44 -> "CSPAR0"; case 0x46 -> "CSPAR1";
            case 0x4c -> "CSBAR0"; case 0x4e -> "CSOR0";
            case 0x50 -> "CSBAR1"; case 0x52 -> "CSOR1";
            default -> null;
        };
    }
    public static int xor16(int a,int b){return (a^b)&0xffff;}
    public static String binary16(int value){
        String b=Integer.toBinaryString((value&0xffff)|0x10000).substring(1);
        return b.substring(0,4)+" "+b.substring(4,8)+" "+
            b.substring(8,12)+" "+b.substring(12);
    }
    public static String setBits(int value){
        List<Integer> bits=new ArrayList<>();
        for(int n=0;n<16;n++)if(((value>>>n)&1)!=0)bits.add(n);
        return bits.toString();
    }
}
