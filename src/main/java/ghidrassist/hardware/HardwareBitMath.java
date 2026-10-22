package ghidrassist.hardware;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Verified integer arithmetic on direct constants, independent of the LLM.
 * No runtime execution, MCU model or register access width is inferred from
 * a decompiler symbol name. These are hypothetical MC68332 register facts.
 */
public final class HardwareBitMath {
    private HardwareBitMath() {}
    private static final Pattern ASSEMBLY=Pattern.compile(
        "(?im)\\bmove\\.(b|w|l)\\s+#(-?0x[0-9a-f]+)\\s*,\\s*\\(\\s*(?:0x)?([0-9a-f]{6,8})\\s*\\)\\.l");
    private static final Pattern DECOMPILED_SIMCR=Pattern.compile(
        "(?im)\\b(?:_?DAT_)(?:00)?(fffa00|7ffa00)\\s*=\\s*(0x[0-9a-f]+)\\s*;");
    private static final Pattern LITERAL_SIMCR=Pattern.compile(
        "(?i)(?:00)?(?:fffa00|7ffa00)\\b");

    public static String annotate(String context) {
        if(context==null || context.isBlank() || !LITERAL_SIMCR.matcher(context).find())
            return context==null?"":context;
        Set<String> evidence=new LinkedHashSet<>();
        Matcher asm=ASSEMBLY.matcher(context);
        while(asm.find()) {
            int bits=switch(asm.group(1).toLowerCase(Locale.ROOT)){
                case "b" -> 8; case "w" -> 16; default -> 32;
            };
            long mask=(1L<<bits)-1;
            long raw=parse(asm.group(2))&mask;
            long address=Long.parseUnsignedLong(asm.group(3),16);
            if((address==0xfffa00L || address==0x7ffa00L) && bits==16)
                evidence.add(mmLine(raw,"assembly move.w to 0x"+Long.toHexString(address)));
            if(bits==32){
                String full=String.format(Locale.ROOT,"0x%08X",raw);
                evidence.add(String.format(Locale.ROOT,
                    "Verified 32-bit immediate: %s => %s; high word=0x%04X, low word=0x%04X "+
                    "(big-endian memory order; peripheral side effects UNVERIFIED).",
                    asm.group(2),full,(raw>>>16)&0xffff,raw&0xffff));
            }
        }
        Matcher decompiled=DECOMPILED_SIMCR.matcher(context);
        while(decompiled.find())
            evidence.add(mmLine(parse(decompiled.group(2))&0xffffL,
                "decompiler constant at 0x"+decompiled.group(1)));
        if(evidence.isEmpty())return context;
        StringBuilder verified=new StringBuilder(
            "\n<<<DETERMINISTIC_HARDWARE_ARITHMETIC>>>\n"+
            "Locally computed facts, NOT an LLM estimate or runtime execution proof.\n");
        for(String item:evidence)verified.append("- ").append(item).append("\n");
        verified.append("MC68332-only documented reset hypothesis: MM=1 at reset; "+
            "SIMCR description: MC68332UM.pdf physical PDF page 219 / "+
            "MC68332TS.pdf physical PDF page 18. Neither MCU identity nor reset path "+
            "nor which write first took effect is verified.\n"+
            "<<<END_DETERMINISTIC_HARDWARE_ARITHMETIC>>>\n");
        return verified+context;
    }
    public static String mmLine(long value,String origin){
        return String.format(Locale.ROOT,
            "%s: SIMCR word=0x%04X; (0x%04X & 0x0040)=0x%04X; "+
            "MM bit 6=%d. MC68332 address hypothesis only.",
            origin,value&0xffff,value&0xffff,value&0x40,
            (value&0x40)!=0?1:0);
    }
    private static long parse(String value){
        boolean neg=value.startsWith("-");
        String number=neg?value.substring(1):value;
        long magnitude=Long.parseUnsignedLong(number.substring(2),16);
        return neg?-magnitude:magnitude;
    }
}
