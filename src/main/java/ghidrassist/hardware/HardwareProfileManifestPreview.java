package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * STRICT preview-only manifest parser. External profile input is untrusted:
 * parsing never creates a HardwareProfiles.Profile and has no Apply path.
 *
 * No URL is fetched; user-supplied edition/hash/page text is *not* verified.
 * The format is tab-delimited to make field boundaries unambiguous.
 */
public final class HardwareProfileManifestPreview {
    private HardwareProfileManifestPreview() {}
    public static final int MAX_BYTES=1_048_576;
    public static final int MAX_ROWS=1024;
    public record Source(String device,String manualId,String url,
                         String edition,String claimedSha256) {}
    public record Module(String id,int offset,int size,String page) {
        public int end(){return offset+size;}
    }
    public record Register(String module,String name,int offset,
                           int widthBits,String page) {
        public int end(){return offset+widthBits/8;}
    }
    public record Field(String register,String name,long mask,String page) {}
    public record Preview(Source source,List<Module> modules,List<Register> registers,
                          List<Field> fields,int ambiguousPages) {
        public Preview {
            modules=List.copyOf(modules);
            registers=List.copyOf(registers);
            fields=List.copyOf(fields);
        }
        public String report() {
            StringBuilder b=new StringBuilder();
            b.append("EXTERNAL CPU PROFILE — VALIDATED STRUCTURE ONLY\n\n")
             .append("Device: ").append(source.device()).append("\n")
             .append("Manual ID: ").append(source.manualId()).append("\n")
             .append("Document URL (not downloaded): ").append(source.url()).append("\n")
             .append("Claimed edition: ").append(source.edition()).append("\n")
             .append("Claimed PDF SHA-256: ").append(source.claimedSha256()).append("\n\n")
             .append("Module apertures: ").append(modules.size())
             .append("; register definitions: ").append(registers.size())
             .append("; bitfields: ").append(fields.size())
             .append("; absent/ambiguous physical PDF-page references: ")
             .append(ambiguousPages).append("\n\n")
             .append("No MCU identification, manual edition, PDF bytes, claimed checksum, ")
             .append("bitfield semantics or physical memory map has been verified.\n")
             .append("NOT IMPORTED into Ghidra. No symbols, blocks, RAG or projects modified.\n\n");
            int shown=Math.min(registers.size(),20);
            for(int i=0;i<shown;i++) {
                Register r=registers.get(i);
                b.append("- ").append(r.module()).append(".").append(r.name())
                 .append(" @ 0x").append(Integer.toHexString(r.offset())
                     .toUpperCase(Locale.ROOT))
                 .append(" / ").append(r.widthBits()).append(" bits")
                 .append("; page label: ").append(r.page()).append("\n");
            }
            if(shown<registers.size())
                b.append("- ").append(registers.size()-shown())
                 .append(" further registers omitted from preview display.\n");
            return b.toString();
        }
    }
    private static int parseHex(String s,String label,int line){
        if(s==null || !s.matches("0[xX][0-9a-fA-F]{1,8}"))
            throw fail(line,label+" must be 0x-prefixed hexadecimal");
        long n=Long.parseLong(s.substring(2),16);
        if(n>Integer.MAX_VALUE)throw fail(line,label+" exceeds supported range");
        return (int)n;
    }
    private static String id(String s,int line) {
        if(s==null || !s.matches("[A-Za-z][A-Za-z0-9_]{0,63}"))
            throw fail(line,"invalid identifier");
        return s;
    }
    private static String page(String s,int line){
        if(s==null || !s.matches("[A-Za-z0-9 .()/_-]{1,96}"))
            throw fail(line,"invalid source-page label");
        return s;
    }
    private static boolean paginated(String page){
        String p=page.toLowerCase(Locale.ROOT);
        return p.contains("pdf page") && !p.contains("unknown") &&
            !p.contains("unverified");
    }
    private static IllegalArgumentException fail(int line,String why){
        return new IllegalArgumentException("Manifest line "+line+": "+why);
    }
    public static Preview parse(String text) {
        if(text==null || text.isBlank() || text.length()>MAX_BYTES ||
                text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>MAX_BYTES)
            throw new IllegalArgumentException("Manifest empty or larger than 1 MiB");
        String[] rows=text.split("\n",-1);
        if(rows.length>MAX_ROWS+5)
            throw new IllegalArgumentException("Manifest contains too many rows");
        Source src=null;
        Map<String,Module> modules=new LinkedHashMap<>();
        Map<String,Register> registers=new LinkedHashMap<>();
        List<Field> fields=new ArrayList<>();
        Map<String,Long> usedMasks=new LinkedHashMap<>();
        int pageMissing=0,seen=0;
        for(int i=0;i<rows.length;i++){
            String line=rows[i].replace("\r","").strip();
            if(line.isEmpty() || line.startsWith("#"))continue;
            seen++;
            String[] v=line.split("\t",-1);
            int ln=i+1;
            if(seen==1) {
                if(v.length!=2 || !"GHIDRASSIST_PROFILE".equals(v[0]) ||
                        !"1".equals(v[1]))
                    throw fail(ln,"expected GHIDRASSIST_PROFILE tab 1 header");
                continue;
            }
            switch(v[0]){
                case "DOCUMENT" -> {
                    if(src!=null || v.length!=6 || !modules.isEmpty() ||
                            !registers.isEmpty() || !fields.isEmpty())
                        throw fail(ln,"exactly one DOCUMENT must precede definitions");
                    String dev=id(v[1],ln),manual=id(v[2],ln);
                    if(!v[3].matches("https://[^\\s<>]{1,300}"))
                        throw fail(ln,"documentation URL must use HTTPS");
                    if(!v[4].matches("[A-Za-z0-9 ._/-]{1,64}"))
                        throw fail(ln,"invalid document edition");
                    if(!("UNKNOWN".equals(v[5]) || v[5].matches("[a-fA-F0-9]{64}")))
                        throw fail(ln,"SHA-256 must be 64 hex characters or UNKNOWN");
                    src=new Source(dev,manual,v[3],v[4],v[5]);
                }
                case "MODULE" -> {
                    if(src==null || v.length!=5)
                        throw fail(ln,"MODULE requires DOCUMENT and four fields");
                    String name=id(v[1],ln);
                    int offset=parseHex(v[2],"module offset",ln);
                    int size=parseHex(v[3],"module size",ln);
                    if(size<1 || (long)offset+size>4096)
                        throw fail(ln,"module must lie in the 4 KiB device aperture");
                    Module proposed=new Module(name,offset,size,page(v[4],ln));
                    if(modules.containsKey(name))
                        throw fail(ln,"duplicate module");
                    for(Module m:modules.values())
                        if(offset<m.end() && m.offset()<proposed.end())
                            throw fail(ln,"overlapping module apertures");
                    modules.put(name,proposed);
                    if(!paginated(proposed.page()))pageMissing++;
                }
                case "REGISTER" -> {
                    if(src==null || v.length!=6)
                        throw fail(ln,"REGISTER requires DOCUMENT and five fields");
                    String module=id(v[1],ln),name=id(v[2],ln);
                    Module m=modules.get(module);
                    if(m==null)throw fail(ln,"unknown module: "+module);
                    int offset=parseHex(v[3],"register offset",ln);
                    int width;
                    try{width=Integer.parseInt(v[4]);}
                    catch(NumberFormatException e){throw fail(ln,"invalid register width");}
                    if(width!=8 && width!=16 && width!=32)
                        throw fail(ln,"register width must be 8, 16 or 32");
                    if(offset%(width/8)!=0 ||
                            offset<m.offset() || (long)offset+width/8>m.end())
                        throw fail(ln,"unaligned or outside module");
                    Register candidate=new Register(module,name,offset,width,page(v[5],ln));
                    if(registers.containsKey(name.toUpperCase(Locale.ROOT)))
                        throw fail(ln,"duplicate register name");
                    for(Register old:registers.values())
                        if(offset<old.end() && old.offset()<candidate.end())
                            throw fail(ln,"overlapping register ranges");
                    registers.put(name.toUpperCase(Locale.ROOT),candidate);
                    if(!paginated(candidate.page()))pageMissing++;
                }
                case "FIELD" -> {
                    if(src==null || v.length!=5)
                        throw fail(ln,"FIELD requires DOCUMENT and four fields");
                    String register=id(v[1],ln),field=id(v[2],ln);
                    Register reg=registers.get(register.toUpperCase(Locale.ROOT));
                    if(reg==null)throw fail(ln,"field refers to unknown register");
                    long mask=Integer.toUnsignedLong(parseHex(v[3],"bit mask",ln));
                    long full=(1L<<reg.widthBits())-1;
                    if(mask==0 || (mask & ~full)!=0)
                        throw fail(ln,"field mask exceeds register width or is zero");
                    String key=register.toUpperCase(Locale.ROOT);
                    long prior=usedMasks.getOrDefault(key,0L);
                    if((prior&mask)!=0)throw fail(ln,"overlapping field masks");
                    for(Field previous:fields)
                        if(previous.register().equalsIgnoreCase(register) &&
                                previous.name().equalsIgnoreCase(field))
                            throw fail(ln,"duplicate field identifier");
                    usedMasks.put(key,prior|mask);
                    Field parsed=new Field(reg.name(),field,mask,page(v[4],ln));
                    fields.add(parsed);
                    if(!paginated(parsed.page()))pageMissing++;
                }
                default -> throw fail(ln,"unsupported manifest record");
            }
        }
        if(src==null || modules.isEmpty() || registers.isEmpty())
            throw new IllegalArgumentException(
                "Manifest requires DOCUMENT, MODULE and REGISTER records");
        return new Preview(src,new ArrayList<>(modules.values()),
            new ArrayList<>(registers.values()),fields,pageMissing);
    }
}
