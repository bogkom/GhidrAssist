package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Read-only join of Ghidra Listing/XREF and CFG/P-code observations.
 * One instruction may appear in both inputs: it must never become
 * two executed writes or two distinct configuration epochs.
 */
public final class HardwareStartupEvidenceMerge {
    private HardwareStartupEvidenceMerge(){}
    public enum Source { LISTING_REFERENCE, CFG_PCODE }
    public enum Status {
        REFERENCE_ONLY, FULL_WORD_LITERAL_CANDIDATE,
        UNKNOWN_VALUE_OR_WIDTH, CONFLICTING_EVIDENCE
    }
    public record Observation(long function,long pc,long registerAddress,
            String candidateRegister,Source source,boolean possibleWrite,
            int widthBits,Integer literalWord,boolean uncertain) {
        public Observation {
            if(function<0 || pc<0 || registerAddress< -1 ||
                    candidateRegister==null || candidateRegister.isBlank() ||
                    source==null || (widthBits!=0 && widthBits!=8 &&
                        widthBits!=16 && widthBits!=32) ||
                    literalWord!=null && (literalWord<0 || literalWord>0xffff) ||
                    registerAddress<0 && source!=Source.CFG_PCODE)
                throw new IllegalArgumentException("Invalid source observation");
        }
    }
    public record Row(long function,long pc,long registerAddress,String candidateRegister,
            Set<Source> sources,boolean possibleWrite,int widthBits,
            Integer literalWord,Status status,boolean conditionalOrUncertain) {
        public Row {sources=Set.copyOf(sources);}
        public HardwareStartupConfig.Site forStartup(){
            return new HardwareStartupConfig.Site(function,pc,candidateRegister,
                possibleWrite,status==Status.FULL_WORD_LITERAL_CANDIDATE?
                    literalWord:null);
        }
    }
    public record Report(List<Row> rows,int rawSites,int duplicateSources,
            int unboundAliasStores,int conflicts,int uncertainWrites) {
        public Report {rows=List.copyOf(rows);}
        public String markdown(boolean selectedMc68332){
            StringBuilder out=new StringBuilder(
                "## Unified startup write evidence (Listing + CFG/P-code)\n\n")
                .append("- Raw source observations: ").append(rawSites)
                .append("; unique candidate function/PC/address sites: ")
                .append(rows.size()).append("; duplicate-source matches: ")
                .append(duplicateSources).append("; unresolved alias stores: ")
                .append(unboundAliasStores).append("; contradicting source sites: ")
                .append(conflicts).append("; unknown-width/value/conditional writes: ")
                .append(uncertainWrites).append(".\n")
                .append("- Each entry is **one static candidate instruction**, ")
                .append("not one executed write. A matching Listing and P-code ")
                .append("record must not be counted as two events.\n")
                .append("- Unknown-address aliases may affect ANY MMIO register; ")
                .append("do not interpret a missing exact address as no write.\n")
                .append("- Unknown widths, disagreeing words or instruction ")
                .append("translations cannot establish a 16-bit register value. ")
                .append("Function-local CFG reachability and RESET call "
                    + "graph are not hardware execution or write order.\n")
                .append("- SIMCR write-once MM latch and all simultaneous physical ")
                .append("CSBAR/CSOR/CSPAR states remain UNKNOWN.\n\n")
                .append("| Function | PC | Register candidate | Address | Sources | ")
                .append("Evidence | Word candidate | Uncertainty |\n")
                .append("|---|---|---|---|---|---|---|---|\n");
            int cap=Math.min(rows.size(),100);
            for(int i=0;i<cap;i++){
                Row r=rows.get(i);
                out.append("| ").append(hex(r.function())).append(" | ")
                    .append(hex(r.pc())).append(" | ")
                    .append(selectedMc68332?r.candidateRegister():
                        "UNVERIFIED_MCU_REGISTER")
                    .append(" | ").append(hex(r.registerAddress()))
                    .append(" | ").append(r.sources())
                    .append(" | ").append(r.status())
                    .append(" | ").append(r.status()==Status.FULL_WORD_LITERAL_CANDIDATE?
                        String.format(Locale.ROOT,"0x%04X",r.literalWord()):"UNKNOWN")
                    .append(" | ").append(r.conditionalOrUncertain())
                    .append(" |\n");
            }
            if(cap<rows.size())out.append("- ").append(rows.size()-cap)
                .append(" more sites omitted by display cap.\n");
            return out.append("\n").toString();
        }
    }
    private static String hex(long a){
        return a<0?"UNKNOWN":String.format(Locale.ROOT,"0x%08X",a);
    }
    private record Identity(long function,long pc,long address){}
    private static final class Mutable {
        final Identity key;
        final EnumSet<Source> sources=EnumSet.noneOf(Source.class);
        String register;
        boolean write,uncertain,conflict,unknownValue;
        int width;
        Integer literal;
        Mutable(Observation o){
            key=new Identity(o.function(),o.pc(),o.registerAddress());
            register=o.candidateRegister();
        }
        void include(Observation o){
            if(!register.equals(o.candidateRegister()))conflict=true;
            sources.add(o.source());
            uncertain|=o.uncertain();
            if(!o.possibleWrite())return;
            if(!write){
                write=true;width=o.widthBits();literal=o.literalWord();
                unknownValue=width!=16 || literal==null;
            }else{
                if(width!=o.widthBits())conflict=true;
                if(literal!=null && o.literalWord()!=null &&
                        !literal.equals(o.literalWord()))conflict=true;
                if(o.widthBits()!=16 || o.literalWord()==null)unknownValue=true;
                if(literal==null)literal=o.literalWord();
            }
        }
    }
    public static Report reconcile(List<Observation> observations){
        if(observations==null)throw new IllegalArgumentException("Null source set");
        Map<Identity,Mutable> grouped=new LinkedHashMap<>();
        int raw=0,duplicates=0,unbound=0;
        for(Observation o:observations){
            if(o==null)throw new IllegalArgumentException("Null source observation");
            raw++;
            if(o.registerAddress()<0){
                if(o.possibleWrite())unbound++;
                continue; // never invent a target address for unknown alias
            }
            Identity key=new Identity(o.function(),o.pc(),o.registerAddress());
            Mutable g=grouped.get(key);
            if(g==null){
                g=new Mutable(o);grouped.put(key,g);
            }else duplicates++;
            g.include(o);
        }
        int conflicts=0,unknownWrites=0;
        List<Row> rows=new ArrayList<>();
        for(Mutable g:grouped.values()){
            Status status=g.conflict?Status.CONFLICTING_EVIDENCE:
                !g.write?Status.REFERENCE_ONLY:
                g.unknownValue||g.width!=16 || g.literal==null?
                    Status.UNKNOWN_VALUE_OR_WIDTH:Status.FULL_WORD_LITERAL_CANDIDATE;
            if(g.conflict)conflicts++;
            if(g.write && (status!=Status.FULL_WORD_LITERAL_CANDIDATE || g.uncertain))
                unknownWrites++;
            rows.add(new Row(g.key.function(),g.key.pc(),g.key.address(),g.register,
                g.sources,g.write,g.width,
                status==Status.FULL_WORD_LITERAL_CANDIDATE?g.literal:null,
                status,g.uncertain || status==Status.CONFLICTING_EVIDENCE));
        }
        rows.sort(Comparator.comparingLong(Row::function)
            .thenComparingLong(Row::pc).thenComparingLong(Row::registerAddress));
        return new Report(rows,raw,duplicates,unbound,conflicts,unknownWrites);
    }
}
