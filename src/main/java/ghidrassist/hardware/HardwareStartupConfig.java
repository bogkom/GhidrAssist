package ghidrassist.hardware;

import java.util.*;

/**
 * GA-01/02/03: function-scoped *static* MMIO write alternatives.
 * Addresses, graph reachability and source order DO NOT establish
 * execution, write-once latch state, or physical chip-select wiring.
 */
public final class HardwareStartupConfig {
    private HardwareStartupConfig() {}
    public record Site(long function,long pc,String register,boolean write,
                       Integer word,boolean uncertain) {
        // Preserve all existing five-field synthetic callers.
        public Site(long function,long pc,String register,boolean write,Integer word) {
            this(function,pc,register,write,word,false);
        }
    }
    public enum Path { STATIC_RESET_CALL_CANDIDATE, OUTSIDE_OR_UNRESOLVED }
    public enum Alternatives { REFERENCE_ONLY, UNKNOWN_WRITE_VALUE,
        ONE_LITERAL_CANDIDATE, MULTIPLE_LITERAL_ALTERNATIVES }
    public record Group(long function,String register,Path path,
        Alternatives alternatives,int writes,int unknownWrites,
        List<Integer> possibleWords,Integer simcrMmCandidate){
        public Group {possibleWords=List.copyOf(possibleWords);}
    }
    public record Result(boolean mc68332Selected,boolean resetRootRecognized,
        boolean callGraphIncomplete,int sites,int writes,int unknownWrites,
        List<Group> groups){
        public Result {groups=List.copyOf(groups);}
        public String markdown(){
            StringBuilder out=new StringBuilder(
                "## RESET-relative initialization alternatives (GA-01/02/03)\n\n")
                .append("- Manual MCU profile selected: ").append(mc68332Selected)
                .append("; reset-root function recognized: ").append(resetRootRecognized)
                .append("; direct-call graph incomplete: ").append(callGraphIncomplete)
                .append("; register sites: ").append(sites)
                .append("; write candidates: ").append(writes)
                .append("; unknown or path-uncertain write candidates: ").append(unknownWrites).append(".\n")
                .append("- **STATIC POSSIBILITY, NOT EXECUTION:** possible direct-call ")
                .append("reachability does not establish feasible paths; other functions ")
                .append("are OUTSIDE_OR_UNRESOLVED, not proven unreachable.\n")
                .append("- **SIMCR/MM write-once caveat:** the first source address ")
                .append("is NOT the first executed write or the latched hardware value.\n")
                .append("- **CSBAR/CSOR/CSPAR caveat:** co-located source writes ")
                .append("are alternatives, NOT one simultaneous active CS map. ")
                .append("No cross-function register state is combined.\n\n")
                .append("| Function | Register | RESET scope | Write evidence | ")
                .append("Literal alternatives | Unknown writes | MM literal |\n")
                .append("|---|---|---|---|---|---|---|\n");
            int shown=Math.min(groups.size(),100);
            for(int i=0;i<shown;i++){
                Group g=groups.get(i);
                out.append("| ").append(String.format(Locale.ROOT,"0x%08X",g.function()))
                    .append(" | ").append(mc68332Selected?
                        g.register():"UNVERIFIED_MCU_REGISTER")
                    .append(" | ").append(g.path())
                    .append(" | ").append(g.alternatives()).append(" | ");
                if(g.possibleWords().isEmpty())out.append("UNKNOWN");
                for(int j=0;j<g.possibleWords().size();j++){
                    if(j>0)out.append(", ");
                    out.append(String.format(Locale.ROOT,"0x%04X",
                        g.possibleWords().get(j)));
                }
                out.append(" | ").append(g.unknownWrites()).append(" | ")
                    .append(!mc68332Selected || g.simcrMmCandidate()==null?
                        "UNKNOWN":g.simcrMmCandidate()+" (literal only)")
                    .append(" |\n");
            }
            if(shown<groups.size())out.append("- Bounded display: ")
                .append(groups.size()-shown).append(" groups omitted.\n");
            return out.append("\n").toString();
        }
    }
    private static final class Grouping {
        final long fn;final String reg;final Path path;
        final Set<Integer> words=new TreeSet<>();
        int writes,unknown;
        Grouping(long fn,String reg,Path path){this.fn=fn;this.reg=reg;this.path=path;}
    }
    public static Result analyze(boolean device,boolean rootRecognized,
        Set<Long> directCallCandidateFunctions,boolean graphIncomplete,
        List<Site> sourceSites){
        if(directCallCandidateFunctions==null || sourceSites==null)
            throw new IllegalArgumentException("Missing graph/inventory evidence");
        Map<String,Grouping> grouped=new TreeMap<>();
        int sites=0,writes=0,unknown=0;
        for(Site s:sourceSites){
            if(s==null || s.function()<0 || s.pc()<0 ||
                    s.register()==null || s.register().isBlank())continue;
            sites++;
            Path path=rootRecognized &&
                directCallCandidateFunctions.contains(s.function())?
                Path.STATIC_RESET_CALL_CANDIDATE:Path.OUTSIDE_OR_UNRESOLVED;
            String key=String.format(Locale.ROOT,"%016X/%s",s.function(),s.register());
            Grouping group=grouped.computeIfAbsent(key,
                k->new Grouping(s.function(),s.register(),path));
            if(!s.write())continue;
            writes++;group.writes++;
            if(s.word()==null || s.word()<0 || s.word()>0xffff ||
                    s.uncertain()){
                unknown++;group.unknown++;
            }
            // The literal is still a source candidate even when a call,
            // alias or unknown-width write prevents safe interpretation.
            if(s.word()!=null && s.word()>=0 && s.word()<=0xffff)
                group.words.add(s.word());
        }
        List<Group> results=new ArrayList<>();
        for(Grouping g:grouped.values()){
            List<Integer> words=List.copyOf(g.words);
            Alternatives a=g.writes==0?Alternatives.REFERENCE_ONLY:
                g.unknown>0?Alternatives.UNKNOWN_WRITE_VALUE:
                words.size()==1?Alternatives.ONE_LITERAL_CANDIDATE:
                Alternatives.MULTIPLE_LITERAL_ALTERNATIVES;
            Integer mm=device && g.reg.equals("SIMCR") && g.unknown==0 &&
                words.size()==1?((words.get(0)&0x40)!=0?1:0):null;
            results.add(new Group(g.fn,g.reg,g.path,a,g.writes,g.unknown,words,mm));
        }
        return new Result(device,rootRecognized,graphIncomplete,
            sites,writes,unknown,results);
    }
}
